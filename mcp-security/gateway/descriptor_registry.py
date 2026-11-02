"""Tool Descriptor Registry for the MCP Security Gateway.

Tracks known MCP tools, their cryptographically hashed descriptors, version numbers,
and approval lifecycle states.

Guarantees:
1. Every tool description is stored with its SHA-256 hash.
2. A new or modified description is NEVER automatically trusted simply because it was received.
3. Approval transitions are explicit and tracked with timestamps and status.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime as dt
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from gateway.feature_extractor import normalize_text

logger = logging.getLogger("descriptor_registry")

# Valid lifecycle states for tool descriptors
STATUS_APPROVED = "APPROVED"            # Verified safe and authorized for agent execution
STATUS_PENDING_REVIEW = "PENDING_REVIEW"  # Staged candidate, unverified
STATUS_QUARANTINED = "QUARANTINED"      # Suspicious or uncertain drift, held without access
STATUS_BLOCKED = "BLOCKED"              # Confirmed malicious or mandatory policy violation


def compute_description_hash(text: str) -> str:
    """Compute deterministic SHA-256 hash of a normalized tool description.

    Args:
        text: Raw or normalized tool description string

    Returns:
        Hexadecimal SHA-256 digest
    """
    normalized = normalize_text(text)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass
class ToolDescriptor:
    """Represents a versioned tool specification in the registry."""
    tool_name: str
    server_name: str
    description: str
    sha256_hash: str
    version: int
    status: str
    last_updated_at: str
    approved_at: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert descriptor to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolDescriptor":
        """Reconstruct descriptor from dictionary."""
        return cls(**data)


class DescriptorRegistry:
    """Registry maintaining approved baselines and tracking unapproved updates."""

    def __init__(self) -> None:
        # Maps (server_name, tool_name) -> ToolDescriptor
        self._approved_registry: dict[tuple[str, str], ToolDescriptor] = {}
        # Maps (server_name, tool_name) -> list of historical/candidate ToolDescriptors
        self._candidate_history: dict[tuple[str, str], list[ToolDescriptor]] = {}

    def _key(self, server_name: str, tool_name: str) -> tuple[str, str]:
        return (server_name.strip(), tool_name.strip())

    def register_approved(
        self,
        tool_name: str,
        server_name: str,
        description: str,
        metadata: dict[str, Any] | None = None,
    ) -> ToolDescriptor:
        """Register an explicitly approved tool baseline (e.g. at gateway onboarding).

        Args:
            tool_name: Tool name exposed over MCP
            server_name: Server name exposing the tool
            description: Approved tool description
            metadata: Optional parameter schemas or permissions

        Returns:
            The approved ToolDescriptor.
        """
        key = self._key(server_name, tool_name)
        norm_desc = normalize_text(description)
        sha = compute_description_hash(norm_desc)
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        descriptor = ToolDescriptor(
            tool_name=tool_name.strip(),
            server_name=server_name.strip(),
            description=norm_desc,
            sha256_hash=sha,
            version=1,
            status=STATUS_APPROVED,
            last_updated_at=now,
            approved_at=now,
            metadata=metadata or {},
        )

        self._approved_registry[key] = descriptor
        self._candidate_history.setdefault(key, []).append(descriptor)
        logger.info(f"Registered approved baseline for {server_name}:{tool_name} (SHA: {sha[:8]}...)")
        return descriptor

    def get_approved(self, tool_name: str, server_name: str) -> ToolDescriptor | None:
        """Retrieve currently approved descriptor for a tool, or None if unapproved."""
        return self._approved_registry.get(self._key(server_name, tool_name))

    def is_approved(self, tool_name: str, server_name: str, description: str) -> bool:
        """Check if incoming description matches currently approved version character-for-character."""
        approved = self.get_approved(tool_name, server_name)
        if approved is None:
            return False
        current_hash = compute_description_hash(description)
        return approved.sha256_hash == current_hash and approved.status == STATUS_APPROVED

    def record_candidate(
        self,
        tool_name: str,
        server_name: str,
        description: str,
        status: str = STATUS_PENDING_REVIEW,
        metadata: dict[str, Any] | None = None,
    ) -> ToolDescriptor:
        """Record an unapproved incoming description without making it trusted.

        Args:
            tool_name: Tool name
            server_name: Server name
            description: Candidate description
            status: Initial lifecycle state (default: PENDING_REVIEW)
            metadata: Optional metadata

        Returns:
            The recorded candidate ToolDescriptor.
        """
        key = self._key(server_name, tool_name)
        approved = self.get_approved(tool_name, server_name)
        next_version = (approved.version + 1) if approved else 1

        norm_desc = normalize_text(description)
        sha = compute_description_hash(norm_desc)
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        candidate = ToolDescriptor(
            tool_name=tool_name.strip(),
            server_name=server_name.strip(),
            description=norm_desc,
            sha256_hash=sha,
            version=next_version,
            status=status,
            last_updated_at=now,
            approved_at=None,
            metadata=metadata or {},
        )

        self._candidate_history.setdefault(key, []).append(candidate)
        logger.info(
            f"Recorded candidate v{next_version} for {server_name}:{tool_name} with status={status}"
        )
        return candidate

    def promote_to_approved(self, tool_name: str, server_name: str, description: str) -> ToolDescriptor:
        """Explicitly promote a reviewed candidate description to approved status."""
        key = self._key(server_name, tool_name)
        approved = self.get_approved(tool_name, server_name)
        next_version = (approved.version + 1) if approved else 1

        norm_desc = normalize_text(description)
        sha = compute_description_hash(norm_desc)
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        descriptor = ToolDescriptor(
            tool_name=tool_name.strip(),
            server_name=server_name.strip(),
            description=norm_desc,
            sha256_hash=sha,
            version=next_version,
            status=STATUS_APPROVED,
            last_updated_at=now,
            approved_at=now,
        )

        self._approved_registry[key] = descriptor
        self._candidate_history.setdefault(key, []).append(descriptor)
        logger.info(f"Promoted {server_name}:{tool_name} to v{next_version} APPROVED.")
        return descriptor

    def revoke_approval(
        self,
        tool_name: str,
        server_name: str,
        revocation_status: str = STATUS_QUARANTINED,
    ) -> bool:
        """Explicitly revoke prior approval for a tool descriptor.

        Removes the descriptor from the approved baseline and records a candidate
        with the revoked status (QUARANTINED or BLOCKED).

        Args:
            tool_name: Name of tool
            server_name: Server name
            revocation_status: Target status after revocation (default QUARANTINED)

        Returns:
            True if an approved descriptor was revoked, False if tool was not approved.
        """
        key = self._key(server_name, tool_name)
        approved = self._approved_registry.pop(key, None)
        if approved:
            now = dt.datetime.now(dt.timezone.utc).isoformat()
            revoked = ToolDescriptor(
                tool_name=tool_name.strip(),
                server_name=server_name.strip(),
                description=approved.description,
                sha256_hash=approved.sha256_hash,
                version=approved.version + 1,
                status=revocation_status,
                last_updated_at=now,
                approved_at=None,
                metadata={"revocation_source_version": approved.version, "revocation_timestamp": now},
            )
            self._candidate_history.setdefault(key, []).append(revoked)
            logger.info(f"Revoked approval for {server_name}:{tool_name} -> {revocation_status}.")
            return True
        return False

    def save_to_disk(self, file_path: Path) -> None:
        """Persist approved registry to JSON."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        serialized = {
            f"{srv}::{tool}": desc.to_dict()
            for (srv, tool), desc in self._approved_registry.items()
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(serialized, f, indent=2)

    def load_from_disk(self, file_path: Path) -> None:
        """Load approved registry from JSON."""
        if not file_path.exists():
            return
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key_str, desc_dict in data.items():
            srv, tool = key_str.split("::", 1)
            desc = ToolDescriptor.from_dict(desc_dict)
            self._approved_registry[(srv, tool)] = desc
            self._candidate_history.setdefault((srv, tool), []).append(desc)
