"""Audit Logging module for the MCP Security Gateway.

Provides structured, append-only security event logging for every tool inspection,
change detection event, and enforcement decision (ALLOW, QUARANTINE, BLOCK).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import datetime as dt
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("audit_logger")


@dataclass
class AuditEvent:
    """Represents an auditable gateway security event."""
    timestamp: str
    event_type: str               # "TOOL_INSPECTION", "POLICY_ENFORCEMENT"
    server_name: str
    tool_name: str
    decision: str                 # "ALLOW", "QUARANTINE", "BLOCK"
    reason: str
    rule_triggered: str
    malicious_probability: float | None
    risk_level: str | None
    has_changed: bool
    old_hash: str | None
    new_hash: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """Thread-safe, append-only structured audit logger for security events."""

    def __init__(self, log_file: Path | None = None) -> None:
        self.log_file = log_file
        self._in_memory_events: list[AuditEvent] = []
        if self.log_file:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event_type: str,
        server_name: str,
        tool_name: str,
        decision: str,
        reason: str,
        rule_triggered: str,
        new_hash: str,
        old_hash: str | None = None,
        malicious_probability: float | None = None,
        risk_level: str | None = None,
        has_changed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record a structured security audit event."""
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        event = AuditEvent(
            timestamp=now,
            event_type=event_type,
            server_name=server_name,
            tool_name=tool_name,
            decision=decision,
            reason=reason,
            rule_triggered=rule_triggered,
            malicious_probability=malicious_probability,
            risk_level=risk_level,
            has_changed=has_changed,
            old_hash=old_hash,
            new_hash=new_hash,
            metadata=metadata or {},
        )

        self._in_memory_events.append(event)
        logger.info(
            f"[{decision}] {server_name}:{tool_name} -> {reason} (Rule: {rule_triggered})"
        )

        if self.log_file:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(event.to_json() + "\n")
            except Exception as e:
                logger.error(f"Failed to append to audit log file: {e}")

        return event

    def get_events(self) -> list[AuditEvent]:
        """Return all logged events in memory."""
        return list(self._in_memory_events)

    def clear(self) -> None:
        """Clear in-memory events."""
        self._in_memory_events.clear()
