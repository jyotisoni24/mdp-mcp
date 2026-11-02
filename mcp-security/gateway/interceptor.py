"""MCP Security Gateway Interceptor and Transparent Proxy Layer.

This module intercepts MCP protocol communication between an AI client and an MCP server:
1. Intercepts 'tools/list' protocol messages:
   - Evaluates incoming tool descriptions against the DescriptorRegistry.
   - Computes SHA-256 hashes to detect descriptor changes.
   - Extracts features and runs the supervised ML detector.
   - Evaluates the PolicyEngine to determine action (ALLOW, QUARANTINE, BLOCK).
   - Filters out non-approved tools so the client LLM is protected from seeing poisoned docstrings.
2. Intercepts 'tools/call' protocol messages:
   - Verifies authorization status before execution.
   - Rejects calls to quarantined or blocked tools before reaching the upstream server.
   - Audits all inspection and invocation events.

TRANSPARENT PROXY & TRANSPORT REQUIREMENTS:
In production, this interceptor sits as an intermediary between the AI Client and Upstream Server:
    AI Client <──[stdio / SSE]──> MCP Security Gateway <──[stdio / SSE]──> Upstream MCP Server
- In stdio mode, the gateway runs as a sub-process manager, intercepting JSON-RPC messages on stdin/stdout.
- In HTTP/SSE mode, the gateway acts as a reverse proxy server forwarding validated requests.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import Any, Callable

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server

from gateway.audit_logger import AuditLogger
from gateway.change_detector import ChangeDetectionResult, DescriptorChangeDetector
from gateway.descriptor_registry import (
    DescriptorRegistry,
    STATUS_APPROVED,
    STATUS_BLOCKED,
    STATUS_PENDING_REVIEW,
    STATUS_QUARANTINED,
)
from gateway.ml_detector import MLDetector
from gateway.policy_engine import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_QUARANTINE,
    PolicyDecision,
    PolicyEngine,
)

logger = logging.getLogger("gateway_interceptor")


class ToolExecutionDeniedError(PermissionError):
    """Raised when an unapproved, quarantined, or blocked tool is invoked."""
    def __init__(self, tool_name: str, action: str, reason: str) -> None:
        super().__init__(f"Tool execution denied for '{tool_name}' [{action}]: {reason}")
        self.tool_name = tool_name
        self.action = action
        self.reason = reason


class MCPGatewayInterceptor:
    """Core security interceptor that guards MCP tools/list and tools/call requests."""

    def __init__(
        self,
        server_name: str = "TargetMCPServer",
        registry: DescriptorRegistry | None = None,
        detector: MLDetector | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: AuditLogger | None = None,
        model_dir: Path | None = None,
    ) -> None:
        self.server_name = server_name
        self.audit_logger = audit_logger or AuditLogger()
        self.registry = registry or DescriptorRegistry()

        # If no detector is explicitly passed, load the expanded model by default
        if detector is None:
            models_path = model_dir or (Path(__file__).resolve().parent.parent / "models")
            try:
                detector = MLDetector.load_expanded(models_path, fallback_to_baseline=False)
                logger.info(f"MCPGatewayInterceptor auto-loaded expanded ML detector from {models_path}.")
            except Exception as e:
                logger.info(f"Expanded detector not auto-loaded ({e}); proceeding with configured detector.")

        self.detector = detector
        self.change_detector = DescriptorChangeDetector(
            registry=self.registry,
            detector=detector,
        )
        self.policy_engine = policy_engine or PolicyEngine(audit_logger=self.audit_logger)

        # Tracks latest decision per tool: tool_name -> PolicyDecision
        self._active_decisions: dict[str, PolicyDecision] = {}

    def filter_tools_list(
        self,
        upstream_tools: list[types.Tool | dict[str, Any]],
    ) -> list[types.Tool | dict[str, Any]]:
        """Intercept the upstream 'tools/list' response and filter out untrusted tools.

        Only tools that receive an ALLOW decision are returned to the AI client.
        Quarantined and blocked tools are suppressed from the client prompt.

        Args:
            upstream_tools: List of Tool objects or tool dictionaries from upstream server

        Returns:
            Filtered list containing only ALLOWED tools.
        """
        allowed_tools: list[types.Tool | dict[str, Any]] = []

        for item in upstream_tools:
            # Handle both mcp.types.Tool objects and standard dictionaries
            if isinstance(item, types.Tool):
                tool_name = item.name
                desc = item.description or ""
                schema = item.inputSchema if hasattr(item, "inputSchema") else None
            elif isinstance(item, dict):
                tool_name = item.get("name", "unknown")
                desc = item.get("description", "")
                schema = item.get("inputSchema")
            else:
                logger.warning(f"Unexpected tool object type: {type(item)}")
                continue

            # 1. Run change detection (SHA-256 + schema check + ML scan if changed)
            change_result = self.change_detector.inspect_tool(
                tool_name=tool_name,
                server_name=self.server_name,
                incoming_description=desc,
                incoming_schema=schema,
                auto_record_candidate=True,
            )

            # 2. Evaluate Policy Engine
            decision = self.policy_engine.evaluate(change_result)
            self._active_decisions[tool_name] = decision

            # 3. Enforce decision and prevent duplicate-name shadowing attacks
            if decision.action == ACTION_ALLOW:
                # Deduplicate to prevent duplicate entries in client toolset
                already_in = any(
                    (t.name if isinstance(t, types.Tool) else t.get("name")) == tool_name
                    for t in allowed_tools
                )
                if not already_in:
                    allowed_tools.append(item)
                logger.info(f"Gateway ALLOWED tool '{self.server_name}:{tool_name}' for client exposure.")
            else:
                # If a duplicate descriptor previously allowed is now quarantined/blocked, strip it
                allowed_tools = [
                    t for t in allowed_tools
                    if (t.name if isinstance(t, types.Tool) else t.get("name")) != tool_name
                ]
                if decision.action == ACTION_QUARANTINE:
                    logger.warning(
                        f"Gateway QUARANTINED tool '{self.server_name}:{tool_name}'. "
                        f"Suppressed from client tools/list. Reason: {decision.reason}"
                    )
                elif decision.action == ACTION_BLOCK:
                    logger.error(
                        f"Gateway BLOCKED tool '{self.server_name}:{tool_name}'. "
                        f"Suppressed from client tools/list. Reason: {decision.reason}"
                    )

        return allowed_tools

    def authorize_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> tuple[bool, PolicyDecision | None]:
        """Verify whether an incoming 'tools/call' request is permitted to execute.

        Args:
            tool_name: Name of requested tool
            arguments: Tool arguments

        Returns:
            Tuple of (is_authorized: bool, decision: PolicyDecision | None)
        """
        decision = self._active_decisions.get(tool_name)
        if decision is None:
            # Tool was never inspected via filter_tools_list
            logger.warning(f"Unregistered tool invocation attempted: '{tool_name}'")
            return False, None

        if decision.action != ACTION_ALLOW:
            logger.warning(
                f"Attempted execution of non-allowed tool '{tool_name}' (Status: {decision.action})"
            )
            return False, decision

        return True, decision

    async def execute_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        upstream_invoker: Callable[..., Any],
    ) -> Any:
        """Enforce authorization boundary around upstream tool invocation.

        Args:
            tool_name: Name of tool to execute
            arguments: Arguments dict
            upstream_invoker: Async or synchronous callable executing the upstream tool

        Returns:
            Upstream execution result if authorized.

        Raises:
            ToolExecutionDeniedError: If tool is quarantined, blocked, or uninspected.
        """
        is_auth, decision = self.authorize_tool_call(tool_name, arguments)
        if not is_auth:
            action = decision.action if decision else "UNREGISTERED"
            reason = decision.reason if decision else "Tool was not inspected or registered."
            raise ToolExecutionDeniedError(tool_name=tool_name, action=action, reason=reason)

        logger.info(f"Forwarding authorized tool call '{tool_name}' to upstream server...")
        if inspect.iscoroutinefunction(upstream_invoker):
            return await upstream_invoker(tool_name, arguments)
        else:
            return upstream_invoker(tool_name, arguments)

    def revoke_tool_approval(self, tool_name: str, server_name: str | None = None) -> bool:
        """Revoke prior approval for a tool and clear its active authorization decision.

        Args:
            tool_name: Name of tool to revoke
            server_name: Server name (defaults to self.server_name)

        Returns:
            True if approval was revoked, False if tool was not approved.
        """
        srv = server_name or self.server_name
        revoked = self.registry.revoke_approval(tool_name, srv)
        if tool_name in self._active_decisions:
            del self._active_decisions[tool_name]
        return revoked

    def get_security_summary(self) -> dict[str, Any]:
        """Return diagnostic metrics of gateway enforcement decisions."""
        total = len(self._active_decisions)
        counts = {"ALLOW": 0, "QUARANTINE": 0, "BLOCK": 0}
        for d in self._active_decisions.values():
            counts[d.action] = counts.get(d.action, 0) + 1

        return {
            "server_name": self.server_name,
            "total_tools_evaluated": total,
            "allowed_count": counts["ALLOW"],
            "quarantined_count": counts["QUARANTINE"],
            "blocked_count": counts["BLOCK"],
            "decisions": {k: v.to_dict() for k, v in self._active_decisions.items()},
        }


class MCPGatewayProxy:
    """Application-layer Security Gateway Proxy for Model Context Protocol (MCP) servers.

    This proxy wraps an upstream MCP server instance (such as a FastMCP server or an MCP
    server session) and enforces strict protocol-level security boundaries:

    1. tools/list Enforcement:
       - Intercepts calls to 'list_tools()'.
       - Inspects all tool descriptors, checks SHA-256 hashes against approved baseline.
       - Runs ML detector inference and policy engine checks.
       - Returns ONLY tools with an explicit ALLOW decision.
       - Quarantined and blocked tools are completely omitted from the toolset exposed
         to the LLM client.

    2. tools/call Enforcement:
       - Intercepts calls to 'call_tool(name, arguments)'.
       - Enforces authorization on EVERY tool call.
       - Rejects execution of uninspected, unapproved, quarantined, or blocked tools with
         ToolExecutionDeniedError.
       - Forwards authorized calls to the underlying tool implementation while preserving
         original arguments and results.

    3. Direct-Call Bypass Prevention:
       - Direct calls to tools not exposed or approved during tools/list are blocked.
       - Upstream server reference is encapsulated to prevent client bypass.

    4. Architectural Scope Disclosure:
       - NOTE: This proxy operates at the application protocol layer (wrapping MCP Python
         server/session interfaces), not as a transparent stdio/socket kernel-level redirector.
       - Real enforcement is implemented at the MCP API boundary.
    """

    def __init__(
        self,
        upstream_server: Any,
        interceptor: MCPGatewayInterceptor | None = None,
        server_name: str | None = None,
        registry: DescriptorRegistry | None = None,
        detector: MLDetector | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self._upstream_server = upstream_server
        srv_name = server_name or getattr(upstream_server, "name", "UpstreamMCPServer")
        self.server_name = srv_name
        self.interceptor = interceptor or MCPGatewayInterceptor(
            server_name=srv_name,
            registry=registry,
            detector=detector,
            policy_engine=policy_engine,
        )

    async def list_tools(self) -> list[types.Tool | dict[str, Any]]:
        """Retrieve upstream tools and filter them through the security interceptor."""
        if hasattr(self._upstream_server, "list_tools"):
            res = self._upstream_server.list_tools()
            if inspect.isawaitable(res):
                upstream_tools = await res
            else:
                upstream_tools = res
        else:
            raise AttributeError("Upstream server does not expose a 'list_tools' method.")

        return self.interceptor.filter_tools_list(upstream_tools)

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Authorize and execute a tool call against the upstream server.

        Raises:
            ToolExecutionDeniedError: If tool is not allowed, quarantined, blocked,
                                      or was not approved in tools/list.
        """
        args = arguments if arguments is not None else {}

        # 1. Authorize via interceptor
        is_auth, decision = self.interceptor.authorize_tool_call(name, args)
        if not is_auth:
            action = decision.action if decision else "UNREGISTERED"
            reason = decision.reason if decision else f"Tool '{name}' was not inspected or approved in tools/list."
            raise ToolExecutionDeniedError(tool_name=name, action=action, reason=reason)

        # 2. Dispatch to upstream server
        if hasattr(self._upstream_server, "call_tool"):
            res = self._upstream_server.call_tool(name, args)
            if inspect.isawaitable(res):
                return await res
            return res
        elif hasattr(self._upstream_server, name):
            func = getattr(self._upstream_server, name)
            if inspect.iscoroutinefunction(func):
                return await func(**args)
            return func(**args)
        else:
            raise AttributeError(f"Upstream server does not expose method to invoke tool '{name}'.")

    def get_security_summary(self) -> dict[str, Any]:
        """Return diagnostic metrics of gateway enforcement decisions."""
        return self.interceptor.get_security_summary()

    def approve_tool(self, tool_name: str, description: str | None = None) -> None:
        """Promote a quarantined or candidate tool to approved baseline and allow it."""
        desc = description
        if desc is None:
            key = self.interceptor.registry._key(self.server_name, tool_name)
            history = self.interceptor.registry._candidate_history.get(key, [])
            if history:
                desc = history[-1].description
            else:
                appr = self.interceptor.registry.get_approved(tool_name, self.server_name)
                desc = appr.description if appr else ""
        self.interceptor.registry.promote_to_approved(tool_name, self.server_name, desc)
        # Update active decision to ALLOW
        from gateway.policy_engine import ACTION_ALLOW, PolicyDecision
        import datetime as dt_mod
        self.interceptor._active_decisions[tool_name] = PolicyDecision(
            action=ACTION_ALLOW,
            reason="Tool was audited and promoted to approved baseline by human administrator.",
            rule_triggered="RULE_HUMAN_APPROVAL_PROMOTION",
            malicious_probability=0.0,
            risk_level="LOW",
            is_approved=True,
            violations=[],
            details={"promoted_by": "human_administrator"},
            sha256_hash="",
            timestamp=dt_mod.datetime.now(dt_mod.timezone.utc).isoformat(),
        )

    def revoke_tool_approval(self, tool_name: str) -> bool:
        """Revoke prior approval for a tool and clear active authorization."""
        return self.interceptor.revoke_tool_approval(tool_name, self.server_name)

    @property
    def raw_server_access(self) -> None:
        """Direct access to upstream server is blocked by security gateway policy."""
        raise PermissionError("Direct access to upstream server is blocked by MCP Security Gateway.")


class MCPGatewayProtocolServer:
    """Protocol-level MCP Gateway Server that acts as a true protocol reverse proxy.

    Accepts incoming MCP Client connections over any supported MCP transport
    (in-memory streams, stdio, or SSE) and proxies requests to an upstream MCP server
    through an upstream ClientSession, enforcing:
    1. tools/list filtering: strips unapproved, quarantined, and blocked tools.
    2. tools/call authorization: verifies every tool call; unapproved tools are rejected
       with ToolExecutionDeniedError / CallToolResult(isError=True).
    3. Upstream execution prevention: unauthorized tool calls are never forwarded to upstream.
    """

    def __init__(
        self,
        upstream_session: ClientSession,
        interceptor: MCPGatewayInterceptor | None = None,
        server_name: str = "mcp_security_gateway",
        registry: DescriptorRegistry | None = None,
        detector: MLDetector | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.upstream_session = upstream_session
        self.interceptor = interceptor or MCPGatewayInterceptor(
            server_name=server_name,
            registry=registry,
            detector=detector,
            policy_engine=policy_engine,
        )
        self.server_name = server_name
        self.server = Server(server_name)
        self._setup_handlers()

    def _setup_handlers(self) -> None:
        @self.server.list_tools()
        async def list_tools() -> list[types.Tool]:
            upstream_res = await self.upstream_session.list_tools()
            allowed = self.interceptor.filter_tools_list(upstream_res.tools)
            return allowed

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.Content]:
            args = arguments or {}
            is_auth, decision = self.interceptor.authorize_tool_call(name, args)
            if not is_auth:
                action = decision.action if decision else "UNREGISTERED"
                reason = decision.reason if decision else f"Tool '{name}' was not inspected or approved in tools/list."
                raise ToolExecutionDeniedError(tool_name=name, action=action, reason=reason)
            res = await self.upstream_session.call_tool(name, args)
            return res

    async def run(
        self,
        read_stream: Any,
        write_stream: Any,
        raise_exceptions: bool = False,
    ) -> None:
        """Run the gateway MCP server over the provided transport streams."""
        init_opts = self.server.create_initialization_options()
        await self.server.run(read_stream, write_stream, init_opts, raise_exceptions=raise_exceptions)
