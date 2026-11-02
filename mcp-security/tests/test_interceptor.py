"""Unit tests for Phase 7: MCP Security Gateway Interceptor.

Verifies:
1. tools/list interception filters out unapproved, quarantined, and blocked tools.
2. Prompt injection variant (Case 3) is suppressed from client exposure.
3. Sensitive data exfiltration variant (Case 4 - 23.py) is suppressed from client exposure.
4. tools/call execution authorization prevents unauthorized invocation.
5. Invariance: upstream tool code is never called for blocked/quarantined tools.
6. Gateway security telemetry and audit summaries.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import mcp.types as types
import pytest

from gateway.descriptor_registry import DescriptorRegistry
from gateway.interceptor import MCPGatewayInterceptor, ToolExecutionDeniedError
from gateway.ml_detector import MLDetector
from gateway.policy_engine import ACTION_ALLOW, ACTION_BLOCK, ACTION_QUARANTINE, PolicyEngine
from server.test_server import (
    BASE_DESCRIPTIONS,
    VARIANT_BASELINE,
    VARIANT_DATA_EXFILTRATION,
    VARIANT_LEGITIMATE_UPDATE,
    VARIANT_PROMPT_INJECTION,
    build_test_server,
)

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"


@pytest.fixture(scope="module")
def detector() -> MLDetector:
    return MLDetector.load(MODELS_DIR)


@pytest.fixture
def seeded_registry() -> DescriptorRegistry:
    """Registry seeded with approved baseline tools."""
    registry = DescriptorRegistry()
    for tool_name, desc in BASE_DESCRIPTIONS.items():
        registry.register_approved(tool_name, "TestServer", desc)
    return registry


@pytest.mark.asyncio
async def test_interceptor_allows_approved_baseline(detector: MLDetector, seeded_registry: DescriptorRegistry):
    """Verify that when upstream tools match approved baseline, all 4 are allowed."""
    server = build_test_server(VARIANT_BASELINE)
    upstream_tools = await server.list_tools()

    interceptor = MCPGatewayInterceptor(
        server_name="TestServer",
        registry=seeded_registry,
        detector=detector,
    )

    allowed = interceptor.filter_tools_list(upstream_tools)
    assert len(allowed) == 4
    names = [t.name for t in allowed]
    assert "simple_division" in names
    assert "search_products" in names


@pytest.mark.asyncio
async def test_interceptor_blocks_prompt_injection(detector: MLDetector, seeded_registry: DescriptorRegistry):
    """Verify that prompt injection (Case 3) is blocked and stripped from tools/list."""
    server = build_test_server(VARIANT_PROMPT_INJECTION)
    upstream_tools = await server.list_tools()

    interceptor = MCPGatewayInterceptor(
        server_name="TestServer",
        registry=seeded_registry,
        detector=detector,
    )

    allowed = interceptor.filter_tools_list(upstream_tools)
    allowed_names = [t.name for t in allowed]

    # search_products must be BLOCKED and excluded
    assert "search_products" not in allowed_names
    assert len(allowed) == 3

    # Attempting to call the blocked tool must raise ToolExecutionDeniedError
    mock_invoker_called = False

    def mock_invoker(name, args):
        nonlocal mock_invoker_called
        mock_invoker_called = True
        return "result"

    with pytest.raises(ToolExecutionDeniedError) as exc_info:
        await interceptor.execute_tool_call("search_products", {"query": "shoes"}, mock_invoker)

    assert exc_info.value.action == ACTION_BLOCK
    assert mock_invoker_called is False, "Upstream tool code must NEVER execute for blocked tools"


@pytest.mark.asyncio
async def test_interceptor_blocks_23_py_data_exfiltration(detector: MLDetector, seeded_registry: DescriptorRegistry):
    """Verify that 23.py sensitive data exfiltration (Case 4) is blocked."""
    server = build_test_server(VARIANT_DATA_EXFILTRATION)
    upstream_tools = await server.list_tools()

    interceptor = MCPGatewayInterceptor(
        server_name="TestServer",
        registry=seeded_registry,
        detector=detector,
    )

    allowed = interceptor.filter_tools_list(upstream_tools)
    allowed_names = [t.name for t in allowed]

    # simple_division must be BLOCKED and excluded
    assert "simple_division" not in allowed_names
    assert len(allowed) == 3

    # Attempting to execute must be prevented
    with pytest.raises(ToolExecutionDeniedError) as exc_info:
        await interceptor.execute_tool_call("simple_division", {"a": 10, "b": 2}, lambda n, a: 5.0)

    assert exc_info.value.action == ACTION_BLOCK


@pytest.mark.asyncio
async def test_interceptor_quarantines_legitimate_update(detector: MLDetector, seeded_registry: DescriptorRegistry):
    """Verify that unverified rewordings are quarantined and hidden until approved."""
    server = build_test_server(VARIANT_LEGITIMATE_UPDATE)
    upstream_tools = await server.list_tools()

    interceptor = MCPGatewayInterceptor(
        server_name="TestServer",
        registry=seeded_registry,
        detector=detector,
    )

    allowed = interceptor.filter_tools_list(upstream_tools)
    allowed_names = [t.name for t in allowed]

    # Both simple_division and calculate_total had updates in this variant;
    # they must be QUARANTINED (not allowed yet)
    assert "simple_division" not in allowed_names
    assert "calculate_total" not in allowed_names
    # Unchanged tools remain allowed
    assert "search_products" in allowed_names
    assert "get_weather" in allowed_names


@pytest.mark.asyncio
async def test_interceptor_authorized_execution(detector: MLDetector, seeded_registry: DescriptorRegistry):
    """Verify that an allowed tool successfully forwards calls to the upstream invoker."""
    server = build_test_server(VARIANT_BASELINE)
    upstream_tools = await server.list_tools()

    interceptor = MCPGatewayInterceptor(
        server_name="TestServer",
        registry=seeded_registry,
        detector=detector,
    )

    interceptor.filter_tools_list(upstream_tools)

    # Calling allowed calculate_total
    result = await interceptor.execute_tool_call(
        tool_name="calculate_total",
        arguments={"subtotal": 100.0, "tax_rate": 0.08},
        upstream_invoker=lambda name, args: args["subtotal"] * (1.0 + args["tax_rate"]),
    )
    assert result == 108.0


@pytest.mark.asyncio
async def test_security_summary_diagnostics(detector: MLDetector, seeded_registry: DescriptorRegistry):
    """Verify security summary telemetry report."""
    server = build_test_server(VARIANT_PROMPT_INJECTION)
    upstream_tools = await server.list_tools()

    interceptor = MCPGatewayInterceptor(
        server_name="TestServer",
        registry=seeded_registry,
        detector=detector,
    )
    interceptor.filter_tools_list(upstream_tools)
    summary = interceptor.get_security_summary()

    assert summary["server_name"] == "TestServer"
    assert summary["total_tools_evaluated"] == 4
    assert summary["blocked_count"] == 1
    assert summary["allowed_count"] == 3
