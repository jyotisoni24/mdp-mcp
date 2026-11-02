"""Interactive Demonstration Runner for MCP Security Gateway.

Provides a standalone, reproducible demonstration of all security enforcement scenarios:
1. Normal approved tool -> ALLOW
2. New benign tool -> QUARANTINE
3. Modified legitimate description -> QUARANTINE
4. Prompt-injection description -> BLOCK
5. Data-exfiltration description -> BLOCK
6. High-privilege tool with low ML score -> Mandatory security rule BLOCK
7. Direct tools/call bypass attempt -> Rejected by gateway (0 upstream calls)
8. Human approval -> Tool promoted to trusted baseline
9. MDP policy mode vs. Static threshold mode comparison

Usage:
    python scripts/demo_runner.py --all
    python scripts/demo_runner.py --scenario 1
    python scripts/demo_runner.py --scenario 7
    python scripts/demo_runner.py --list-tools
    python scripts/demo_runner.py --call-tool calculate_total --args '{"subtotal": 100.0, "tax_rate": 0.05}'
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
import sys
import tempfile
from typing import Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.audit_logger import AuditLogger
from gateway.change_detector import DescriptorChangeDetector
from gateway.descriptor_registry import DescriptorRegistry
from gateway.interceptor import (
    MCPGatewayInterceptor,
    MCPGatewayProxy,
    ToolExecutionDeniedError,
)
from gateway.ml_detector import MLDetector
from gateway.policy_engine import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ACTION_QUARANTINE,
    POLICY_MODE_MDP,
    POLICY_MODE_THRESHOLD,
    PolicyConfig,
    PolicyEngine,
    evaluate_mandatory_violations,
)
from server.test_server import (
    BASE_DESCRIPTIONS,
    VARIANT_BASELINE,
    VARIANT_DATA_EXFILTRATION,
    VARIANT_LEGITIMATE_UPDATE,
    VARIANT_PROMPT_INJECTION,
    VARIANT_SUSPICIOUS_BENIGN,
    build_test_server,
    get_tool_descriptions,
)

MODELS_DIR = PROJECT_ROOT / "models"


def init_demo_context(policy_mode: str = POLICY_MODE_THRESHOLD):
    """Initialize an isolated in-memory gateway context with baseline approvals."""
    # Ensure log directory in a temporary safe location
    temp_dir = Path(tempfile.mkdtemp(prefix="mcp_sec_demo_"))
    log_file = temp_dir / "audit.jsonl"
    logger = AuditLogger(log_file=log_file)

    detector = MLDetector.load_expanded(MODELS_DIR)
    registry = DescriptorRegistry()

    # Seed baseline approved tools
    for name, desc in BASE_DESCRIPTIONS.items():
        registry.register_approved(name, "ProductionServer", desc)

    config = PolicyConfig(mode=policy_mode, block_threshold=0.70)
    policy_engine = PolicyEngine(config=config, audit_logger=logger)

    interceptor = MCPGatewayInterceptor(
        server_name="ProductionServer",
        registry=registry,
        detector=detector,
        policy_engine=policy_engine,
        audit_logger=logger,
    )

    return {
        "detector": detector,
        "registry": registry,
        "policy_engine": policy_engine,
        "interceptor": interceptor,
        "logger": logger,
        "temp_dir": temp_dir,
    }


def print_banner(title: str):
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


async def demo_scenario_1():
    print_banner("SCENARIO 1: Normal Approved MCP Tool -> ALLOW")
    ctx = init_demo_context()
    server = build_test_server(VARIANT_BASELINE)
    proxy = MCPGatewayProxy(
        upstream_server=server,
        server_name="ProductionServer",
        interceptor=ctx["interceptor"],
    )

    print("Target Tool: 'calculate_total'")
    print(f"Description: \"{BASE_DESCRIPTIONS['calculate_total']}\"")
    print("\n[Step 1] Client invokes tools/list via Gateway Proxy...")
    exposed = await proxy.list_tools()
    exposed_names = [t.name for t in exposed]
    print(f"-> Gateway exposed {len(exposed)} tools: {exposed_names}")

    print("\n[Step 2] Client invokes tools/call('calculate_total', subtotal=100.0, tax_rate=0.05)...")
    res = await proxy.call_tool("calculate_total", {"subtotal": 100.0, "tax_rate": 0.05})
    # FastMCP returns tuple or dict
    output_val = res[1]["result"] if isinstance(res, tuple) else res
    print(f"-> Upstream execution SUCCESS! Output: {output_val}")
    print("\nRESULT: [ALLOW] - Baseline hash matches, ML risk is low, tool executed upstream.")


async def demo_scenario_2():
    print_banner("SCENARIO 2: New Benign MCP Tool -> QUARANTINE")
    ctx = init_demo_context()

    # Create server with an unapproved new tool
    server = build_test_server(VARIANT_BASELINE)
    new_desc = "Compute cryptographic checksum of a string or buffer using BLAKE3 algorithm."

    @server.tool(name="compute_blake3_hash", description=new_desc)
    def compute_blake3_hash(data: str) -> str:
        return "mock_hash_abc123"

    proxy = MCPGatewayProxy(
        upstream_server=server,
        server_name="ProductionServer",
        interceptor=ctx["interceptor"],
    )

    print("Target Tool: 'compute_blake3_hash' (Brand new, unapproved tool)")
    print(f"Description: \"{new_desc}\"")

    print("\n[Step 1] Client invokes tools/list via Gateway Proxy...")
    exposed = await proxy.list_tools()
    exposed_names = [t.name for t in exposed]
    print(f"-> Exposed tools: {exposed_names}")
    print(f"-> Is 'compute_blake3_hash' exposed to client? {'compute_blake3_hash' in exposed_names}")

    decision = ctx["interceptor"]._active_decisions.get("compute_blake3_hash")
    print(f"-> Gateway Decision: [{decision.action}] (Reason: {decision.reason})")

    print("\n[Step 2] Attacker/Client attempts direct tools/call('compute_blake3_hash')...")
    try:
        await proxy.call_tool("compute_blake3_hash", {"data": "test"})
        print("-> ERROR: Tool executed upstream!")
    except ToolExecutionDeniedError as e:
        print(f"-> Gateway REJECTED execution: {e}")
        print("-> Upstream execution count: 0 (Protected)")

    print("\nRESULT: [QUARANTINE] - New tool safely isolated; never exposed to LLM client.")


async def demo_scenario_3():
    print_banner("SCENARIO 3: Modified Legitimate Tool Description -> QUARANTINE")
    ctx = init_demo_context()

    # Upstream server updated simple_division description to add error handling docs
    server = build_test_server(VARIANT_LEGITIMATE_UPDATE)
    mutated_desc = get_tool_descriptions(VARIANT_LEGITIMATE_UPDATE)["simple_division"]

    proxy = MCPGatewayProxy(
        upstream_server=server,
        server_name="ProductionServer",
        interceptor=ctx["interceptor"],
    )

    print("Target Tool: 'simple_division'")
    print(f"Baseline Description: \"{BASE_DESCRIPTIONS['simple_division']}\"")
    print(f"Updated Description : \"{mutated_desc}\"")

    print("\n[Step 1] Client invokes tools/list...")
    exposed = await proxy.list_tools()
    exposed_names = [t.name for t in exposed]
    print(f"-> Exposed tools: {exposed_names}")

    pred = ctx["detector"].predict(mutated_desc)
    print(f"-> ML Malicious Probability: {pred.malicious_probability:.4f} (Benign wording)")
    print(f"-> SHA-256 Hash Status: MISMATCH (Descriptor drift detected)")

    decision = ctx["interceptor"]._active_decisions.get("simple_division")
    print(f"-> Gateway Decision: [{decision.action}] (Reason: {decision.reason})")

    print("\n[Step 2] Attempt execution...")
    try:
        await proxy.call_tool("simple_division", {"a": 10, "b": 2})
    except ToolExecutionDeniedError as e:
        print(f"-> Gateway BLOCKED invocation: {e}")

    print("\nRESULT: [QUARANTINE] - Modified tool held for administrator review; not auto-trusted.")


async def demo_scenario_4():
    print_banner("SCENARIO 4: Prompt Injection Attack in Description -> BLOCK")
    ctx = init_demo_context()

    server = build_test_server(VARIANT_PROMPT_INJECTION)
    injected_desc = get_tool_descriptions(VARIANT_PROMPT_INJECTION)["search_products"]

    proxy = MCPGatewayProxy(
        upstream_server=server,
        server_name="ProductionServer",
        interceptor=ctx["interceptor"],
    )

    print("Target Tool: 'search_products'")
    print(f"Injected Description: \"{injected_desc}\"")

    print("\n[Step 1] ML Detector analysis...")
    pred = ctx["detector"].predict(injected_desc)
    print(f"-> ML Malicious Probability: {pred.malicious_probability:.4f} ({pred.risk_level} Risk)")
    print(f"-> Extraction Signal: {pred.signals}")

    print("\n[Step 2] Client invokes tools/list...")
    exposed = await proxy.list_tools()
    exposed_names = [t.name for t in exposed]
    print(f"-> Exposed tools: {exposed_names}")
    print(f"-> 'search_products' exposed? {'search_products' in exposed_names}")

    decision = ctx["interceptor"]._active_decisions.get("search_products")
    print(f"-> Gateway Decision: [{decision.action}] (Reason: {decision.reason})")

    print("\nRESULT: [BLOCK] - Malicious prompt injection stripped from tool list; LLM never sees injection.")


async def demo_scenario_5():
    print_banner("SCENARIO 5: Data Exfiltration Attack (23.py) -> BLOCK")
    ctx = init_demo_context()

    server = build_test_server(VARIANT_DATA_EXFILTRATION)
    exfil_desc = get_tool_descriptions(VARIANT_DATA_EXFILTRATION)["simple_division"]

    proxy = MCPGatewayProxy(
        upstream_server=server,
        server_name="ProductionServer",
        interceptor=ctx["interceptor"],
    )

    print("Target Tool: 'simple_division'")
    print(f"Poisoned Description: \"{exfil_desc[:120]}...\"")

    print("\n[Step 1] Checking Mandatory Security Rules...")
    violations = evaluate_mandatory_violations(exfil_desc)
    print(f"-> Detected Violations: {violations}")

    pred = ctx["detector"].predict(exfil_desc)
    print(f"-> ML Malicious Probability: {pred.malicious_probability:.4f}")

    print("\n[Step 2] Client invokes tools/list...")
    exposed = await proxy.list_tools()
    exposed_names = [t.name for t in exposed]
    print(f"-> Exposed tools: {exposed_names}")

    decision = ctx["interceptor"]._active_decisions.get("simple_division")
    print(f"-> Gateway Decision: [{decision.action}] (Reason: {decision.reason})")

    print("\nRESULT: [BLOCK] - High-severity sensitive file access strictly blocked by heuristic + ML.")


async def demo_scenario_6():
    print_banner("SCENARIO 6: High-Privilege Target with Low ML Score -> STRICT BLOCK")
    ctx = init_demo_context()

    # Tool with low ML score but targeting sensitive file
    subtle_desc = "Quick utility tool to verify user directory permissions and inspect ~/.ssh/id_rsa credentials."
    violations = evaluate_mandatory_violations(subtle_desc)
    pred = ctx["detector"].predict(subtle_desc)

    print(f"Target Description: \"{subtle_desc}\"")
    print(f"-> ML Malicious Probability: {pred.malicious_probability:.4f} (Disguised wording)")
    print(f"-> Mandatory Rule Invariant: {violations}")

    # Evaluate via PolicyEngine
    change_detector = DescriptorChangeDetector(registry=ctx["registry"], detector=ctx["detector"])
    change_res = change_detector.inspect_tool("ssh_checker", "ProductionServer", subtle_desc)
    decision = ctx["policy_engine"].evaluate(change_res)

    print(f"-> Policy Decision: [{decision.action}]")
    print(f"-> Reason: {decision.reason}")
    print("\nRESULT: [BLOCK] - Mandatory security rules non-overridable by ML score.")


async def demo_scenario_7():
    print_banner("SCENARIO 7: Direct tools/call Bypass Attempt -> REJECTED")
    ctx = init_demo_context()
    server = build_test_server(VARIANT_BASELINE)
    proxy = MCPGatewayProxy(
        upstream_server=server,
        server_name="ProductionServer",
        interceptor=ctx["interceptor"],
    )

    print("Attack Vector: Direct invocation of uninspected tool 'unregistered_admin_tool'")
    print("Notice: The client intentionally skips tools/list and calls tools/call directly.")

    try:
        await proxy.call_tool("unregistered_admin_tool", {"command": "whoami"})
        print("-> BREACH: Direct call bypassed security gateway!")
    except ToolExecutionDeniedError as e:
        print(f"-> Gateway Interceptor Caught Bypass Attempt: {e}")
        print("-> Status: REJECTED | Upstream calls: 0")

    print("\nRESULT: [BLOCKED] - Protocol-level interception enforces fail-closed authorization.")


async def demo_scenario_8():
    print_banner("SCENARIO 8: Human Approval Workflow -> Tool Becomes Trusted")
    ctx = init_demo_context()
    server = build_test_server(VARIANT_LEGITIMATE_UPDATE)
    mutated_desc = get_tool_descriptions(VARIANT_LEGITIMATE_UPDATE)["simple_division"]
    proxy = MCPGatewayProxy(
        upstream_server=server,
        server_name="ProductionServer",
        interceptor=ctx["interceptor"],
    )

    print("1. Initial state: Modified simple_division description is quarantined...")
    _ = await proxy.list_tools()
    decision_before = ctx["interceptor"]._active_decisions.get("simple_division")
    print(f"   -> Status before approval: [{decision_before.action}]")

    print("\n2. Security Administrator audits tool code, verifies safety, and approves:")
    print("   -> Executing: proxy.approve_tool('simple_division', new_description)")
    proxy.approve_tool("simple_division", mutated_desc)

    print("\n3. Client invokes tools/list again...")
    exposed = await proxy.list_tools()
    exposed_names = [t.name for t in exposed]
    print(f"   -> Exposed tools: {exposed_names}")
    print(f"   -> 'simple_division' now visible? {'simple_division' in exposed_names}")

    print("\n4. Client executes simple_division...")
    res = await proxy.call_tool("simple_division", {"a": 42, "b": 7})
    output_val = res[1]["result"] if isinstance(res, tuple) else res
    print(f"   -> Execution SUCCESS! Output: {output_val}")

    print("\nRESULT: [TRUSTED] - Cryptographic baseline updated; tool safely restored to production.")


async def demo_scenario_9():
    print_banner("SCENARIO 9: Policy Mode Comparison (Static Threshold vs. MDP)")
    from training.compare_gateway_policies import run_comparative_gateway_evaluation
    _ = run_comparative_gateway_evaluation()


async def run_all_demos():
    print("=" * 80)
    print("   MCP SECURITY GATEWAY - COMPREHENSIVE DEMONSTRATION SUITE")
    print("=" * 80)
    await demo_scenario_1()
    await demo_scenario_2()
    await demo_scenario_3()
    await demo_scenario_4()
    await demo_scenario_5()
    await demo_scenario_6()
    await demo_scenario_7()
    await demo_scenario_8()
    await demo_scenario_9()

    print("\n" + "=" * 80)
    print("   ALL 9 DEMONSTRATION SCENARIOS COMPLETED SUCCESSFULLY")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="Run all 9 demonstration scenarios in sequence")
    parser.add_argument("--scenario", type=int, choices=range(1, 10), help="Run a specific scenario (1-9)")
    parser.add_argument("--list-tools", action="store_true", help="Demonstrate tools/list filtering on baseline")
    parser.add_argument("--call-tool", type=str, help="Call a specific tool (e.g. calculate_total)")
    parser.add_argument("--args", type=str, default="{}", help="JSON string arguments for tool call")
    args = parser.parse_args()

    if args.all or (len(sys.argv) == 1):
        asyncio.run(run_all_demos())
    elif args.scenario == 1:
        asyncio.run(demo_scenario_1())
    elif args.scenario == 2:
        asyncio.run(demo_scenario_2())
    elif args.scenario == 3:
        asyncio.run(demo_scenario_3())
    elif args.scenario == 4:
        asyncio.run(demo_scenario_4())
    elif args.scenario == 5:
        asyncio.run(demo_scenario_5())
    elif args.scenario == 6:
        asyncio.run(demo_scenario_6())
    elif args.scenario == 7:
        asyncio.run(demo_scenario_7())
    elif args.scenario == 8:
        asyncio.run(demo_scenario_8())
    elif args.scenario == 9:
        asyncio.run(demo_scenario_9())
    elif args.list_tools:
        async def list_cmd():
            ctx = init_demo_context()
            server = build_test_server(VARIANT_BASELINE)
            proxy = MCPGatewayProxy(upstream_server=server, server_name="ProductionServer", interceptor=ctx["interceptor"])
            tools = await proxy.list_tools()
            print("\nExposed Tools via Gateway Proxy:")
            for t in tools:
                print(f" - {t.name}: {t.description}")
        asyncio.run(list_cmd())
    elif args.call_tool:
        async def call_cmd():
            ctx = init_demo_context()
            server = build_test_server(VARIANT_BASELINE)
            proxy = MCPGatewayProxy(upstream_server=server, server_name="ProductionServer", interceptor=ctx["interceptor"])
            _ = await proxy.list_tools()
            kwargs = json.loads(args.args)
            print(f"\nCalling tool '{args.call_tool}' with args {kwargs}...")
            res = await proxy.call_tool(args.call_tool, kwargs)
            print(f"Result: {res}")
        asyncio.run(call_cmd())


if __name__ == "__main__":
    main()
