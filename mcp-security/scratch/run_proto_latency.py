import asyncio
import time
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import anyio
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
import mcp.types as types

from gateway.descriptor_registry import DescriptorRegistry
from gateway.interceptor import MCPGatewayInterceptor, MCPGatewayProtocolServer
from gateway.ml_detector import MLDetector
from server.test_server import BASE_DESCRIPTIONS

async def test_protocol_latency():
    upstream = Server("test_upstream")
    @upstream.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name="calculate_total",
                description=BASE_DESCRIPTIONS["calculate_total"],
                inputSchema={"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}},
            )
        ]
    @upstream.call_tool()
    async def call_tool(name: str, arguments: dict | None) -> list[types.TextContent]:
        return [types.TextContent(type="text", text="105.0")]

    models_dir = PROJECT_ROOT / "models"
    detector = MLDetector.load_expanded(models_dir)
    registry = DescriptorRegistry()
    registry.register_approved("calculate_total", "ProductionMCPServer", BASE_DESCRIPTIONS["calculate_total"])

    interceptor = MCPGatewayInterceptor(server_name="ProductionMCPServer", registry=registry, detector=detector)

    # Streams
    gw2up_send, gw2up_recv = anyio.create_memory_object_stream(20)
    up2gw_send, up2gw_recv = anyio.create_memory_object_stream(20)

    c2gw_send, c2gw_recv = anyio.create_memory_object_stream(20)
    gw2c_send, gw2c_recv = anyio.create_memory_object_stream(20)

    async with anyio.create_task_group() as tg:
        tg.start_soon(upstream.run, gw2up_recv, up2gw_send, upstream.create_initialization_options())
        async with ClientSession(up2gw_recv, gw2up_send) as upstream_session:
            await upstream_session.initialize()

            gw_server = MCPGatewayProtocolServer(
                upstream_session=upstream_session,
                interceptor=interceptor,
                server_name="GatewayProxy",
            )
            tg.start_soon(gw_server.run, c2gw_recv, gw2c_send)

            async with ClientSession(gw2c_recv, c2gw_send) as client:
                await client.initialize()

                # Warmup
                for _ in range(5):
                    await client.list_tools()
                    await client.call_tool("calculate_total", {"a": 10, "b": 20})

                # Measure 20 runs
                t0 = time.perf_counter()
                for _ in range(20):
                    await client.list_tools()
                list_time = (time.perf_counter() - t0) / 20 * 1000

                t1 = time.perf_counter()
                for _ in range(20):
                    await client.call_tool("calculate_total", {"a": 10, "b": 20})
                call_time = (time.perf_counter() - t1) / 20 * 1000

                print(f"Protocol list latency: {list_time:.3f} ms")
                print(f"Protocol call latency: {call_time:.3f} ms")
                tg.cancel_scope.cancel()

if __name__ == "__main__":
    anyio.run(test_protocol_latency)
