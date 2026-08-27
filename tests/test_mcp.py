from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest
from mcp.client import Client

import pyunidbg

FIXTURE = Path(__file__).parent / "fixtures" / "libtrace.so"


def test_python_native_mcp_in_process() -> None:
    async def exercise() -> None:
        with pyunidbg.AndroidEmulator("io.pyunidbg.mcp") as emulator:
            emulator.load_library(FIXTURE)
            server = emulator.mcp()

            @server.tool()
            def multiply(left: int, right: int) -> int:
                """Multiply two integers."""
                return left * right

            async with Client(server.protocol) as client:
                tools = await client.list_tools()
                names = {tool.name for tool in tools.tools}
                assert len(names) == 43
                assert {"check_connection", "read_memory", "call_symbol", "multiply"} <= names

                status = await client.call_tool("check_connection", {})
                assert status.structured_content["architecture"] == "ARM64"
                assert status.structured_content["backend"] == "UnicornBackend"

                result = await client.call_tool(
                    "call_symbol",
                    {
                        "module_name": "libtrace.so",
                        "symbol": "traced_add",
                        "arguments": [20, 22],
                    },
                )
                assert result.structured_content == {"result": 42}

                custom = await client.call_tool("multiply", {"left": 6, "right": 7})
                assert custom.structured_content == {"result": 42}

                allocation = await client.call_tool("allocate_memory", {"size": 16})
                address = allocation.structured_content["address"]
                await client.call_tool(
                    "write_memory", {"address": address, "hex_data": "68656c6c6f00"}
                )
                string = await client.call_tool("read_string", {"address": address})
                assert string.structured_content == {"result": "hello"}
                freed = await client.call_tool("free_memory", {"address": address})
                assert freed.structured_content == {"result": True}

            server.stop()

    asyncio.run(exercise())


def test_python_mcp_breakpoint_pause_and_continue() -> None:
    async def exercise() -> None:
        with pyunidbg.AndroidEmulator("io.pyunidbg.mcp-breakpoint") as emulator:
            module = emulator.load_library(FIXTURE)
            symbol = module.find_symbol("traced_add")
            assert symbol is not None
            server = emulator.mcp()
            async with Client(server.protocol) as client:
                added = await client.call_tool(
                    "add_breakpoint", {"address": f"0x{symbol.address:x}"}
                )
                assert added.structured_content == {"result": True}
                execution = asyncio.create_task(
                    asyncio.to_thread(module.call_symbol, "traced_add", 4, 5)
                )
                for _ in range(100):
                    if server.controller.paused:
                        break
                    await asyncio.sleep(0.01)
                assert server.controller.paused
                events = await client.call_tool("poll_events", {"after": 0})
                assert events.structured_content["result"][0]["event"] == "breakpoint_hit"
                continued = await client.call_tool("continue_execution", {})
                assert continued.structured_content == {"result": True}
                assert int(await execution) == 9
            server.stop()

    asyncio.run(exercise())


def test_streamable_http_and_remote_binding_guard() -> None:
    with pyunidbg.AndroidEmulator("io.pyunidbg.mcp-http") as emulator:
        with pytest.raises(ValueError, match="allow_remote"):
            emulator.mcp(host="0.0.0.0")

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        server = emulator.mcp(port=port).start()

        async def exercise() -> None:
            async with Client(server.url) as client:
                result = await client.call_tool("check_connection", {})
                assert result.structured_content["process"] == "io.pyunidbg.mcp-http"

        try:
            asyncio.run(exercise())
            assert server.running
            assert server.url == f"http://127.0.0.1:{port}/mcp"
        finally:
            server.stop()
        assert not server.running


def test_mcp_implementation_has_no_unidbg_java_mcp_reference() -> None:
    source = (Path(pyunidbg.__file__).parent / "mcp.py").read_text()
    assert "com.github.unidbg.mcp" not in source
