"""MCP client: connect to MCP servers and expose their tools to the agent.

Streamlit code is synchronous and MCP's SDK is async, so a hub owns one background event loop in a daemon thread and
every call is submitted to it. Servers come from ``mcp_servers.json`` (the same shape Claude Desktop uses); the
built-in ``secagents`` server (our own, over stdio) is always available. Tool names are prefixed ``server__tool`` so
two servers cannot collide. A server that fails to start is reported and skipped; it never breaks the app.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import settings

CONNECT_TIMEOUT = 40
CALL_TIMEOUT = 60
SEP = "__"
BUILTIN = {"secagents": {"command": sys.executable, "args": ["-m", "secagents.mcp_server"]}}


def load_config(path: str | Path | None) -> dict[str, dict[str, Any]]:
    """Servers from a Claude-Desktop-style JSON file ({"mcpServers": {name: {command, args, env}}}); built-in first."""
    servers = dict(BUILTIN)
    if path and Path(path).is_file():
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
            for name, spec in (doc.get("mcpServers") or {}).items():
                if isinstance(spec, dict) and spec.get("command") and not str(name).startswith("_"):  # "_name" = disabled
                    servers[str(name)] = spec
        except (OSError, ValueError):
            pass
    return servers


class McpHub:
    def __init__(self, servers: dict[str, dict[str, Any]] | None = None):
        self.servers = servers if servers is not None else load_config(None if settings.public else settings.mcp_config)  # public: built-in only
        self.sessions: dict[str, ClientSession] = {}
        self.tools: dict[str, dict[str, Any]] = {}  # prefixed name -> {"server", "name", "description", "parameters"}
        self.errors: dict[str, str] = {}
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True, name="mcp-hub")
        self._thread.start()

    def _run(self, coro, timeout: float):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    # ---- connecting ------------------------------------------------------------------------------------------
    def connect(self) -> dict[str, str]:
        """Start every configured server. Returns {server: error} for the ones that failed."""
        ready = asyncio.run_coroutine_threadsafe(self._start(), self._loop)
        ready.result(CONNECT_TIMEOUT * max(1, len(self.servers)) + 5)
        return dict(self.errors)

    async def _start(self) -> None:
        # anyio scopes must be entered and exited by the same task, so one long-lived task owns every connection.
        self._ready, self._closing = asyncio.Event(), asyncio.Event()
        self._owner = asyncio.create_task(self._own())
        await self._ready.wait()

    async def _own(self) -> None:
        async with AsyncExitStack() as stack:
            for name, spec in self.servers.items():
                try:
                    await asyncio.wait_for(self._connect_one(stack, name, spec), CONNECT_TIMEOUT)
                except Exception as exc:  # noqa: BLE001 - one bad server must not take the others down
                    self.errors[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
            self._ready.set()
            await self._closing.wait()

    async def _connect_one(self, stack: AsyncExitStack, name: str, spec: dict[str, Any]) -> None:
        params = StdioServerParameters(command=spec["command"], args=list(spec.get("args", [])), env=spec.get("env"))
        read, write = await stack.enter_async_context(stdio_client(params))
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        self.sessions[name] = session
        for t in (await session.list_tools()).tools:
            self.tools[f"{name}{SEP}{t.name}"] = {"server": name, "name": t.name, "description": t.description or "",
                                                 "parameters": t.inputSchema or {"type": "object", "properties": {}}}

    # ---- using tools -----------------------------------------------------------------------------------------
    def schemas(self) -> list[dict[str, Any]]:
        return [{"name": k, "description": f"[{v['server']}] {v['description']}", "parameters": v["parameters"]} for k, v in self.tools.items()]

    def call(self, prefixed: str, arguments: dict[str, Any]) -> str:
        info = self.tools.get(prefixed)
        if info is None:
            return f"Error: no MCP tool named {prefixed!r}."
        try:
            res = self._run(self.sessions[info["server"]].call_tool(info["name"], arguments), CALL_TIMEOUT)
        except Exception as exc:  # noqa: BLE001
            return f"Error: MCP call failed ({type(exc).__name__}: {str(exc)[:300]})."
        text = "\n".join(getattr(b, "text", "") for b in res.content if getattr(b, "text", None))
        return f"Error: {text}" if res.isError else text

    def runner(self):
        """A tool_runner for Agent: our tools go through the built-in MCP server, so every call crosses the MCP protocol."""
        from .tools import call_tool

        def run(name: str, args: dict[str, Any], ctx) -> str:
            key = f"secagents{SEP}{name}"
            return self.call(key, args) if key in self.tools else call_tool(name, args, ctx)

        return run

    def close(self) -> None:
        closing = getattr(self, "_closing", None)
        if closing is not None:
            self._loop.call_soon_threadsafe(closing.set)
            try:
                self._run(asyncio.wait_for(self._owner, 10), 12)
            except Exception:  # noqa: BLE001
                pass
        self._loop.call_soon_threadsafe(self._loop.stop)
