"""The Streamlit "Agent" tab: chat with the tool-using agent, approve actions, manage memory.

Kept out of the main app file so the app's stale-module guards reload it with the rest of the package.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st

from . import history, session
from .agent import Agent
from .config import settings
from .llm import get_router
from .mcp_client import McpHub
from .memory import Memory
from .tools import TOOLS, ToolContext

SUGGESTIONS = [
    "Summarise the latest assessment and tell me what to fix first.",
    "What is CVE-2021-44228 and how do we mitigate it?",
    "Which MITRE ATT&CK techniques cover SSH brute force?",
    "Run a full assessment of the demo environment.",
]
RESULT_PREVIEW_CHARS = 1500


@st.cache_resource(show_spinner="Starting the MCP server...")
def shared_hub() -> McpHub:
    """One MCP connection for the whole process: its tools are stateless and read-only, so visitors can share it."""
    hub = McpHub()
    hub.connect()
    return hub


def _memory() -> Memory:
    if "agent_memory" not in st.session_state:
        st.session_state["agent_memory"] = Memory(settings.memory_db)
    return st.session_state["agent_memory"]


def _switch_thread(pick_key: str) -> None:
    st.session_state["agent_thread"] = st.session_state[pick_key]


def _workspace(nonce: int) -> str:
    if settings.public:
        code = st.session_state.get(f"agent-ws-{nonce}", "")
        return session.workspace_id(code) if len(code.strip()) >= 8 else session.workspace()
    return "default"


def _groups(messages: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    """Chat bubbles: each user message alone, then one assistant bubble holding its tool calls, results and answer."""
    groups: list[tuple[str, list[dict[str, Any]]]] = []
    for m in messages:
        if m["role"] == "user":
            groups.append(("user", [m]))
        elif groups and groups[-1][0] == "assistant":
            groups[-1][1].append(m)
        else:
            groups.append(("assistant", [m]))
    return groups


def _render_tool_call(call: dict[str, Any]) -> None:
    args = json.dumps(call["arguments"], default=str)
    st.caption(f"🔧 **{call['name']}**({args[:200]}{'…' if len(args) > 200 else ''})")


def _render_tool_result(name: str, text: str, denied: bool = False) -> None:
    with st.expander(("⛔ denied · " if denied else "↳ result · ") + name, expanded=False):
        st.code(text[:RESULT_PREVIEW_CHARS] + ("…" if len(text) > RESULT_PREVIEW_CHARS else ""), language="json" if text[:1] in "[{" else None)


def _render_history(messages: list[dict[str, Any]]) -> None:
    for role, group in _groups(messages):
        with st.chat_message(role):
            for m in group:
                if m["role"] == "tool":
                    _render_tool_result(m.get("name", "tool"), m.get("content", ""), bool(m.get("denied")))
                    continue
                if m["role"] == "assistant":
                    if m.get("content"):
                        (st.warning if m.get("stopped") else st.markdown)(m["content"])
                    for c in m.get("tool_calls", []):
                        _render_tool_call(c)
                    if m.get("model") and not m.get("tool_calls"):
                        st.caption(f"{m.get('provider', '')} · {m['model']}")
                else:
                    st.markdown(m["content"])


def _run_turn(agent: Agent, events, tid: str, ws: str, memory: Memory) -> None:
    """Show a turn as it happens, save the conversation, then rerun so the stored history is what is drawn."""
    with st.chat_message("assistant"):
        with st.status("Thinking...", expanded=True) as status:
            for ev in events:
                if ev["type"] == "tool_call":
                    status.update(label=f"Calling {ev['name']}...")
                    _render_tool_call(ev)
                elif ev["type"] == "tool_result":
                    _render_tool_result(ev["name"], ev["text"], ev["denied"])
                elif ev["type"] == "approval":
                    status.update(label="Waiting for your approval", state="running")
            status.update(label="Done", state="complete", expanded=False)
    memory.save_messages(tid, ws, agent.messages(tid))
    _adopt_assessment(agent.ctx)
    st.rerun()


def _adopt_assessment(ctx: ToolContext) -> None:
    """An assessment the agent ran becomes the dashboard's current result (and is saved to Scan history)."""
    state = ctx.state
    if state and state is not st.session_state.get("result"):
        state.setdefault("trace", [])
        state.setdefault("llm_calls", list(get_router().calls))
        scan_id = history.save(state, "Agent-run assessment", "Agent")
        st.session_state["result"] = state
        st.session_state["scan"] = {k: v for k, v in history.load(scan_id).items() if k != "result"}


def _memory_panel(memory: Memory, ws: str, nonce: int) -> None:
    with st.expander("🧠 Memory", expanded=False):
        st.caption("Facts the agent remembers across conversations (it asks before saving one). Secrets are never stored.")
        facts = memory.facts(ws)
        for f in facts:
            cols = st.columns([8, 1])
            cols[0].markdown(f"- {f['text']}")
            if cols[1].button("🗑", key=f"forget-{f['id']}-{nonce}", help="Forget this"):
                memory.forget(f["id"], ws)
                st.rerun()
        if not facts:
            st.caption("Nothing remembered yet.")
        new = st.text_input("Add a fact", key=f"fact-{nonce}", placeholder="e.g. Our production web servers run nginx on Ubuntu 22.04")
        if st.button("Remember", key=f"remember-{nonce}") and new.strip():
            st.toast("Remembered." if memory.remember(new, ws) else "Not saved: empty, secret-like, or the memory is full.")
            st.rerun()
        st.download_button("⬇ Export memory + chats (JSON)", memory.export_json(ws), "secagents_memory.json", on_click="ignore",
                           help="The server's disk is temporary on free hosting. Export now, import later.")
        up = st.file_uploader("Import an export", type=["json"], key=f"import-{nonce}")
        if up is not None and st.button("Import", key=f"import-go-{nonce}"):
            try:
                st.success("Imported {facts} fact(s) and {threads} chat(s).".format(**memory.import_json(up.getvalue().decode("utf-8"), ws)))
            except ValueError as exc:
                st.error(str(exc))


def render(result: dict[str, Any], nonce: int = 0) -> None:
    router = get_router()
    memory, ws = _memory(), _workspace(nonce)
    ctx = ToolContext(state=result or {}, memory=memory, workspace=ws)
    ss = st.session_state

    st.caption("Chat with an agent that decides which tools to use: the knowledge base, your assessment results, log analysis. "
               "Actions that change something ask for your approval first.")
    if settings.public:
        st.text_input("Workspace code (optional)", key=f"agent-ws-{nonce}", type="password", placeholder="8+ characters",
                      help="Use the same code next time to find your saved chats and memory again. It is a shared secret, "
                           "not a login: choose something others cannot guess.")
        if router.budget is not None:
            st.caption(f"Shared-key allowance this session: {router.budget.session_used:,} / {router.budget.session_cap:,} tokens. "
                       "A key pasted in the sidebar is used instead and does not count.")

    with st.expander("⚙ Agent settings", expanded=False):
        use_mcp = st.checkbox("Route tool calls through MCP", key=f"agent-mcp-{nonce}",
                              help="Knowledge and log tools are called through the built-in MCP server (a separate process "
                                   "speaking the Model Context Protocol) instead of directly. Same results, real protocol.")
        auto = False if settings.public else st.checkbox("Approve actions automatically", key=f"agent-auto-{nonce}",
                                                         help="Skip the approval step for run_assessment, writing log lines and memory.")
        st.caption("Tools: " + ", ".join(f"`{n}`" + (" 🔒" if t.needs_approval else "") for n, t in TOOLS.items()) + "  (🔒 asks first)")

    hub = shared_hub() if use_mcp else None
    if hub is not None and hub.errors:
        st.warning("MCP server problem, using direct tool calls: " + "; ".join(f"{k}: {v}" for k, v in hub.errors.items()))
        hub = None
    signature = (bool(hub), auto, id(router))
    if ss.get("agent_sig") != signature or "agent_obj" not in ss:
        def allow() -> str | None:
            return None if router.available_providers() else (router.budget.blocked() if router.budget else None)

        ss["agent_obj"] = Agent(ctx, router, max_steps=settings.agent_max_steps, max_tokens=settings.agent_turn_tokens,
                                auto_approve=auto, allow=allow, tool_runner=hub.runner() if hub else None)
        ss["agent_sig"] = signature
    agent: Agent = ss["agent_obj"]
    agent.ctx.state, agent.ctx.workspace, agent.ctx.memory = result or {}, ws, memory  # the dashboard result may have changed
    agent.router = router

    threads = memory.threads(ws)
    ids = [None, *[t["id"] for t in threads]]
    titles = {t["id"]: t["title"] for t in threads}
    tid = ss.get("agent_thread") if ss.get("agent_thread") in ids else None
    pick_key = f"agent-thread-{nonce}"
    ss[pick_key] = tid  # the widget follows the current chat (a new chat is created while the widget still says "New chat")
    st.selectbox("Conversation", ids, key=pick_key, on_change=_switch_thread, args=(pick_key,),
                 format_func=lambda i: "➕ New chat" if i is None else f"💬 {titles[i]}")
    if tid and st.button("Delete this chat", key=f"agent-del-{nonce}"):
        memory.delete_thread(tid, ws)
        ss["agent_thread"] = None
        st.rerun()

    _memory_panel(memory, ws, nonce)

    messages = (agent.messages(tid) if tid else []) or (memory.messages(tid, ws) if tid else [])
    _render_history(messages)

    can_chat = bool(router.available_providers())
    if not can_chat:
        reason = router.budget.blocked() if router.budget else None
        st.warning(reason or "The agent needs a language model with tool calling. Add an API key in the sidebar (or .env).")

    # a pending approval survives reruns: the graph is paused until a button is pressed
    pending = agent.pending(tid) if tid else None
    if pending:
        with st.chat_message("assistant"):
            st.warning(f"**Approval needed:** the agent wants to run **{pending['tool']}**", icon="🔒")
            st.caption(pending["description"])
            st.code(json.dumps(pending["arguments"], indent=2, default=str), language="json")
            cols = st.columns(2)
            approve = cols[0].button("✅ Approve", key=f"approve-{nonce}", type="primary", use_container_width=True)
            deny = cols[1].button("⛔ Deny", key=f"deny-{nonce}", use_container_width=True)
        if approve or deny:
            _run_turn(agent, agent.resume(tid, approve), tid, ws, memory)
        return

    if not messages:
        cols = st.columns(2)
        for i, text in enumerate(SUGGESTIONS):
            if cols[i % 2].button(text, key=f"suggest-{i}-{nonce}", use_container_width=True, disabled=not can_chat):
                ss["agent_queue"] = text
                st.rerun()
    prompt = st.chat_input("Ask the agent...", key=f"agent-input-{nonce}", disabled=not can_chat) or ss.pop("agent_queue", None)
    if prompt:
        if tid is None:
            tid = ss["agent_thread"] = memory.create_thread(ws)
        with st.chat_message("user"):
            st.markdown(prompt)
        _run_turn(agent, agent.send(tid, prompt, history=memory.messages(tid, ws)), tid, ws, memory)
