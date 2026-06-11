"""
Interactive TUI for OpenHack.

Full-screen prompt_toolkit Application with two modes:

- LANDING: ground-symbol logo + "OpenHack" wordmark + centered input. Tip and
  account footer below. Type a slash command or a path/URL to scan.
- SCANNING: pinned status bar (target, elapsed, cost) + VSplit pane layout
  (agents on the left, findings on the right) + input bar at the bottom.

Scan execution still uses CoordinatorAgent/Session under the hood; trace
events from the session are translated into agent/finding pane state and the
layout re-renders on every update.
"""

import asyncio
import json
import logging
import os
import signal
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from prompt_toolkit import HTML
from prompt_toolkit.data_structures import Point
from prompt_toolkit.application import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.filters import Condition
from prompt_toolkit.formatted_text import to_formatted_text
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import (
    ConditionalContainer,
    Float,
    FloatContainer,
    HSplit,
    VSplit,
    Window,
    WindowAlign,
)
from prompt_toolkit.layout.scrollable_pane import ScrollablePane
from prompt_toolkit.widgets import Frame
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.formatted_text import split_lines
from prompt_toolkit.layout.dimension import Dimension as D
from prompt_toolkit.layout.menus import CompletionsMenu
from prompt_toolkit.layout.processors import BeforeInput
from prompt_toolkit.mouse_events import MouseEvent, MouseEventType
from prompt_toolkit.styles import Style

from openhack.agents.coordinator import CoordinatorAgent
from openhack.agents.llm import LLMClient, Message, LLMResponse
from openhack.agents.session import Session, SessionStatus, Finding, TraceEntry
from openhack.config import (
    settings,
    save_user_config,
    load_user_config,
    resolve_provider,
    reload_settings,
    _PROVIDER_KEY_FIELDS,
)
from openhack.setup import run_setup_command
from openhack.tools.registry import ToolRegistry
from openhack.prompts.project_context import build_project_context
from openhack.updates import Announcement, UpdateInfo, fetch_updates, save_dismissed


# ── Brand ─────────────────────────────────────────────────────────

# OpenHack ground-symbol logo (chunky pixel blocks). All lines are padded to
# 26 cols so the line's geometric midpoint matches the blocks' visual midpoint
# (col 13.5) — keeps the "OpenHack" wordmark aligned with the vertical bar.
_LOGO_WIDTH = 26
_LOGO_LINES = [line.ljust(_LOGO_WIDTH) for line in [
    "            ██",
    "            ██",
    "            ██",
    "            ██",
    "            ██",
    "   ████████████████████",
    "",
    "     ████████████████",
    "",
    "       ████████████",
]]



PROVIDER_DEFAULTS = {"openhack": "kimi-k2.5"}

CHAT_SYSTEM_PROMPT = (
    "You are OpenHack, a security-focused AI assistant embedded in the OpenHack CLI. "
    "You help users understand vulnerability scan results, explain security concepts, "
    "and advise on remediation. Be concise and direct. "
    "If the user asks you to scan, tell them to use /full-scan or /scan <path>."
)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── Severity coloring ─────────────────────────────────────────────

def _sev_style(severity: str) -> str:
    s = (severity or "").lower()
    if s == "critical":
        return "class:sev.critical"
    if s == "high":
        return "class:sev.high"
    if s == "medium":
        return "class:sev.medium"
    if s == "low":
        return "class:sev.low"
    return "class:sev.info"


def _sev_label(severity: str) -> str:
    s = (severity or "").lower()
    return {
        "critical": "CRIT",
        "high": "HIGH",
        "medium": "MED ",
        "low": "LOW ",
    }.get(s, "INFO")


# ── Slash command registry ────────────────────────────────────────

_SLASH_COMMANDS = [
    ("/copy", "Copy the selected finding for Codex / Claude Code / OpenCode"),
    ("/logout", "Sign out (clears the saved token — requires confirmation)"),
    ("/verify", "Run sandbox/browser verification on loaded findings (`/verify sandbox` or `/verify browser`)"),
    ("/mouse", "Toggle mouse capture — off lets you drag-to-select text natively"),
    ("/discord", "Open the OpenHack Discord in your browser"),
    ("/scan", "Full scan on a specific directory (defaults to current)"),
    ("/pause", "Pause the running scan (Ctrl+C also pauses)"),
    ("/resume", "Resume a paused scan"),
    ("/cancel", "Cancel the running scan permanently"),
    ("/sessions", "Browse and re-load past scan results"),
    ("/findings", "Re-display findings from last scan"),
    ("/sidebar", "Show/hide the Findings list sidebar (Ctrl+B)"),
    ("/login", "Re-login with OpenHack account (browser flow)"),
    ("/setup", "Interactive setup wizard"),
    ("/config", "Show or set configuration"),
    ("/provider", "Switch provider"),
    ("/model", "Override model ID"),
    ("/cost", "Show cost breakdown from last scan"),
    ("/clear", "Clear scan history (returns to landing)"),
    ("/help", "Show available commands"),
    ("/test", "Run a simulated scan (no LLM)"),
    ("/quit", "Exit"),
]

_CONFIG_KEYS = [
    ("provider", "LLM provider"),
    ("model", "Model ID override"),
    ("openhack_api_key", "OpenHack API key"),
    ("openhack_model_id", "OpenHack model ID"),
]

_CANCEL_PHRASES = {
    "cancel", "cancel scan", "cancel the scan",
    "stop", "stop scan", "stop the scan",
    "abort", "abort scan",
}


class OpenHackCompleter(Completer):
    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        words = text.split()

        if not text or (len(words) == 1 and not text.endswith(" ")):
            prefix = text.lstrip()
            if not prefix or prefix.startswith("/"):
                for cmd, desc in _SLASH_COMMANDS:
                    if cmd.startswith(prefix):
                        yield Completion(cmd, start_position=-len(prefix), display_meta=desc)
            return

        # Whitespace-only input (no actual words) — nothing to complete against.
        if not words:
            return

        cmd = words[0].lower()

        if cmd == "/config":
            if len(words) == 1 and text.endswith(" "):
                for key, desc in _CONFIG_KEYS:
                    yield Completion(key, display_meta=desc)
            elif len(words) == 2 and not text.endswith(" "):
                partial = words[1]
                for key, desc in _CONFIG_KEYS:
                    if key.startswith(partial):
                        yield Completion(key, start_position=-len(partial), display_meta=desc)
        elif cmd == "/scan":
            partial = words[-1] if len(words) > 1 and not text.endswith(" ") else ""
            base = partial or "."
            try:
                base_path = Path(base)
                if base_path.is_dir():
                    parent = base_path
                    prefix = ""
                else:
                    parent = base_path.parent if base_path.parent.is_dir() else Path(".")
                    prefix = base_path.name
                for child in sorted(parent.iterdir()):
                    if child.name.startswith(".") or not child.is_dir():
                        continue
                    if prefix and not child.name.startswith(prefix):
                        continue
                    yield Completion(str(child) + "/", start_position=-len(partial))
            except OSError:
                pass


# ── Agent/finding state derived from trace entries ────────────────

# Status icons:
#   ◌  pending (not yet started)
#   ●  running (current step is this agent)
#   ▸  working (mid-task)
#   ✓  complete
#   ✗  failed / cancelled

_STATUS_PENDING = ("◌", "class:status.pending")
_STATUS_RUNNING = ("●", "class:status.running")
_STATUS_WORKING = ("▸", "class:status.working")
_STATUS_DONE = ("✓", "class:status.done")
_STATUS_FAIL = ("✗", "class:status.fail")


class _AgentRow:
    __slots__ = ("name", "status", "detail")

    def __init__(self, name: str, status: tuple[str, str], detail: str = ""):
        self.name = name
        self.status = status
        self.detail = detail


class ScanState:
    """Derived UI state for an in-progress scan."""

    def __init__(self, target: str):
        self.target = target
        self.start_time = time.time()
        self.end_time: Optional[float] = None  # set when the scan terminates
        self.cost: float = 0.0
        self.current_step: Optional[str] = None
        self.agents: dict[str, _AgentRow] = {}
        self.findings: list[Finding] = []
        self.agent_order: list[str] = []
        self.last_message: str = ""
        # Each rendered trace line carries its source agent so the Trace tab
        # can filter to "show only this agent's events".
        self.trace_lines: list[tuple[str, list[tuple[str, str]]]] = []
        # Unique agents in order of first appearance — drives the trace sidebar.
        self.trace_agents: list[str] = []

    def _append_trace(self, agent: str, fragments: list[tuple[str, str]]) -> None:
        """Internal: record a rendered trace line with its agent attribution."""
        self.trace_lines.append((agent, fragments))
        if agent and agent not in self.trace_agents:
            self.trace_agents.append(agent)

    def finish(self) -> None:
        """Freeze the elapsed clock — call when the scan completes/cancels/fails."""
        if self.end_time is None:
            self.end_time = time.time()

    def elapsed_str(self) -> str:
        endpoint = self.end_time if self.end_time is not None else time.time()
        seconds = int(endpoint - self.start_time)
        m, s = divmod(seconds, 60)
        return f"{m}:{s:02d}" if m else f"0:{s:02d}"

    def upsert_agent(self, name: str, status: tuple[str, str], detail: str = "") -> None:
        row = self.agents.get(name)
        if row is None:
            self.agents[name] = _AgentRow(name, status, detail)
            self.agent_order.append(name)
        else:
            row.status = status
            if detail:
                row.detail = detail

    def update_from_trace(self, entry: TraceEntry) -> None:
        agent = entry.agent
        etype = entry.event_type

        ts = self._ts(entry.timestamp)

        if etype == "step_start":
            self.current_step = str(entry.content)
            self.last_message = f"step start · {entry.content}"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.step", f"  ── {entry.content} ──"),
            ])
            return

        if etype == "step_complete":
            data = entry.content if isinstance(entry.content, dict) else {}
            self.cost += float(data.get("cost", 0) or 0)
            self.last_message = f"step complete · {data.get('step', '')}"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.dim", f"  {data.get('step', 'step')} complete · "
                 f"${float(data.get('cost', 0)):.4f} · {data.get('tokens', 0):,} tok"),
            ])
            return

        if etype == "swarm_start":
            data = entry.content if isinstance(entry.content, dict) else {}
            groups = data.get("groups", [])
            base = agent.replace("_swarm", "")
            for g in groups:
                self.upsert_agent(f"{base}:{g}", _STATUS_PENDING, "queued")
            self.last_message = f"{agent} · spawned {len(groups)} sub-agents"
            count = data.get("group_count") or data.get("findings_count") or len(groups)
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent}"),
                ("class:trace.dim", f" spawned {count} sub-agents"),
            ])
            return

        if etype == "swarm_complete":
            data = entry.content if isinstance(entry.content, dict) else {}
            base = agent.replace("_swarm", "")
            for name in list(self.agents):
                if name.startswith(f"{base}:") and self.agents[name].status[0] != "✓":
                    self.upsert_agent(name, _STATUS_DONE, "complete")
            cost = data.get("total_cost", 0)
            self.cost += float(cost or 0)
            n = data.get("total_findings") or data.get("total_confirmed") or 0
            self.last_message = f"{agent} · complete"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent}"),
                ("class:trace.dim", f" complete · {n} findings · ${float(cost):.4f}"),
            ])
            return

        if etype == "tool_call":
            tool = entry.tool_name or "tool"
            args = entry.tool_input or {}
            detail = _short_tool_label(tool, args)
            self.upsert_agent(agent, _STATUS_WORKING, detail)
            self.last_message = f"{agent} · {detail}"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent:>24}"),
                ("class:trace.arrow", "  →  "),
                ("class:trace.tool", tool),
                ("class:trace.dim", f"  {detail}" if detail and detail != tool else ""),
            ])
            return

        if etype == "tool_result":
            row = self.agents.get(agent)
            if row and row.status[0] == "▸":
                row.status = _STATUS_RUNNING
            return

        if etype == "thinking":
            self.upsert_agent(agent, _STATUS_RUNNING, "thinking…")
            content_str = str(entry.content or "").strip()
            if content_str:
                # Truncate hard at the source level so a 5-page chain-of-thought
                # doesn't blow up the pane. Render the (possibly truncated)
                # content as markdown — headers, bold, bullets, inline code.
                if len(content_str) > 2000:
                    content_str = content_str[:1997] + "…"
                line: list[tuple[str, str]] = [
                    ("class:trace.time", ts),
                    ("class:trace.agent", f"  {agent:>24}"),
                    ("class:trace.arrow", "  ⋯  "),
                ]
                line.extend(_render_md_prose(content_str))
                self._append_trace(agent, line)
            return

        if etype == "finding_added":
            data = entry.content if isinstance(entry.content, dict) else {}
            sev = (data.get("severity") or "info").lower()
            title = data.get("title", "")
            file_path = data.get("file_path", "")
            self.last_message = f"finding · {title}"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("", "  "),
                (_sev_style(sev), f"★ {_sev_label(sev)}"),
                ("", "  "),
                ("class:finding.title", title),
                ("class:finding.path", f"  {file_path}" if file_path else ""),
            ])
            return

        if etype == "queued":
            data = entry.content if isinstance(entry.content, dict) else {}
            title = data.get("title", "")
            self.upsert_agent(agent, _STATUS_PENDING, "queued")
            self.last_message = f"{agent} · queued"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent:>24}"),
                ("class:trace.dim", f"  queued · {title}" if title else "  queued"),
            ])
            return

        if etype == "sandbox_starting":
            msg = str(entry.content or "starting sandbox…")
            self.last_message = f"{agent} · starting sandbox"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent}"),
                ("class:trace.dim", f"  {msg}"),
            ])
            return

        if etype == "sandbox_ready":
            data = entry.content if isinstance(entry.content, dict) else {}
            url = data.get("base_url", "")
            self.last_message = f"sandbox ready · {url}"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent}"),
                ("class:trace.dim", f"  sandbox ready · {url}"),
            ])
            return

        if etype == "error":
            msg = str(entry.content or "error")
            self.upsert_agent(agent, _STATUS_FAIL, msg[:60])
            self.last_message = f"{agent} · error"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent:>24}"),
                ("class:trace.arrow", "  ✗  "),
                ("class:status.fail", msg[:200]),
            ])
            return

        if etype == "skipped":
            msg = str(entry.content or "skipped")
            self.upsert_agent(agent, _STATUS_FAIL, "skipped")
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent:>24}"),
                ("class:trace.dim", f"  skipped · {msg[:120]}"),
            ])
            return

        if etype == "swarm_aborted":
            msg = str(entry.content or "aborted")
            self.last_message = f"{agent} · aborted"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent}"),
                ("class:trace.arrow", "  ✗  "),
                ("class:status.fail", msg[:200]),
            ])
            return

        if etype == "sandbox_teardown":
            msg = str(entry.content or "stopping sandbox")
            self.last_message = f"{agent} · teardown"
            self._append_trace(agent, [
                ("class:trace.time", ts),
                ("class:trace.agent", f"  {agent}"),
                ("class:trace.dim", f"  {msg}"),
            ])
            return

    def _ts(self, t: float) -> str:
        rel = max(0, int(t - self.start_time))
        m, s = divmod(rel, 60)
        return f"[{m}:{s:02d}]"


# ── Syntax highlighting ───────────────────────────────────────────

def _highlight_code(code: str, file_path: str = "") -> list[tuple[str, str]]:
    """Tokenize *code* with Pygments and return prompt_toolkit fragments."""
    if not code:
        return []
    try:
        from pygments.lexers import get_lexer_for_filename, guess_lexer
        from pygments.token import Token
        from pygments.util import ClassNotFound
    except ImportError:
        return [("class:code", code)]

    lexer = None
    if file_path:
        try:
            lexer = get_lexer_for_filename(file_path)
        except ClassNotFound:
            lexer = None
    if lexer is None:
        try:
            lexer = guess_lexer(code)
        except Exception:
            return [("class:code", code)]

    def style_for(token) -> str:
        if token in Token.Comment:
            return "class:syntax.comment"
        if token in Token.String:
            return "class:syntax.string"
        if token in Token.Keyword:
            return "class:syntax.keyword"
        if token in Token.Name.Builtin:
            return "class:syntax.builtin"
        if token in Token.Name.Function:
            return "class:syntax.function"
        if token in Token.Name.Class:
            return "class:syntax.class"
        if token in Token.Name.Decorator:
            return "class:syntax.decorator"
        if token in Token.Number:
            return "class:syntax.number"
        if token in Token.Operator:
            return "class:syntax.operator"
        return "class:code"

    return [(style_for(tok), text) for tok, text in lexer.get_tokens(code)]


class _ScrollableFormattedTextControl(FormattedTextControl):
    """A FormattedTextControl that *always* catches scroll-wheel events and
    forwards them to a callback. Used by the details pane so mouse wheel
    scrolling fires reliably regardless of which fragment is hovered.
    """

    def __init__(self, *args, on_scroll=None, on_event=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._on_scroll = on_scroll
        self._on_event = on_event  # called for *any* event — used for debug

    def mouse_handler(self, mouse_event: MouseEvent):  # type: ignore[override]
        if self._on_event is not None:
            try:
                self._on_event(mouse_event)
            except Exception:
                pass
        if self._on_scroll is not None:
            if mouse_event.event_type == MouseEventType.SCROLL_DOWN:
                self._on_scroll(+3)
                return None
            if mouse_event.event_type == MouseEventType.SCROLL_UP:
                self._on_scroll(-3)
                return None
        return super().mouse_handler(mouse_event)


def _section_header(label: str) -> list[tuple[str, str]]:
    """An open-bottom 'box top' that visually demarcates a section."""
    width = 78
    prefix = f"┌─ {label} "
    pad = max(0, width - len(prefix) - 1)
    return [
        ("class:section.box", prefix),
        ("class:section.box", "─" * pad),
        ("class:section.box", "┐\n"),
    ]


def _highlight_code_by_lang(code: str, lang: str, fallback_file: str = "") -> list[tuple[str, str]]:
    """Tokenize code with Pygments using a language name; fall back to file-based detection."""
    try:
        from pygments.lexers import get_lexer_by_name
        from pygments.token import Token
        from pygments.util import ClassNotFound
    except ImportError:
        return [("class:code", code)]
    try:
        lexer = get_lexer_by_name(lang)
    except ClassNotFound:
        return _highlight_code(code, fallback_file)

    def style_for(tok):
        if tok in Token.Comment: return "class:syntax.comment"
        if tok in Token.String: return "class:syntax.string"
        if tok in Token.Keyword: return "class:syntax.keyword"
        if tok in Token.Name.Builtin: return "class:syntax.builtin"
        if tok in Token.Name.Function: return "class:syntax.function"
        if tok in Token.Name.Class: return "class:syntax.class"
        if tok in Token.Name.Decorator: return "class:syntax.decorator"
        if tok in Token.Number: return "class:syntax.number"
        if tok in Token.Operator: return "class:syntax.operator"
        return "class:code"

    return [(style_for(tok), t) for tok, t in lexer.get_tokens(code)]


# Inline markdown patterns: **bold**, *italic*, _italic_, `code`, [link](url)
_MD_INLINE_RE = __import__("re").compile(
    r"(\*\*[^*\n]+\*\*)"
    r"|(`[^`\n]+`)"
    r"|(\*(?!\s)[^*\n]+?\*)"
    r"|(_(?!\s)[^_\n]+?_)"
    r"|(\[[^\]\n]+\]\([^)\s]+\))"
)


def _render_md_inline(text: str) -> list[tuple[str, str]]:
    """Render inline markdown — bold/italic/code/links — into styled fragments."""
    import re as _re
    out: list[tuple[str, str]] = []
    pos = 0
    for m in _MD_INLINE_RE.finditer(text):
        if m.start() > pos:
            out.append(("", text[pos:m.start()]))
        token = m.group(0)
        if token.startswith("**") and token.endswith("**"):
            out.append(("class:md.bold", token[2:-2]))
        elif token.startswith("`") and token.endswith("`"):
            out.append(("class:md.code", token[1:-1]))
        elif token.startswith("*") and token.endswith("*"):
            out.append(("class:md.italic", token[1:-1]))
        elif token.startswith("_") and token.endswith("_"):
            out.append(("class:md.italic", token[1:-1]))
        elif token.startswith("["):
            link_m = _re.match(r"\[([^\]]+)\]\(([^)]+)\)", token)
            if link_m:
                out.append(("class:md.link", link_m.group(1)))
            else:
                out.append(("", token))
        pos = m.end()
    if pos < len(text):
        out.append(("", text[pos:]))
    return out


def _render_md_prose(text: str) -> list[tuple[str, str]]:
    """Render a chunk of markdown prose (no code fences) into styled fragments."""
    import re as _re
    out: list[tuple[str, str]] = []
    lines = text.split("\n")
    for idx, line in enumerate(lines):
        # ATX headers: #, ##, ###, ...
        m_h = _re.match(r"^(#{1,6})\s+(.*)$", line)
        if m_h:
            level = len(m_h.group(1))
            content = m_h.group(2).strip()
            style = (
                "class:md.h1" if level == 1
                else "class:md.h2" if level == 2
                else "class:md.h3"
            )
            out.append((style, content))
        # Horizontal rule
        elif _re.match(r"^[-*_]{3,}\s*$", line):
            out.append(("class:rule", "─" * 60))
        # Bullet list
        elif (m_b := _re.match(r"^(\s*)[-*+]\s+(.*)$", line)):
            out.append(("", m_b.group(1)))
            out.append(("class:md.bullet", "• "))
            out.extend(_render_md_inline(m_b.group(2)))
        # Numbered list
        elif (m_n := _re.match(r"^(\s*)(\d+)\.\s+(.*)$", line)):
            out.append(("", m_n.group(1)))
            out.append(("class:md.bullet", f"{m_n.group(2)}. "))
            out.extend(_render_md_inline(m_n.group(3)))
        # Blockquote
        elif (m_q := _re.match(r"^>\s?(.*)$", line)):
            out.append(("class:md.quote", "│ "))
            out.extend(_render_md_inline(m_q.group(1)))
        # Regular line
        else:
            out.extend(_render_md_inline(line))
        # Preserve newlines between lines
        if idx < len(lines) - 1:
            out.append(("", "\n"))
    return out


def _render_markdown_with_code(text: str, default_file: str = "") -> list[tuple[str, str]]:
    """Render markdown text. Code fences are syntax-highlighted; prose handles
    headers, bold, italic, inline code, lists, blockquotes, and horizontal rules."""
    import re as _re
    if not text:
        return []
    fragments: list[tuple[str, str]] = []
    pattern = _re.compile(r"```([a-zA-Z0-9_+\-]*)\n(.*?)```", _re.DOTALL)
    last_end = 0
    for m in pattern.finditer(text):
        prose = text[last_end:m.start()]
        if prose:
            fragments.extend(_render_md_prose(prose))
        lang = m.group(1).strip()
        code = m.group(2)
        if lang:
            fragments.extend(_highlight_code_by_lang(code, lang, default_file))
        else:
            fragments.extend(_highlight_code(code, default_file))
        last_end = m.end()
    if last_end < len(text):
        fragments.extend(_render_md_prose(text[last_end:]))
    return fragments


def _short_tool_label(tool: str, args: dict) -> str:
    path = args.get("path", "")
    pattern = args.get("pattern", "")
    # Paths are already relative to the project root (tools are rooted at
    # target_dir), so we surface them verbatim in the trace.
    if tool == "read_file" and path:
        return f"read {path}"
    if tool == "list_dir":
        return f"ls {path}" if path else "ls ."
    if tool == "glob" and pattern:
        scope = f" in {path}" if path else ""
        return f"glob {pattern}{scope}"
    if tool == "grep":
        p = pattern[:24] + "…" if len(pattern) > 24 else pattern
        scope = f" in {path}" if path else ""
        return f"grep /{p}/{scope}"
    if tool == "get_project_info":
        return "project info"
    if tool == "get_route_map":
        return "route map"
    if tool == "extract_functions" and path:
        return f"extract functions from {path}"
    if tool == "find_dangerous_patterns" and path:
        return f"find dangerous patterns in {path}"
    if tool == "trace_variable":
        var = args.get("variable_name", "")
        return f"trace {var} in {path}" if var else f"trace variable in {path}"
    if tool == "report_finding":
        cat = args.get("category", "")
        fp = args.get("file_path", "")
        if cat and fp:
            return f"report {cat} in {fp}"
        return f"report {cat}" if cat else "report finding"
    if tool == "validate_finding":
        return f"validate {args.get('status', '')}"
    if tool == "finish_hunt":
        return "finish hunt"
    if tool == "finish_validation":
        return "finish validation"
    if path:
        return f"{tool} {path}"
    return tool


# ── App ───────────────────────────────────────────────────────────

class OpenHackApp:
    """Full-screen prompt_toolkit application driving the OpenHack TUI."""

    def __init__(self) -> None:
        cfg = load_user_config()
        self.provider = resolve_provider(cfg.get("provider", settings.llm_provider))
        self.model = cfg.get("model") or PROVIDER_DEFAULTS.get(self.provider, settings.openhack_model_id)
        self.org_name: str = cfg.get("openhack_org_name") or ""
        self.user_email: str = ""  # populated lazily

        self.mode: str = "landing"  # "landing" | "scanning" | "viewing" | "sessions"
        self.previous_mode: Optional[str] = None  # set when entering "sessions" so Esc can return
        self.active_tab: str = "trace"  # "trace" | "findings" — sessions is its own mode now
        self.scan: Optional[ScanState] = None
        self.session: Optional[Session] = None
        self.scan_task: Optional[asyncio.Task] = None
        self.last_status_line: str = ""
        self.last_findings: list[Finding] = []  # findings from most recent scan
        self.last_session: Optional[Session] = None
        self.chat_history: list[Message] = []
        self._cancel_armed = False
        # Sessions tab state
        self.sessions_index: list[dict] = []
        self.sessions_selected: int = 0
        self.viewing_target: str = ""  # header label when in "viewing" mode
        # Findings tab selection (split pane: list left, details right)
        self.findings_selected: int = 0
        self.findings_list_hidden: bool = False  # toggle the left list via Ctrl+B / /sidebar
        # macOS terminals sometimes emit BOTH a mouse SCROLL event AND an
        # arrow-key event for a single trackpad gesture. Track when the last
        # mouse scroll happened so the arrow-key handler can stand down.
        self._last_scroll_at: float = 0.0
        # /logout uses a two-press confirmation; flag is reset on any other action.
        self._logout_armed: bool = False
        # /verify also uses two-press confirmation for the "enable" path so the
        # user reads the warning about prereqs. Stores which subject is armed.
        self._verify_arm_subject: Optional[str] = None  # 'sandbox' | 'browser' | 'all' | None
        # Mouse capture state. When True, prompt_toolkit consumes every mouse
        # event (so wheel-scroll + click-to-select work) but the terminal's
        # native drag-to-select-text is blocked. /mouse toggles this.
        self._mouse_enabled: bool = True
        # Centered modal-dialog state. None = no modal; otherwise a key
        # identifying which one to render (e.g. 'verify:sandbox', 'logout').
        self._modal_kind: Optional[str] = None
        self._modal_title: str = ""
        self._modal_body: str = ""
        self._modal_on_yes: Optional[Any] = None  # callable invoked on 'y' / Enter
        # Manual scroll offset for the details pane (in logical lines).
        # We bypass Window.vertical_scroll because prompt_toolkit's render
        # was clamping it back to 0 in our setup — instead we clip the
        # fragment list ourselves in details_text().
        self._details_scroll: int = 0
        # Findings sidebar width as a percentage of the Findings tab width.
        # The sibling Dimensions (built in _build_layout) hold weights that
        # we mutate to resize live.
        self._sidebar_pct: int = 35
        # Trace pane scroll. _trace_follow=True means stick to the bottom as
        # new events stream in; flipped off when the user scrolls up to read
        # history, flipped back on when they scroll back to bottom.
        self._trace_scroll: int = 0
        self._trace_follow: bool = True
        # Trace sidebar: 0 = "All", 1+ = scan.trace_agents[idx-1]
        self._trace_agent_idx: int = 0
        # Update/announcement state — populated asynchronously on startup.
        self._update_info: Optional[UpdateInfo] = None

        self.input_buffer = Buffer(
            multiline=False,
            completer=OpenHackCompleter(),
            complete_while_typing=True,
            accept_handler=self._on_buffer_accept,
        )

        self.kb = self._build_keybindings()
        self.layout = self._build_layout()
        self.style = self._build_style()

        self.app: Application = Application(
            layout=self.layout,
            key_bindings=self.kb,
            style=self.style,
            full_screen=True,
            # Filter-driven so /mouse can toggle native copy on demand.
            # When False, the terminal's built-in drag-to-select works.
            mouse_support=Condition(lambda: self._mouse_enabled),
            erase_when_done=True,
        )

    # ── Keybindings ───────────────────────────────────────────────

    def _build_keybindings(self) -> KeyBindings:
        kb = KeyBindings()

        @kb.add("c-c")
        def _ctrl_c(event):
            # Behavior:
            #   • Scan running, not paused → pause (state preserved)
            #   • Scan paused              → exit TUI (scan stays as 'running'
            #                                with dead PID → reclassified as
            #                                'aborted' next launch; resume with
            #                                'r' in /sessions)
            #   • No scan running          → exit TUI
            if self.mode == "scanning" and self.session is not None:
                if self.session.paused:
                    event.app.exit()
                else:
                    self.session.pause()
                    self.last_status_line = (
                        "scan paused · Ctrl+C again to exit · /resume to continue · /cancel to stop"
                    )
                    self._invalidate()
            else:
                event.app.exit()

        @kb.add("c-d")
        def _ctrl_d(event):
            if not self.input_buffer.text:
                event.app.exit()

        # Modal-dialog keys (eager so they take priority over text input
        # while a modal is open — typing 'y' goes to the dialog, not the
        # input box).
        modal_open = Condition(lambda: self._modal_kind is not None)

        @kb.add("y", filter=modal_open, eager=True)
        @kb.add("Y", filter=modal_open, eager=True)
        @kb.add("enter", filter=modal_open, eager=True)
        def _modal_yes(event):
            cb = self._modal_on_yes
            self._close_modal()
            if cb is not None:
                try:
                    cb()
                except Exception as exc:
                    self.last_status_line = f"action failed: {exc}"
            self._invalidate()

        @kb.add("n", filter=modal_open, eager=True)
        @kb.add("N", filter=modal_open, eager=True)
        @kb.add("escape", filter=modal_open, eager=True)
        def _modal_no(event):
            self._close_modal()
            self.last_status_line = "cancelled"
            self._invalidate()

        def _completion_open() -> bool:
            return self.input_buffer.complete_state is not None

        @kb.add("escape", eager=True, filter=Condition(_completion_open))
        def _escape_completion(event):
            event.current_buffer.cancel_completion()

        @kb.add("escape", eager=False, filter=~Condition(_completion_open))
        def _escape(event):
            pass

        # Option+Shift+Left/Right — select word (macOS sends Escape + ShiftLeft/Right)
        @kb.add("escape", "s-left")
        def _select_word_left(event):
            buf = event.current_buffer
            pos = buf.document.find_previous_word_beginning() or 0
            buf.cursor_position += pos
            buf.start_selection()
            # Already moved — selection is from new pos to old pos
            # Re-do: move back, start selection, then move
            buf.cursor_position -= pos
            buf.start_selection()
            buf.cursor_position += pos

        @kb.add("escape", "s-right")
        def _select_word_right(event):
            buf = event.current_buffer
            pos = buf.document.find_next_word_ending() or 0
            buf.start_selection()
            buf.cursor_position += pos

        # Tab navigation — only in scanning/viewing modes, and only when the
        # input is empty so they don't conflict with typing.
        def _in_tabs() -> bool:
            return self.mode in ("scanning", "viewing")

        def _in_sessions() -> bool:
            return self.mode == "sessions"

        def _input_empty() -> bool:
            return not self.input_buffer.text

        @kb.add("c-t")
        def _ctrl_t(event):
            if _in_tabs():
                self._cycle_tab(+1)

        @kb.add("right", filter=Condition(lambda: _in_tabs() and _input_empty()))
        def _right(event):
            self._cycle_tab(+1)

        @kb.add("left", filter=Condition(lambda: _in_tabs() and _input_empty()))
        def _left(event):
            self._cycle_tab(-1)

        for i, name in enumerate(("trace", "findings"), 1):
            @kb.add(str(i), filter=Condition(lambda: _in_tabs() and _input_empty()))
            def _digit(event, _name=name):
                self.active_tab = _name
                self._invalidate()

        # Findings list navigation (Findings tab + empty input).
        def _on_findings() -> bool:
            return _in_tabs() and self.active_tab == "findings" and _input_empty()

        def _reset_details_scroll() -> None:
            self._details_scroll = 0

        def _move_selection(delta: int) -> None:
            # If a mouse scroll fired in the last 400ms, this arrow key is
            # almost certainly the paired event from a Mac trackpad gesture —
            # not a deliberate keyboard press to switch findings. Stand down.
            if time.monotonic() - self._last_scroll_at < 0.4:
                return
            n = len(self._current_findings())
            if n == 0:
                return
            new_idx = max(0, min(n - 1, self.findings_selected + delta))
            if new_idx != self.findings_selected:
                self.findings_selected = new_idx
                _reset_details_scroll()
                self._invalidate()

        def _scroll_details(delta: int) -> None:
            self._details_scroll = max(0, self._details_scroll + delta)
            self._invalidate()

        # Up / Down switch findings (keyboard nav). [ and ] are aliases.
        @kb.add("up", filter=Condition(_on_findings))
        def _f_up(event):
            _move_selection(-1)

        @kb.add("down", filter=Condition(_on_findings))
        def _f_down(event):
            _move_selection(+1)

        @kb.add("[", filter=Condition(_on_findings))
        def _f_prev(event):
            _move_selection(-1)

        @kb.add("]", filter=Condition(_on_findings))
        def _f_next(event):
            _move_selection(+1)

        # 'y' = yank the finding as an AI-agent prompt to the system clipboard.
        @kb.add("y", filter=Condition(_on_findings))
        def _f_yank(event):
            self._cmd_copy_fix()

        # < / > resize the sidebar / details split by 5% steps.
        def _resize_sidebar(delta_pct: int) -> None:
            self._sidebar_pct = max(15, min(75, self._sidebar_pct + delta_pct))
            self._sidebar_dim.weight = self._sidebar_pct
            self._details_dim.weight = 100 - self._sidebar_pct
            self.last_status_line = f"sidebar {self._sidebar_pct}% · details {100 - self._sidebar_pct}%"
            self._invalidate()

        @kb.add("<", filter=Condition(_on_findings))
        def _f_shrink(event):
            _resize_sidebar(-5)

        @kb.add(">", filter=Condition(_on_findings))
        def _f_grow(event):
            _resize_sidebar(+5)

        # Trace tab scrolling — keyboard fallbacks for the mouse wheel.
        def _on_trace() -> bool:
            return _in_tabs() and self.active_tab == "trace" and _input_empty()

        # Up / Down → navigate the trace sidebar (agent picker).
        # PgUp / PgDn → scroll the trace content (was Up/Down before).
        def _move_trace_agent(delta: int) -> None:
            if self.scan is None:
                return
            # Total entries = "All" + however many agents the tree shows.
            # Compute by counting trace_agents (which is what the tree is built
            # from) — works for both the flat sidebar and the tree variant.
            n_entries = 1 + len(self.scan.trace_agents)
            if n_entries <= 1:
                return
            self._trace_agent_idx = max(0, min(n_entries - 1, self._trace_agent_idx + delta))
            self._trace_scroll = 0
            self._trace_follow = True
            self._invalidate()

        @kb.add("up", filter=Condition(_on_trace))
        def _t_up(event):
            _move_trace_agent(-1)

        @kb.add("down", filter=Condition(_on_trace))
        def _t_down(event):
            _move_trace_agent(+1)

        @kb.add("[", filter=Condition(_on_trace))
        def _t_prev_agent(event):
            _move_trace_agent(-1)

        @kb.add("]", filter=Condition(_on_trace))
        def _t_next_agent(event):
            _move_trace_agent(+1)

        # PgUp / PgDn scroll the trace content (was Up/Down before).
        @kb.add("pageup", filter=Condition(_on_trace))
        def _t_pgup(event):
            self._scroll_trace_by(-12)

        @kb.add("pagedown", filter=Condition(_on_trace))
        def _t_pgdn(event):
            self._scroll_trace_by(+12)

        @kb.add("home", filter=Condition(_on_trace))
        def _t_home(event):
            # Home: jump to "All" + reset trace to top.
            self._trace_agent_idx = 0
            self._trace_follow = False
            self._trace_scroll = 0
            self._invalidate()

        @kb.add("end", filter=Condition(_on_trace))
        def _t_end(event):
            # End: stay on current agent filter, jump trace to bottom.
            self._trace_follow = True
            self._invalidate()

        # Mouse wheel over the right pane is the primary scroll mechanism.
        # Keyboard fallbacks below work when the input box is empty so they
        # don't conflict with typing.
        @kb.add("pageup", filter=Condition(_on_findings))
        def _details_pgup(event):
            _scroll_details(-12)

        @kb.add("pagedown", filter=Condition(_on_findings))
        def _details_pgdn(event):
            _scroll_details(+12)

        @kb.add("home", filter=Condition(_on_findings))
        def _f_home(event):
            _reset_details_scroll()
            self._invalidate()

        @kb.add("end", filter=Condition(_on_findings))
        def _f_end(event):
            _scroll_details(+10_000)

        # Ctrl+B toggles the sidebar (left findings list) — global shortcut,
        # only meaningful on the Findings tab but harmless elsewhere.
        @kb.add("c-b", filter=Condition(lambda: _in_tabs() and _input_empty()))
        def _toggle_sidebar(event):
            self.findings_list_hidden = not self.findings_list_hidden
            self.last_status_line = "sidebar hidden" if self.findings_list_hidden else "sidebar shown"
            self._invalidate()

        # Sessions overlay keybindings.
        @kb.add("up", filter=Condition(lambda: _in_sessions() and _input_empty()))
        def _up(event):
            if self.sessions_index:
                self.sessions_selected = max(0, self.sessions_selected - 1)
                self._invalidate()

        @kb.add("down", filter=Condition(lambda: _in_sessions() and _input_empty()))
        def _down(event):
            if self.sessions_index:
                self.sessions_selected = min(len(self.sessions_index) - 1, self.sessions_selected + 1)
                self._invalidate()

        @kb.add("enter", filter=Condition(lambda: _in_sessions() and _input_empty()))
        def _enter(event):
            self._load_selected_session()

        @kb.add("r", filter=Condition(lambda: _in_sessions() and _input_empty()))
        def _resume(event):
            self._resume_selected_session()

        @kb.add("escape", eager=True, filter=Condition(lambda: _in_sessions() and _input_empty()))
        def _esc_sessions(event):
            self._close_sessions_overlay()

        return kb

    def _cycle_tab(self, direction: int) -> None:
        order = ["trace", "findings"]
        try:
            idx = order.index(self.active_tab)
        except ValueError:
            idx = 0
        self.active_tab = order[(idx + direction) % len(order)]
        self._invalidate()

    # ── Style ─────────────────────────────────────────────────────

    def _build_style(self) -> Style:
        return Style.from_dict({
            "logo": "bold ansiwhite",
            "wordmark": "bold ansiwhite",
            "tagline": "ansigray",
            "tip": "ansigray italic",
            "tip.label": "ansiyellow",
            "footer": "ansigray",
            "input.box": "",
            "input.prompt": "bold ansibrightgreen",
            "input.placeholder": "ansigray italic",
            "hint": "ansigray",
            "hint.key": "bold ansiwhite",
            "rule": "ansigray",
            "header.brand": "bold ansicyan",
            "header.sep": "ansigray",
            "header.target": "bold ansiwhite",
            "header.meta": "ansigray",
            "tab.active": "bold reverse ansicyan",
            "tab.inactive": "ansigray",
            "tab.key": "bold ansiwhite",
            "pane.title": "bold ansiwhite",
            "pane.empty": "ansigray italic",
            "pane.dim": "ansigray",
            "verified": "bold ansigreen",
            "status.pending": "ansigray",
            "status.running": "bold ansicyan",
            "status.working": "bold ansiyellow",
            "status.done": "bold ansigreen",
            "status.fail": "bold ansired",
            "agent.name": "ansiwhite",
            "agent.detail": "ansigray",
            "sev.critical": "bold reverse ansired",
            "sev.high": "bold ansired",
            "sev.medium": "bold ansiyellow",
            "sev.low": "bold ansiblue",
            "sev.info": "ansigray",
            "finding.title": "ansiwhite",
            "finding.path": "ansigray",
            "finding.cursor": "bold reverse ansicyan",
            "trace.time": "ansigray",
            "trace.agent": "ansicyan",
            "trace.arrow": "ansigray",
            "trace.tool": "bold ansiwhite",
            "trace.dim": "ansigray",
            "trace.step": "bold ansibrightblue",
            "session.row": "ansiwhite",
            "session.row.selected": "bold reverse ansicyan",
            "session.meta": "ansigray",
            "section.label": "bold ansicyan",
            "section.box": "ansicyan",
            "code": "ansiwhite",
            "md.h1": "bold ansibrightcyan underline",
            "md.h2": "bold ansicyan",
            "md.h3": "bold ansiwhite",
            "md.bold": "bold ansiwhite",
            "md.italic": "italic",
            "md.code": "bg:#222222 ansibrightgreen",
            "md.bullet": "ansicyan",
            "md.link": "underline ansibrightblue",
            "md.quote": "italic ansigray",
            "syntax.comment": "italic ansigray",
            "syntax.string": "ansigreen",
            "syntax.keyword": "bold ansimagenta",
            "syntax.builtin": "ansicyan",
            "syntax.function": "ansiyellow",
            "syntax.class": "bold ansiyellow",
            "syntax.decorator": "ansiyellow",
            "syntax.number": "ansicyan",
            "syntax.operator": "ansiwhite",
            "log": "ansigray",
            "modal.frame": "bg:#1a1a1a ansiwhite",
            "modal.title": "bg:#1a1a1a bold ansibrightcyan",
            "modal.body": "bg:#1a1a1a ansiwhite",
            "modal.hint": "bg:#1a1a1a ansigray",
            "modal.key": "bg:#1a1a1a bold ansibrightyellow",
            "completion-menu.completion": "bg:#222222 ansiwhite",
            "completion-menu.completion.current": "bg:ansibrightblue ansiwhite",
        })

    # ── Layout ────────────────────────────────────────────────────

    def _build_layout(self) -> Layout:
        is_landing = Condition(lambda: self.mode == "landing")
        is_sessions = Condition(lambda: self.mode == "sessions")
        is_scanning = Condition(lambda: self.mode in ("scanning", "viewing"))

        landing = self._build_landing_container()
        scan = self._build_scan_container()
        sessions = self._build_sessions_container()

        body = HSplit([
            ConditionalContainer(content=landing, filter=is_landing),
            ConditionalContainer(content=sessions, filter=is_sessions),
            ConditionalContainer(content=scan, filter=is_scanning),
        ])

        # ── Modal overlay: centered Frame shown when self._modal_kind set ──
        def _modal_text():
            return [
                ("class:modal.title", self._modal_title),
                ("", "\n\n"),
                ("class:modal.body", self._modal_body),
                ("", "\n\n"),
                ("class:modal.key", "[Y]"),
                ("class:modal.hint", " confirm   "),
                ("class:modal.key", "[N]"),
                ("class:modal.hint", " cancel   "),
                ("class:modal.key", "[Esc]"),
                ("class:modal.hint", " dismiss"),
            ]

        modal_body_window = Window(
            FormattedTextControl(_modal_text),
            wrap_lines=True,
            style="class:modal.frame",
        )
        modal_frame = Frame(
            body=modal_body_window,
            title="OpenHack",
            style="class:modal.frame",
            width=D(min=50, max=80, preferred=72),
            height=D(min=8, max=20, preferred=14),
        )
        # Center via weight-1 spacers on all four sides inside the full-screen Float.
        modal_centered = HSplit([
            Window(height=D(weight=1)),
            VSplit([
                Window(width=D(weight=1)),
                modal_frame,
                Window(width=D(weight=1)),
            ]),
            Window(height=D(weight=1)),
        ])
        modal_visible = Condition(lambda: self._modal_kind is not None)

        root = FloatContainer(
            content=body,
            floats=[
                Float(
                    xcursor=True,
                    ycursor=True,
                    content=CompletionsMenu(max_height=12, scroll_offset=1),
                ),
                Float(
                    top=0, left=0, right=0, bottom=0,
                    content=ConditionalContainer(modal_centered, filter=modal_visible),
                ),
            ],
        )
        return Layout(root, focused_element=self._input_window)

    def _build_landing_container(self) -> HSplit:
        # Centered logo + wordmark + input + hints + tip + footer.
        # Render each logo line as its own Window so WindowAlign.CENTER puts
        # them all at the same horizontal offset.
        logo_windows = [
            Window(
                FormattedTextControl(lambda line=line: [("class:logo", line)]),
                align=WindowAlign.CENTER,
                height=1,
            )
            for line in _LOGO_LINES
        ]

        def wordmark():
            return [("class:wordmark", "OpenHack")]

        def tip():
            return [
                ("class:tip.label", "• Tip  "),
                ("class:tip", "Type "),
                ("class:hint.key", "/scan ."),
                ("class:tip", " to scan the current directory, or "),
                ("class:hint.key", "?"),
                ("class:tip", " for help"),
            ]

        # "Get Started" box — four key commands a new user needs. Each row is
        # `command  description`, column-aligned so the descriptions line up.
        _GETTING_STARTED = [
            ("/login",          "login to OpenHack"),
            ("/scan <dir>",     "begin a scan"),
            ("/sessions",       "browse past scans"),
            ("/help",           "list commands"),
            ("/discord",        "chat with the community"),
        ]
        _GS_CMD_WIDTH = max(len(cmd) for cmd, _ in _GETTING_STARTED)

        _GS_LPAD = "  "  # 2 spaces left padding inside the frame
        _GS_RPAD = "  "  # 2 spaces right padding inside the frame

        def getting_started():
            out: list[tuple[str, str]] = [
                ("", "\n"),  # top vertical padding
                ("", _GS_LPAD), ("class:pane.title", "Get Started"), ("", _GS_RPAD + "\n"),
                ("", "\n"),  # spacer under the title
            ]
            for cmd, desc in _GETTING_STARTED:
                pad = " " * (_GS_CMD_WIDTH - len(cmd) + 3)
                out.append(("", _GS_LPAD))
                out.append(("class:hint.key", cmd))
                out.append(("", pad))
                out.append(("class:tip", desc))
                out.append(("", _GS_RPAD + "\n"))
            out.append(("", "\n"))  # bottom vertical padding
            return out

        # Width = lpad + command column + gap + longest description column + rpad.
        _GS_INNER_WIDTH = (
            len(_GS_LPAD) + _GS_CMD_WIDTH + 3
            + max(len(d) for _, d in _GETTING_STARTED) + len(_GS_RPAD)
        )
        _GS_FRAME_WIDTH = _GS_INNER_WIDTH + 2  # +2 for the box borders
        # Body height: 1 top pad + 1 title + 1 blank + N rows + 1 bottom pad.
        _GS_INNER_HEIGHT = 3 + len(_GETTING_STARTED) + 1

        def hints():
            return [
                ("class:hint", "  enter "),
                ("class:hint.key", "submit"),
                ("class:hint", "   tab "),
                ("class:hint.key", "complete"),
                ("class:hint", "   "),
                ("class:hint.key", "?"),
                ("class:hint", " help"),
            ]

        def footer():
            cfg = load_user_config()
            first = cfg.get("openhack_user_first_name") or ""
            last = cfg.get("openhack_user_last_name") or ""
            email = cfg.get("openhack_user_email") or self.user_email or ""
            org = cfg.get("openhack_org_name") or self.org_name or ""
            # Prefer full name → first name → email.
            display_name = " ".join(p for p in (first, last) if p).strip() or email
            parts: list[tuple[str, str]] = []
            if display_name:
                parts.append(("class:footer", display_name))
            if org:
                if parts:
                    parts.append(("class:footer", "  ·  "))
                parts.append(("class:footer", org))
            if not parts:
                parts.append(("class:footer", "not logged in — run /login"))
            return parts

        # The input bar (used by both landing and scanning, but here it's
        # styled to feel like opencode's centered prompt).
        self._input_window = Window(
            content=BufferControl(
                buffer=self.input_buffer,
                input_processors=[BeforeInput("❯ ", style="class:input.prompt")],
            ),
            height=1,
        )

        return HSplit([
            Window(height=D(weight=1)),  # top spacer
            *logo_windows,
            Window(height=1),
            Window(FormattedTextControl(wordmark), align=WindowAlign.CENTER, height=1),
            Window(height=2),
            # Input row, padded so it appears centered with consistent width.
            VSplit([
                Window(width=D(weight=1)),
                HSplit([
                    Window(
                        FormattedTextControl(lambda: [("class:rule", "─" * 64)]),
                        height=1,
                    ),
                    self._input_window,
                    Window(
                        FormattedTextControl(lambda: [("class:rule", "─" * 64)]),
                        height=1,
                    ),
                ], width=64),
                Window(width=D(weight=1)),
            ]),
            Window(height=1),
            Window(FormattedTextControl(hints), align=WindowAlign.CENTER, height=1),
            Window(height=1),
            Window(FormattedTextControl(tip), align=WindowAlign.CENTER, height=1),
            Window(height=1),
            # "Get Started" box — fixed-width, horizontally centered with
            # flexible spacers on either side.
            VSplit([
                Window(width=D(weight=1)),
                Frame(
                    Window(
                        FormattedTextControl(getting_started),
                        height=_GS_INNER_HEIGHT,
                    ),
                    width=_GS_FRAME_WIDTH,
                ),
                Window(width=D(weight=1)),
            ]),
            Window(height=1),
            # Update notification + announcement banners (populated async on
            # startup via the /updates endpoint). Empty if nothing to show.
            Window(
                FormattedTextControl(self._update_banner_text),
                align=WindowAlign.CENTER,
                wrap_lines=True,
            ),
            # Status-line slot: shows /verify warnings, /logout prompts, errors,
            # etc., on the landing screen. wrap_lines so long warnings stay
            # readable instead of getting truncated at the right edge.
            Window(
                FormattedTextControl(lambda: [
                    ("class:log", f"  {self.last_status_line}" if self.last_status_line else "")
                ]),
                wrap_lines=True,
                align=WindowAlign.CENTER,
            ),
            Window(height=D(weight=1)),
            Window(FormattedTextControl(footer), align=WindowAlign.CENTER, height=1),
            Window(height=1),
        ])

    def _build_scan_container(self) -> HSplit:
        # ── Header bar ────────────────────────────────────────────
        def header_text():
            target = ""
            elapsed = ""
            cost = 0.0
            label = ""
            if self.scan is not None:
                target = self.scan.target or ""
                elapsed = self.scan.elapsed_str()
                cost = self.scan.cost
                if self.scan.end_time is not None and self.mode != "viewing":
                    label = "complete"
                elif self.session is not None and self.session.paused:
                    label = "⏸ paused"
            if self.mode == "viewing":
                target = self.viewing_target or target
                label = "viewing"
            short = self._short_target(target) if target else ""
            out: list[tuple[str, str]] = [("class:header.brand", "⏚ openhack")]
            if short:
                out.extend([
                    ("class:header.sep", "  ·  "),
                    ("class:header.target", short),
                ])
            if elapsed:
                out.extend([
                    ("class:header.sep", "    "),
                    ("class:header.meta", elapsed),
                ])
            if self.scan is not None and self.mode != "viewing":
                out.extend([
                    ("class:header.sep", "  ·  "),
                    ("class:header.meta", f"${cost:.4f}"),
                ])
            if label:
                out.extend([
                    ("class:header.sep", "  ·  "),
                    ("class:header.meta", label),
                ])
            return out

        def account_text():
            # Mirror the landing-page footer: show "Name · Org" on the right
            # edge of the scan header so users always see who they're scanning
            # as. Falls back through full name → first name → email → blank.
            cfg = load_user_config()
            first = cfg.get("openhack_user_first_name") or ""
            last = cfg.get("openhack_user_last_name") or ""
            email = cfg.get("openhack_user_email") or self.user_email or ""
            org = cfg.get("openhack_org_name") or self.org_name or ""
            display_name = " ".join(p for p in (first, last) if p).strip() or email
            parts: list[tuple[str, str]] = []
            if display_name:
                parts.append(("class:header.meta", display_name))
            if org:
                if parts:
                    parts.append(("class:header.sep", "  ·  "))
                parts.append(("class:header.meta", org))
            if parts:
                # Trailing pad keeps the text off the right edge.
                parts.append(("", "  "))
            return parts

        header = VSplit([
            Window(FormattedTextControl(header_text), height=1),
            Window(
                FormattedTextControl(account_text),
                height=1,
                align=WindowAlign.RIGHT,
            ),
        ], height=1)
        rule = Window(FormattedTextControl(lambda: [("class:rule", "─" * 240)]), height=1)

        # ── Tab bar ───────────────────────────────────────────────
        def tab_bar():
            findings = self._current_findings()
            count = len(findings)
            tabs = [("trace", "Trace"), ("findings", f"Findings ({count})")]
            out: list[tuple[str, str]] = [("", "  ")]
            for i, (key, label) in enumerate(tabs, 1):
                active = self.active_tab == key
                cls = "class:tab.active" if active else "class:tab.inactive"
                out.append(("class:tab.key", f" {i} "))
                out.append((cls, f" {label} "))
                out.append(("", "  "))
            out.append(("class:hint",
                        "    ←/→ tab · ↑↓ scroll · [ ] finding · < > resize · Ctrl+B hide · /sessions"))
            return out

        tab_bar_window = Window(FormattedTextControl(tab_bar), height=1)

        # ── Trace tab ─────────────────────────────────────────────
        def _agent_tree() -> list[tuple[int, str]]:
            """Flatten scan.trace_agents into [(indent_level, agent_name), …].

            Swarms like 'hunter_swarm' adopt their 'hunter:*' children as
            level-1 entries underneath. Other agents stay at level 0.
            """
            if self.scan is None:
                return []
            agents = self.scan.trace_agents
            agent_set = set(agents)
            # Map of parent_swarm_name -> [child names in original order]
            children_map: dict[str, list[str]] = {}
            for a in agents:
                if ":" in a:
                    base = a.split(":", 1)[0]
                    parent = f"{base}_swarm"
                    if parent in agent_set:
                        children_map.setdefault(parent, []).append(a)

            seen: set[str] = set()
            out: list[tuple[int, str]] = []
            for a in agents:
                if a in seen:
                    continue
                if ":" in a:
                    base = a.split(":", 1)[0]
                    parent = f"{base}_swarm"
                    if parent in agent_set:
                        # Will be emitted under its parent when parent is visited.
                        continue
                # Top-level entry.
                out.append((0, a))
                seen.add(a)
                # Children (if a is a known swarm parent).
                for c in children_map.get(a, []):
                    if c not in seen:
                        out.append((1, c))
                        seen.add(c)
            # Orphans — any agent not yet emitted (parent wasn't actually seen).
            for a in agents:
                if a not in seen:
                    out.append((0, a))
                    seen.add(a)
            return out

        def _selected_trace_agents() -> Optional[set[str]]:
            """None = show all events; otherwise a set of agent names to include.

            Selecting a swarm parent expands to include all its children, so
            'hunter_swarm' shows events from hunter_swarm AND every hunter:*.
            """
            if self.scan is None:
                return None
            idx = self._trace_agent_idx
            if idx <= 0:
                return None
            tree = _agent_tree()
            if not tree:
                return None
            idx = min(idx - 1, len(tree) - 1)
            _, name = tree[idx]
            if name.endswith("_swarm"):
                base = name[: -len("_swarm")]
                return {name} | {
                    a for a in self.scan.trace_agents
                    if a.startswith(f"{base}:")
                }
            return {name}

        def _trace_text_raw():
            if self.scan is None or not self.scan.trace_lines:
                return [("class:pane.empty", "  no trace yet — start a scan with /scan <path>")]
            wanted = _selected_trace_agents()
            out: list[tuple[str, str]] = []
            matched = 0
            for agent, fragments in self.scan.trace_lines:
                if wanted is not None and agent not in wanted:
                    continue
                for fragment in fragments:
                    out.append(fragment)
                out.append(("", "\n"))
                matched += 1
            if matched == 0 and wanted is not None:
                label = next(iter(wanted)) if len(wanted) == 1 else f"{len(wanted)} agents"
                return [("class:pane.empty", f"  no events from {label} (yet)")]
            return out

        def trace_text():
            """Manual viewport clipping. _trace_follow=True sticks to the
            bottom; otherwise show from _trace_scroll."""
            raw = _trace_text_raw()
            try:
                lines = list(split_lines(raw))
            except Exception:
                return raw
            if not lines:
                return raw
            info = self._trace_window.render_info if hasattr(self, '_trace_window') else None
            window_height = info.window_height if info is not None else 20
            max_scroll = max(0, len(lines) - window_height)
            if self._trace_follow:
                self._trace_scroll = max_scroll
            elif self._trace_scroll > max_scroll:
                self._trace_scroll = max_scroll
            visible = lines[self._trace_scroll:]
            out: list[tuple[str, str]] = []
            for i, line in enumerate(visible):
                out.extend(line)
                if i < len(visible) - 1:
                    out.append(("", "\n"))
            return out

        def _scroll_trace_by(delta: int) -> None:
            # If user scrolls up, break the auto-follow.
            if delta < 0:
                self._trace_follow = False
            # Bump the offset, then re-clamp on next render.
            self._trace_scroll = max(0, self._trace_scroll + delta)
            # If we scrolled down past the visible content end, re-enable follow.
            if delta > 0 and self.scan and self.scan.trace_lines:
                total_lines = sum(
                    sum(frag[1].count("\n") for frag in line) + 1
                    for line in self.scan.trace_lines
                )
                info = self._trace_window.render_info if hasattr(self, '_trace_window') else None
                window_height = info.window_height if info is not None else 20
                if self._trace_scroll >= max(0, total_lines - window_height):
                    self._trace_follow = True
            self._invalidate()

        trace_window = Window(
            content=_ScrollableFormattedTextControl(
                text=trace_text,
                focusable=False,
                on_scroll=_scroll_trace_by,
            ),
            # Wrap so full relative paths in tool calls stay visible. Manual
            # scroll counts logical (\n-delimited) lines, not visual rows, so
            # wrap doesn't break the scroll offset.
            wrap_lines=True,
            always_hide_cursor=True,
        )
        self._trace_window = trace_window
        self._scroll_trace_by = _scroll_trace_by

        # ── Trace sidebar: tree of agents that have produced events. ──
        # Sidebar entries (flat list, ordered):
        #   index 0 = "All"
        #   index 1..N = _agent_tree() entries (level 0 or 1 with indent)
        def trace_sidebar_text():
            tree = _agent_tree() if self.scan is not None else []
            n_entries = 1 + len(tree)  # "All" + tree
            out: list = [("class:pane.title", "  agents\n\n")]
            if len(tree) == 0:
                # "All" + waiting message.
                def _handler_all(event: MouseEvent):
                    if event.event_type == MouseEventType.MOUSE_UP:
                        self._trace_agent_idx = 0
                        self._invalidate()
                cls0 = "class:finding.cursor" if self._trace_agent_idx == 0 else "class:trace.agent"
                pointer0 = "❯ " if self._trace_agent_idx == 0 else "  "
                out.append((cls0, f"  {pointer0}All", _handler_all))
                out.append(("", "\n", _handler_all))
                out.append(("class:pane.empty", "\n  (waiting for events)\n"))
                return out

            def _make_handler(idx: int):
                def _handler(event: MouseEvent):
                    if event.event_type == MouseEventType.MOUSE_UP:
                        self._trace_agent_idx = idx
                        self._trace_scroll = 0
                        self._trace_follow = True
                        self._invalidate()
                return _handler

            # Clamp selection if agents list shrank since last selection.
            if self._trace_agent_idx >= n_entries:
                self._trace_agent_idx = 0

            # Entry 0: "All"
            sel = self._trace_agent_idx == 0
            cls = "class:finding.cursor" if sel else "class:trace.agent"
            pointer = "❯ " if sel else "  "
            h0 = _make_handler(0)
            out.append((cls, f"  {pointer}All", h0))
            out.append(("", "\n", h0))

            # Tree entries
            for i, (level, name) in enumerate(tree, start=1):
                sel = i == self._trace_agent_idx
                handler = _make_handler(i)
                pointer = "❯ " if sel else "  "
                if level == 0:
                    indent = ""
                    label_full = name
                    cls = "class:finding.cursor" if sel else "class:trace.agent"
                else:
                    indent = "  ├─ "
                    label_full = name
                    cls = "class:finding.cursor" if sel else "class:trace.dim"
                shown = label_full if len(label_full) <= 24 else label_full[:23] + "…"
                out.append((cls, f"  {pointer}{indent}{shown}", handler))
                out.append(("", "\n", handler))
            return out

        def _trace_sidebar_cursor() -> Point:
            # Row 0 = title ("agents"), row 1 = blank, row 2+ = entries.
            # Each entry is 1 row. Selected index maps to row (2 + idx).
            return Point(x=0, y=2 + self._trace_agent_idx)

        trace_sidebar_ctrl = FormattedTextControl(
            trace_sidebar_text, focusable=False,
            get_cursor_position=_trace_sidebar_cursor,
        )
        trace_sidebar = Window(
            content=trace_sidebar_ctrl,
            wrap_lines=False,
            always_hide_cursor=True,
            width=D(weight=25, preferred=10_000),
        )
        trace_sep = Window(
            FormattedTextControl(lambda: [("class:rule", "│\n") for _ in range(0, 200)]),
            width=1,
        )
        trace_pane = VSplit([
            trace_sidebar,
            trace_sep,
            VSplit([
                Window(width=1),
                trace_window,
            ], width=D(weight=75, preferred=10_000)),
        ])

        # ── Findings tab (split: list on left, details on right) ──
        def findings_list_text():
            findings = self._current_findings()
            count = len(findings)
            # Per-finding verification summary: how many have been confirmed by
            # the sandbox / browser verifier. Source is a comma-joined string
            # like "sandbox,browser" — split and bucket.
            sb_n = sum(1 for f in findings if "sandbox" in (f.source or ""))
            br_n = sum(1 for f in findings if "browser" in (f.source or ""))
            out: list[tuple[str, str, "MouseEvent"] | tuple[str, str]] = [
                ("class:pane.title", f"  Findings ({count})\n"),
            ]
            if sb_n or br_n:
                badge_parts: list[str] = []
                if sb_n:
                    badge_parts.append(f"sandbox ✓ {sb_n}/{count}")
                if br_n:
                    badge_parts.append(f"browser ✓ {br_n}/{count}")
                out.append(("class:pane.dim", f"  {' · '.join(badge_parts)}\n"))
            out.append(("", "\n"))
            if not findings:
                out.append(("class:pane.empty", "  none yet — start a scan with /scan <path>\n"))
                return out

            def _make_handler(idx: int):
                def _handler(event: MouseEvent):
                    # Only handle clicks for selection. Mouse wheel on the
                    # sidebar is intentionally a no-op (consumed but ignored)
                    # so it doesn't fight with the details pane's scrolling.
                    if event.event_type == MouseEventType.MOUSE_UP:
                        self.findings_selected = idx
                        self._invalidate()
                return _handler

            for i, f in enumerate(findings):
                selected = i == self.findings_selected
                handler = _make_handler(i)
                pointer = "❯ " if selected else "  "
                row_cls = "class:finding.cursor" if selected else "class:finding.title"
                # Verified badge: green ✓ when sandbox- or browser-validated.
                src = f.source or ""
                if "sandbox" in src and "browser" in src:
                    verified_mark = ("class:verified", "✓✓ ")
                elif "sandbox" in src or "browser" in src:
                    verified_mark = ("class:verified", "✓  ")
                else:
                    verified_mark = ("", "   ")
                # The row itself — clickable
                out.append((row_cls, f"  {pointer}", handler))
                out.append((verified_mark[0], verified_mark[1], handler))
                out.append((_sev_style(f.severity), f" {_sev_label(f.severity)} ", handler))
                out.append(("", "  ", handler))
                # Truncate the title to keep the list pane scannable.
                title = f.title if len(f.title) <= 60 else f.title[:57] + "…"
                out.append((row_cls, title, handler))
                out.append(("", "\n", handler))
                if f.file_path:
                    short_path = f.file_path
                    if len(short_path) > 64:
                        short_path = "…" + short_path[-63:]
                    out.append(("class:finding.path", f"          {short_path}\n", handler))
                out.append(("", "\n", handler))
            return out

        # ── Details pane: a single scrollable Window ──
        def _selected_finding():
            findings = self._current_findings()
            if not findings:
                return None
            if self.findings_selected >= len(findings):
                self.findings_selected = max(0, len(findings) - 1)
            return findings[self.findings_selected]

        def _scroll_details_by(delta: int) -> None:
            self._details_scroll = max(0, self._details_scroll + delta)
            self._last_scroll_at = time.monotonic()
            self._invalidate()

        def _details_text_raw():
            f = _selected_finding()
            if f is None:
                return [("class:pane.empty", "  no findings to inspect")]
            out: list[tuple[str, str]] = []

            out.append(("class:pane.title", f"{f.title}\n"))
            out.append(("", "\n"))
            out.append((_sev_style(f.severity), f" {_sev_label(f.severity)} "))
            if f.category:
                out.append(("", "  "))
                out.append(("class:finding.path", f.category))
            if getattr(f, "cvss_score", None):
                out.append(("", "  "))
                out.append(("class:trace.dim", f"CVSS {f.cvss_score:.1f}"))
            src = f.source or ""
            verifiers = [v for v in ("sandbox", "browser") if v in src]
            if verifiers:
                out.append(("", "  "))
                out.append(("class:verified", "✓ verified via " + ", ".join(verifiers)))
            out.append(("", "\n"))
            if f.file_path:
                loc = f.file_path
                if getattr(f, "line_number", None):
                    loc += f":{f.line_number}"
                out.append(("class:finding.path", f"{loc}\n"))
            out.append(("", "\n"))

            if f.description:
                out.extend(_section_header("Description"))
                out.append(("", "\n"))
                out.append(("", f.description))
                out.append(("", "\n\n"))

            snippet = getattr(f, "code_snippet", None)
            if snippet:
                out.extend(_section_header("Vulnerable code"))
                out.append(("", "\n"))
                out.extend(_highlight_code(snippet, f.file_path or ""))
                out.append(("", "\n\n"))

            fix = getattr(f, "fix", None)
            if fix:
                out.extend(_section_header("Recommended fix"))
                out.append(("", "\n"))
                out.extend(_render_markdown_with_code(fix, f.file_path or ""))
                out.append(("", "\n\n"))
            else:
                out.append(("class:trace.dim", "No fix saved for this finding.\n"))

            return out

        def details_text():
            """Manual viewport-clipping scroll: drop the first N logical
            lines from the rendered fragments based on self._details_scroll."""
            raw = _details_text_raw()
            try:
                lines = list(split_lines(raw))
            except Exception:
                return raw
            if not lines:
                return raw
            # Clamp scroll so that the last line lands at the bottom of the
            # viewport — no scrolling past the end into blank space.
            info = self._details_window.render_info
            window_height = info.window_height if info is not None else 20
            max_scroll = max(0, len(lines) - window_height)
            if self._details_scroll > max_scroll:
                self._details_scroll = max_scroll
            visible = lines[self._details_scroll:]
            out: list[tuple[str, str]] = []
            for i, line in enumerate(visible):
                out.extend(line)
                if i < len(visible) - 1:
                    out.append(("", "\n"))
            return out

        # The custom control catches SCROLL_UP/SCROLL_DOWN at the control
        # level — guaranteed to fire on wheel events anywhere over this
        # Window, regardless of which fragment is under the cursor.
        details_window = Window(
            content=_ScrollableFormattedTextControl(
                text=details_text,
                focusable=False,
                on_scroll=_scroll_details_by,
            ),
            wrap_lines=True,
            always_hide_cursor=True,
        )
        self._details_window = details_window

        # Resizable split: the two Dimensions are stored on self so the
        # < / > keybindings can mutate their `weight` to change the ratio.
        self._sidebar_dim = D(weight=self._sidebar_pct, preferred=10_000)
        self._details_dim = D(weight=100 - self._sidebar_pct, preferred=10_000)

        # Findings list pane (left)
        findings_list_pane = Window(
            content=FormattedTextControl(findings_list_text, focusable=False),
            wrap_lines=False,
            always_hide_cursor=True,
            width=self._sidebar_dim,
        )
        details_sep = Window(
            FormattedTextControl(lambda: [("class:rule", "│\n") for _ in range(0, 200)]),
            width=1,
        )
        # Right pane — symmetric horizontal padding so content sits balanced.
        findings_details_pane = VSplit([
            Window(width=2),
            details_window,
            Window(width=2),
        ], width=self._details_dim)
        sidebar_visible = Condition(lambda: not self.findings_list_hidden)
        findings_pane = VSplit([
            ConditionalContainer(findings_list_pane, filter=sidebar_visible),
            ConditionalContainer(details_sep, filter=sidebar_visible),
            findings_details_pane,
        ])

        # ── Body: one of the two tabs ─────────────────────────────
        body = HSplit([
            ConditionalContainer(content=trace_pane,
                                 filter=Condition(lambda: self.active_tab == "trace")),
            ConditionalContainer(content=findings_pane,
                                 filter=Condition(lambda: self.active_tab == "findings")),
        ])

        # ── Bottom status line + input ────────────────────────────
        def status_line():
            msg = self.last_status_line or (self.scan.last_message if self.scan else "")
            return [("class:log", f"  {msg}" if msg else "")]

        return HSplit([
            Window(height=1),  # top padding
            header,
            rule,
            tab_bar_window,
            rule,
            body,
            rule,
            Window(FormattedTextControl(status_line), height=1),
            VSplit([
                Window(width=2),
                self._input_window,
                Window(FormattedTextControl(lambda: [("class:hint", "  /cancel  /clear")]),
                       width=20, height=1, align=WindowAlign.RIGHT),
            ]),
            Window(height=1),  # bottom padding
        ])

    def _build_sessions_container(self) -> HSplit:
        """Standalone sessions overlay — full-screen picker, no tab bar."""
        def header_text():
            return [
                ("class:header.brand", "openhack"),
                ("class:header.sep", "  ·  "),
                ("class:header.target", "sessions"),
                ("class:header.sep", "    "),
                ("class:header.meta",
                 f"{len(self.sessions_index)} saved scan(s)" if self.sessions_index else "no saved scans"),
            ]

        def sessions_text():
            out: list[tuple[str, str]] = [("", "\n")]
            if not self.sessions_index:
                out.append((
                    "class:pane.empty",
                    "  no saved scans yet — completed scans are saved to ~/.openhack/scans/\n",
                ))
                return out
            for i, row in enumerate(self.sessions_index):
                selected = i == self.sessions_selected
                cls = "class:session.row.selected" if selected else "class:session.row"
                pointer = "❯ " if selected else "  "
                out.append((cls, f"  {pointer}{row.get('label', '')}"))
                out.append(("", "\n"))
                out.append(("class:session.meta", f"      {row.get('meta', '')}"))
                out.append(("", "\n\n"))
            return out

        def hint_text():
            return [
                ("class:hint", "  ↑/↓ "),
                ("class:hint.key", "navigate"),
                ("class:hint", "   enter "),
                ("class:hint.key", "load"),
                ("class:hint", "   esc "),
                ("class:hint.key", "back"),
            ]

        header = Window(FormattedTextControl(header_text), height=1)
        rule = Window(FormattedTextControl(lambda: [("class:rule", "─" * 240)]), height=1)
        def _sessions_cursor() -> Point:
            # Row 0 = leading blank. Each session = 3 rows (label, meta, blank).
            return Point(x=0, y=1 + self.sessions_selected * 3)

        body = Window(
            FormattedTextControl(
                sessions_text, focusable=False,
                get_cursor_position=_sessions_cursor,
            ),
            wrap_lines=False,
            always_hide_cursor=True,
        )
        hint = Window(FormattedTextControl(hint_text), height=1)

        return HSplit([
            Window(height=1),
            header,
            rule,
            body,
            rule,
            hint,
            VSplit([Window(width=2), self._input_window]),
            Window(height=1),
        ])

    _SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _current_findings(self) -> list[Finding]:
        if self.scan is not None and self.mode == "scanning":
            findings = self.scan.findings
        elif self.mode == "viewing":
            findings = self.last_findings
        elif self.scan is not None and self.scan.findings:
            findings = self.scan.findings
        else:
            findings = self.last_findings
        # Sort by severity (critical first), stable so equal-severity findings
        # keep their discovery order.
        return sorted(
            findings,
            key=lambda f: self._SEV_RANK.get((f.severity or "info").lower(), 99),
        )

    @staticmethod
    def _short_target(target: str) -> str:
        try:
            home = str(Path.home())
            if target.startswith(home):
                return "~" + target[len(home):]
        except Exception:
            pass
        return target

    # ── Update banner ────────────────────────────────────────────

    _ANN_LEVEL_STYLE = {
        "info": "class:tip",
        "warning": "class:sev.medium",
        "critical": "class:sev.critical",
    }

    def _update_banner_text(self) -> list[tuple[str, str]]:
        """Render update + announcement banners for the landing screen."""
        info = self._update_info
        if info is None:
            return []
        out: list[tuple[str, str]] = []

        # Update available notification.
        if info.has_update and info.latest:
            from openhack import __version__ as cur
            out.append(("class:sev.medium", f"  ⬆ Update available: {cur} → {info.latest.version}"))
            out.append(("class:tip", "  ·  pipx upgrade openhack"))
            if info.latest.download_url:
                out.append(("class:tip", f"  ·  {info.latest.download_url}"))
            out.append(("", "\n"))

        # Banner-placement announcements.
        for ann in info.announcements:
            if "banner" not in ann.placement:
                continue
            style = self._ANN_LEVEL_STYLE.get(ann.level, "class:tip")
            out.append((style, f"  {ann.title}"))
            if ann.body:
                # Show first line of body as a subtitle.
                first_line = ann.body.split("\n")[0].strip()
                if first_line:
                    out.append(("class:tip", f"  —  {first_line}"))
            out.append(("", "\n"))

        return out

    # ── Invalidate / refresh ──────────────────────────────────────

    def _invalidate(self) -> None:
        try:
            self.app.invalidate()
        except Exception:
            pass

    # ── Input handling ────────────────────────────────────────────

    def _on_buffer_accept(self, buf: Buffer) -> bool:
        text = buf.text.strip()
        buf.reset()
        if not text:
            return False
        if text == "?":
            text = "/help"
        asyncio.create_task(self._dispatch_input(text))
        return False  # keep buffer alive

    async def _dispatch_input(self, text: str) -> None:
        try:
            await self._handle_input(text)
        finally:
            self._invalidate()

    async def _handle_input(self, text: str) -> None:
        # Cancel any pending confirmations when an unrelated input arrives.
        if self._logout_armed and not text.startswith("/logout"):
            self._logout_armed = False
        if self._verify_arm_subject is not None and not text.startswith("/verify"):
            self._verify_arm_subject = None

        # Non-slash input.
        if not text.startswith("/"):
            if self.mode == "scanning" and self.session:
                low = text.lstrip("-").strip().lower()
                if low in _CANCEL_PHRASES:
                    self._cancel_scan()
                    return
                self.session.add_user_instruction(text)
                self.last_status_line = "instruction queued for scan agents"
                return
            # Landing: chat about findings.
            await self._chat(text)
            return

        parts = text.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "/help":
            self._show_help()
        elif cmd in ("/quit", "/exit"):
            if self.mode == "scanning":
                self._cancel_scan()
            self.app.exit()
        elif cmd == "/cancel":
            self._cancel_scan()
        elif cmd == "/pause":
            self._pause_scan()
        elif cmd == "/resume":
            self._resume_scan()
        elif cmd == "/clear":
            self.mode = "landing"
            self.scan = None
            self.active_tab = "trace"
            self.viewing_target = ""
            self.last_status_line = ""
        elif cmd == "/login":
            await self._cmd_login()
        elif cmd == "/logout":
            self._cmd_logout()
        elif cmd == "/setup":
            await self._cmd_setup()
        elif cmd == "/provider":
            self._cmd_provider(arg)
        elif cmd == "/model":
            self._cmd_model(arg)
        elif cmd == "/scan":
            target = (arg.strip() or os.getcwd())
            target_path = Path(target).resolve()
            if not target_path.exists():
                self.last_status_line = f"error: directory not found: {target_path}"
            else:
                self._start_scan(str(target_path))
        elif cmd == "/cost":
            self._cmd_cost()
        elif cmd == "/findings":
            self._cmd_findings()
        elif cmd == "/config":
            self._cmd_config(arg)
        elif cmd == "/test":
            self._start_test_scan()
        elif cmd == "/sessions":
            self._open_sessions_overlay()
        elif cmd == "/sidebar":
            self.findings_list_hidden = not self.findings_list_hidden
            self.last_status_line = "sidebar hidden" if self.findings_list_hidden else "sidebar shown"
        elif cmd == "/copy":
            self._cmd_copy_fix()
        elif cmd == "/verify":
            self._cmd_verify(arg)
        elif cmd == "/mouse":
            self._cmd_mouse(arg)
        elif cmd == "/discord":
            self._cmd_discord()
        else:
            self.last_status_line = f"unknown command: {cmd} — try /help"

    # ── Commands that just update status ──────────────────────────

    def _show_help(self) -> None:
        lines = ["commands: " + ", ".join(c for c, _ in _SLASH_COMMANDS)]
        self.last_status_line = lines[0]

    def _cmd_provider(self, name: str) -> None:
        name = name.lower().strip()
        if name not in PROVIDER_DEFAULTS:
            self.last_status_line = f"unknown provider: {name}"
            return
        self.provider = resolve_provider(name)
        self.model = PROVIDER_DEFAULTS[name]
        save_user_config({"provider": self.provider, "model": self.model})
        self.last_status_line = f"switched to {name} ({self.model})"

    def _cmd_model(self, arg: str) -> None:
        if arg:
            self.model = arg
            save_user_config({"model": arg})
            self.last_status_line = f"model set to {arg}"
        else:
            self.last_status_line = f"current model: {self.model}"

    # ── Copy finding for AI agent ─────────────────────────────────

    @staticmethod
    def _clipboard_write(text: str) -> tuple[bool, str]:
        """Write *text* to the system clipboard. Returns (success, tool_used)."""
        import subprocess
        import shutil

        for tool, args in (
            ("pbcopy", ["pbcopy"]),                               # macOS
            ("wl-copy", ["wl-copy"]),                             # Wayland
            ("xclip", ["xclip", "-selection", "clipboard"]),      # X11
            ("xsel", ["xsel", "--clipboard", "--input"]),         # X11 alt
            ("clip", ["clip"]),                                   # Windows
        ):
            if shutil.which(args[0]) is None:
                continue
            try:
                proc = subprocess.run(
                    args, input=text.encode("utf-8"),
                    timeout=2, check=False,
                )
                if proc.returncode == 0:
                    return True, tool
            except Exception:
                continue
        return False, ""

    @staticmethod
    def _format_finding_for_agent(f: Finding) -> str:
        """Format the finding as a self-contained prompt for an AI coding agent."""
        lines: list[str] = [
            "Please fix this security vulnerability in my codebase.",
            "",
            f"# {f.title}",
            "",
        ]
        meta_bits = [f"**Severity:** {f.severity.upper()}"]
        if f.category:
            meta_bits.append(f"**Category:** {f.category}")
        if getattr(f, "cvss_score", None):
            meta_bits.append(f"**CVSS:** {f.cvss_score:.1f}")
        lines.append("  •  ".join(meta_bits))
        if f.file_path:
            loc = f.file_path
            if getattr(f, "line_number", None):
                loc += f":{f.line_number}"
            lines.append(f"**Location:** `{loc}`")
        lines.append("")

        if f.description:
            lines += ["## Description", "", f.description, ""]

        snippet = getattr(f, "code_snippet", None)
        if snippet:
            # Try to infer the fence language from the file extension.
            lang = ""
            if f.file_path:
                ext = f.file_path.rsplit(".", 1)[-1].lower() if "." in f.file_path else ""
                lang = {
                    "ts": "typescript", "tsx": "typescript",
                    "js": "javascript", "jsx": "javascript",
                    "py": "python", "rb": "ruby", "go": "go",
                    "rs": "rust", "java": "java", "kt": "kotlin",
                    "c": "c", "cpp": "cpp", "cs": "csharp",
                    "php": "php", "swift": "swift",
                }.get(ext, ext)
            lines += ["## Vulnerable code", "", f"```{lang}", snippet, "```", ""]

        fix = getattr(f, "fix", None)
        if fix:
            lines += ["## Recommended fix", "", fix, ""]

        if f.file_path:
            lines.append(f"Apply the recommended fix to `{f.file_path}`.")

        return "\n".join(lines)

    def _cmd_copy_fix(self) -> None:
        findings = self._current_findings()
        if not findings:
            self.last_status_line = "no finding selected"
            return
        if self.findings_selected >= len(findings):
            self.last_status_line = "no finding selected"
            return
        f = findings[self.findings_selected]
        text = self._format_finding_for_agent(f)
        ok, tool = self._clipboard_write(text)
        if ok:
            self.last_status_line = (
                f"copied {len(text):,} chars to clipboard via {tool} · "
                f"paste into Codex / Claude Code / OpenCode"
            )
        else:
            self.last_status_line = (
                "couldn't find a clipboard tool (pbcopy/xclip/wl-copy/clip)"
            )

    # ── Sessions overlay ──────────────────────────────────────────

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        """Cheap liveness check — `kill -0` doesn't actually signal."""
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def _resume_selected_session(self) -> None:
        """Resume an aborted scan by kicking off a fresh scan against the
        same target. The prior aborted scan's data stays preserved as a
        separate session — this is coarse resume (re-scan the target),
        not mid-scan resume from a step. Findings from the old scan can
        still be viewed via Enter on the aborted row.
        """
        if not self.sessions_index:
            return
        row = self.sessions_index[self.sessions_selected]
        target = row.get("target") or ""
        if not target or not Path(target).exists():
            self.last_status_line = f"target no longer exists: {target}"
            return
        status = (row.get("status") or "").lower()
        if status not in ("aborted", "failed", "cancelled"):
            self.last_status_line = f"can only resume aborted/failed scans (this one is {status})"
            return
        self._close_sessions_overlay()
        self._start_scan(target)
        self.last_status_line = f"resuming: re-scanning {self._short_target(target)}"


    def _open_sessions_overlay(self) -> None:
        """Open the sessions picker as a full-screen overlay."""
        self._refresh_sessions_index()
        self.previous_mode = self.mode  # remember where to go back on Esc
        self.mode = "sessions"
        if not self.sessions_index:
            self.last_status_line = "no saved scans yet — completed scans are saved to ~/.openhack/scans/"
        else:
            self.last_status_line = (
                f"{len(self.sessions_index)} session(s) · ↑/↓ navigate · enter load · r resume (aborted) · esc back"
            )

    def _close_sessions_overlay(self) -> None:
        """Return from the sessions overlay to whatever screen the user was on."""
        target_mode = self.previous_mode or "landing"
        self.mode = target_mode
        self.previous_mode = None
        self.last_status_line = ""

    def _refresh_sessions_index(self) -> None:
        scans_dir = Path.home() / ".openhack" / "scans"
        self.sessions_index = []
        if not scans_dir.exists():
            return
        rows: list[tuple[float, dict]] = []
        for p in scans_dir.glob("*.json"):
            try:
                with open(p) as fp:
                    data = json.load(fp)
            except (OSError, json.JSONDecodeError):
                continue
            findings = data.get("findings", []) or []
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                sev = (f.get("severity") or "info").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            top_sev = next((s.upper() for s in ("critical", "high", "medium", "low", "info")
                            if sev_counts.get(s, 0) > 0), "—")
            target = data.get("target_dir") or "(unknown)"
            started = data.get("started_at") or ""
            try:
                started_display = datetime.fromisoformat(started).strftime("%Y-%m-%d %H:%M")
            except ValueError:
                started_display = started[:16]
            duration = data.get("duration_seconds") or 0
            dur_m, dur_s = divmod(int(duration), 60)
            duration_display = f"{dur_m}:{dur_s:02d}"
            scan_id = data.get("scan_id") or p.stem
            short_id = scan_id[:8]

            # Resolve true status: a "running" report whose PID is no longer
            # alive means the terminal closed mid-scan — reclassify as aborted.
            raw_status = (data.get("status") or "completed").lower()
            status = raw_status
            if raw_status == "running":
                pid = data.get("pid")
                if not (isinstance(pid, int) and self._pid_alive(pid)):
                    status = "aborted"

            label = f"{short_id}  {self._short_target(target)}"
            meta = (
                f"[{status}]  {started_display} · {len(findings)} findings · "
                f"top {top_sev} · {duration_display}"
            )
            row = {
                "path": p,
                "scan_id": scan_id,
                "label": label,
                "meta": meta,
                "target": target,
                "status": status,
                "data": data,
            }
            rows.append((p.stat().st_mtime, row))
        rows.sort(key=lambda x: x[0], reverse=True)
        self.sessions_index = [r for _, r in rows]
        if self.sessions_selected >= len(self.sessions_index):
            self.sessions_selected = max(0, len(self.sessions_index) - 1)

    def _load_selected_session(self) -> None:
        if not self.sessions_index:
            return
        row = self.sessions_index[self.sessions_selected]
        data = row.get("data") or {}
        findings_raw = data.get("findings", []) or []
        loaded: list[Finding] = []
        for fd in findings_raw:
            try:
                # JSON uses camelCase keys (via Finding.to_dict). Accept either.
                loaded.append(Finding(
                    category=fd.get("category", "") or "",
                    severity=(fd.get("severity") or "info"),
                    title=fd.get("title", "") or "",
                    description=fd.get("description", "") or "",
                    file_path=fd.get("file_path") or fd.get("filePath") or "",
                    line_number=fd.get("line_number") or fd.get("lineNumber"),
                    code_snippet=fd.get("code_snippet") or fd.get("relevantCode"),
                    poc=fd.get("poc"),
                    fix=fd.get("fix") or fd.get("recommendation"),
                    cvss_score=fd.get("cvss_score") or fd.get("cvssScore"),
                    confidence=fd.get("confidence", "medium"),
                    validated=bool(fd.get("validated", False)),
                ))
            except Exception:
                continue
        self.last_findings = loaded
        # Build a placeholder scan with a frozen clock. start_time / end_time
        # must share the same time base — we anchor on the first trace
        # event's epoch timestamp so per-event [m:ss] offsets read sanely,
        # then set end_time = start_time + duration so the header shows the
        # actual duration (not start-epoch arithmetic).
        scan = ScanState(target=row.get("target") or "")
        scan.cost = float((data.get("cost") or {}).get("total_cost") or 0.0)
        duration = float(data.get("duration_seconds") or 0)

        # Hydrate saved trace events (version 2+ reports). Older reports
        # have no trace field — Trace tab will show "no trace yet" for those.
        trace_raw = data.get("trace") or []
        first_ts: Optional[float] = None
        for entry_data in trace_raw:
            try:
                entry = TraceEntry(
                    timestamp=float(entry_data.get("timestamp") or 0),
                    agent=entry_data.get("agent", "") or "",
                    event_type=entry_data.get("event_type", "") or "",
                    content=entry_data.get("content"),
                    tool_name=entry_data.get("tool_name"),
                    tool_input=entry_data.get("tool_input"),
                    tool_output=entry_data.get("tool_output"),
                )
                if first_ts is None and entry.timestamp > 0:
                    first_ts = entry.timestamp
                    scan.start_time = first_ts
                scan.update_from_trace(entry)
            except Exception:
                continue

        # Anchor end_time relative to start_time so elapsed_str() reports
        # the actual duration. If no trace events were saved (older reports),
        # fall back to start_time=0 + end_time=duration.
        if first_ts is not None:
            scan.end_time = first_ts + duration
        else:
            scan.start_time = 0
            scan.end_time = duration

        self.scan = scan
        self.viewing_target = row.get("target") or ""
        self.mode = "viewing"
        self.previous_mode = None
        self.active_tab = "findings"
        self.last_status_line = (
            f"loaded {row.get('scan_id', '')[:8]} · "
            f"{len(loaded)} findings · {row.get('meta', '')}"
        )

    def _cmd_cost(self) -> None:
        sess = self.last_session or self.session
        if not sess:
            self.last_status_line = "no scan has been run yet"
            return
        b = sess.get_cost_breakdown()
        self.last_status_line = (
            f"cost: ${b['total_cost']:.4f} · tokens: {b['total_tokens']:,}"
        )

    def _cmd_findings(self) -> None:
        findings = (self.last_session.findings if self.last_session else None) or self.last_findings
        if not findings:
            self.last_status_line = "no findings to display"
            return
        self.last_findings = list(findings)
        self.last_status_line = f"{len(findings)} finding(s)"

    def _cmd_config(self, arg: str) -> None:
        if not arg.strip():
            cfg = load_user_config()
            self.last_status_line = "config: " + ", ".join(
                f"{k}={'***' if 'api_key' in k and v else v}" for k, v in cfg.items() if v
            )
            return
        parts = arg.strip().split(None, 1)
        key = parts[0].lower()
        value = parts[1] if len(parts) > 1 else ""
        valid = {"provider", "model", "openhack_api_key", "openhack_model_id", "openhack_base_url", "prompt_caching"}
        if key not in valid:
            self.last_status_line = f"unknown config key: {key}"
            return
        if not value:
            cfg = load_user_config()
            current = cfg.get(key, "")
            self.last_status_line = f"{key} = {'***' if 'api_key' in key and current else current or '(not set)'}"
            return
        save_user_config({key: value})
        if key == "provider":
            self.provider = resolve_provider(value)
            self.model = PROVIDER_DEFAULTS.get(value, self.model)
            save_user_config({"provider": self.provider})
        elif key == "model":
            self.model = value
        reload_settings()
        self.last_status_line = f"saved {key}"

    # ── Setup / login (delegate to setup.py / auth.py) ────────────

    async def _cmd_setup(self) -> None:
        if self.mode == "scanning":
            self.last_status_line = "cannot run setup while a scan is in progress"
            return
        # Setup wizard is a separate full-screen flow; we need to suspend our
        # app to let it use the terminal.
        await self._run_external(run_setup_command())
        reload_settings()
        cfg = load_user_config()
        self.provider = resolve_provider(cfg.get("provider", settings.llm_provider))
        self.model = cfg.get("model") or PROVIDER_DEFAULTS.get(self.provider, settings.openhack_model_id)
        self.org_name = cfg.get("openhack_org_name") or self.org_name
        self.last_status_line = f"active: {self.provider} · {self.model}"

    async def _cmd_login(self) -> None:
        if self.mode == "scanning":
            self.last_status_line = "cannot log in while a scan is in progress"
            return
        from openhack.auth import (
            DeviceLoginCancelled,
            DeviceLoginError,
            DeviceLoginExpired,
            device_login,
        )
        cfg = load_user_config()
        app_url = cfg.get("openhack_app_url") or settings.openhack_app_url

        async def _do_login():
            try:
                return await device_login(app_url)
            except DeviceLoginCancelled:
                self.last_status_line = "login cancelled"
            except DeviceLoginExpired as exc:
                self.last_status_line = f"login expired: {exc}"
            except DeviceLoginError as exc:
                self.last_status_line = f"login failed: {exc}"
            return None

        result = await self._run_external(_do_login())
        if not result:
            return
        new_cfg: dict = {"provider": "openhack", "openhack_api_key": result.token}
        if result.org_id: new_cfg["openhack_org_id"] = result.org_id
        if result.org_slug: new_cfg["openhack_org_slug"] = result.org_slug
        if result.org_name: new_cfg["openhack_org_name"] = result.org_name
        if result.user_email: new_cfg["openhack_user_email"] = result.user_email
        if result.user_first_name: new_cfg["openhack_user_first_name"] = result.user_first_name
        if result.user_last_name: new_cfg["openhack_user_last_name"] = result.user_last_name
        save_user_config(new_cfg)
        reload_settings()
        self.org_name = result.org_name or self.org_name
        self.last_status_line = f"logged in · {result.org_name or ''}"

    def _cmd_logout(self) -> None:
        cfg = load_user_config()
        if not cfg.get("openhack_api_key"):
            self.last_status_line = "not signed in"
            return
        first = cfg.get("openhack_user_first_name") or ""
        last = cfg.get("openhack_user_last_name") or ""
        email = cfg.get("openhack_user_email") or ""
        who = " ".join(p for p in (first, last) if p).strip() or email or "current user"
        org = cfg.get("openhack_org_name") or ""
        target = f"{who} · {org}" if org else who
        self._open_modal(
            "logout",
            "Sign out?",
            f"You're about to sign out from {target}.\n\n"
            f"The saved API token will be cleared from ~/.openhack/config. "
            f"You can sign back in any time with /login.",
            self._do_logout,
        )

    def _do_logout(self) -> None:
        cleared = {
            "openhack_api_key": None,
            "openhack_org_id": None,
            "openhack_org_slug": None,
            "openhack_org_name": None,
            "openhack_user_email": None,
            "openhack_user_first_name": None,
            "openhack_user_last_name": None,
        }
        # `save_user_config` merges into the existing JSON, so None values
        # would just be ignored. We need to physically remove them.
        try:
            existing = load_user_config()
            for k in cleared:
                existing.pop(k, None)
            from openhack.config import CONFIG_PATH
            import json as _json, os as _os
            with open(CONFIG_PATH, "w") as fp:
                _json.dump(existing, fp, indent=2)
                fp.write("\n")
            try:
                _os.chmod(CONFIG_PATH, 0o600)
            except OSError:
                pass
        except Exception as exc:
            self.last_status_line = f"sign-out failed: {exc}"
            self._logout_armed = False
            return

        reload_settings()
        self.org_name = ""
        self.user_email = ""
        self.scan = None
        self.session = None
        self.mode = "landing"
        self.active_tab = "trace"
        self._logout_armed = False
        self.last_status_line = "signed out · run /login to sign back in"
        self._invalidate()

    # ── Modal helpers ─────────────────────────────────────────────

    def _open_modal(self, kind: str, title: str, body: str,
                    on_yes: Callable[[], None]) -> None:
        self._modal_kind = kind
        self._modal_title = title
        self._modal_body = body
        self._modal_on_yes = on_yes
        self._invalidate()

    def _close_modal(self) -> None:
        self._modal_kind = None
        self._modal_title = ""
        self._modal_body = ""
        self._modal_on_yes = None

    def _show_announcement_modal(self, ann: Announcement) -> None:
        """Display an announcement as a modal dialog. On dismiss, persist
        the announcement ID so it won't appear again (unless critical)."""
        def _dismiss():
            save_dismissed(ann.id)

        # Critical announcements can't be dismissed without acknowledging.
        title = ann.title or "Announcement"
        body = ann.body or ""
        self._open_modal(f"announcement:{ann.id}", title, body, _dismiss)
        self._invalidate()

    def _cmd_discord(self) -> None:
        url = "https://openhack.com/discord"
        try:
            import webbrowser
            webbrowser.open(url)
            self.last_status_line = f"opened {url} in your browser"
        except Exception as exc:
            self.last_status_line = f"couldn't open browser: {exc} · visit {url}"
        self._invalidate()

    def _cmd_mouse(self, arg: str) -> None:
        """Toggle mouse capture. When off, native terminal drag-to-select works
        (so users can copy text), at the cost of mouse-wheel scrolling and
        click-to-select inside the TUI. Keyboard nav still works either way.
        """
        a = arg.strip().lower()
        if a in ("on", "true", "1"):
            self._mouse_enabled = True
        elif a in ("off", "false", "0"):
            self._mouse_enabled = False
        else:
            self._mouse_enabled = not self._mouse_enabled
        if self._mouse_enabled:
            self.last_status_line = (
                "mouse ON · wheel scroll & click work · /mouse off to enable drag-to-copy"
            )
        else:
            self.last_status_line = (
                "mouse OFF · drag to select & copy text · /mouse on to re-enable"
            )
        self._invalidate()

    # ── Verify (sandbox / browser) ────────────────────────────────

    _VERIFY_PREREQS = {
        "sandbox": (
            "SANDBOX needs: (1) Docker Desktop or daemon running · "
            "(2) Dockerfile OR docker-compose.yml at the scan target's root · "
            "(3) the app must start and respond to a health check on /  · "
            "(4) a free localhost port the sandbox can bind to."
        ),
        "browser": (
            "BROWSER needs: (1) the browser extra installed → "
            "`uv sync --extra browser`  · "
            "(2) Chromium installed → `uv run playwright install chromium` · "
            "(3) the target app reachable over HTTP — usually means sandbox "
            "verification is also on (so the app is running)."
        ),
    }

    def _cmd_verify(self, arg: str) -> None:
        """Run sandbox or browser verification against the currently-loaded
        session's findings. /verify is an *action*, not a settings toggle —
        the user loads a session via /sessions or finishes a scan, then runs
        /verify sandbox or /verify browser to add verification evidence to
        the existing findings.
        """
        parts = arg.strip().split()
        logging.getLogger("openhack.tui").info("/verify dispatched: arg=%r", arg)

        if not parts:
            self.last_status_line = (
                "usage: /verify <sandbox|browser> "
                "— runs verification against the loaded session's findings"
            )
            return

        kind = parts[0].lower()
        if kind not in ("sandbox", "browser"):
            self.last_status_line = f"unknown subject: {kind} (use sandbox/browser)"
            return

        if self.mode == "scanning" and self.scan_task is not None:
            self.last_status_line = "a scan is already running · wait for it to finish first"
            return

        findings = self._current_findings()
        if not findings:
            self.last_status_line = "no findings loaded — finish a scan or load a session from /sessions first"
            return

        # Resolve the target directory: viewing mode stores it on viewing_target,
        # otherwise pull from the currently-loaded session.
        target_dir = (
            self.viewing_target
            or (self.scan.target if self.scan and self.scan.target else "")
        )
        if not target_dir or not Path(target_dir).exists():
            self.last_status_line = (
                f"target directory not accessible: {target_dir or '(unknown)'}"
            )
            return

        title = f"Run {kind} verification on {len(findings)} finding(s)?"
        body = (
            f"{self._VERIFY_PREREQS[kind]}\n\n"
            f"Target: {target_dir}\n"
            f"This will spin up the verification swarm against the loaded findings, "
            f"stream events into the Trace tab, and write a new report to "
            f"~/.openhack/scans/ when it finishes."
        )

        def _apply():
            task = asyncio.create_task(self._run_verification(kind, target_dir, list(findings)))
            self.scan_task = task

        self._open_modal(f"verify:{kind}", title, body, _apply)

    async def _run_verification(self, kind: str, target_dir: str,
                                findings: list[Finding]) -> None:
        """Spin up the sandbox/browser verifier swarm against an existing
        findings set. Streams trace events live and writes a new report when done.
        """
        reload_settings()

        # Preserve the loaded scan's existing trace and findings — verification
        # is an *extension* of an existing scan, not a fresh run. We mutate the
        # current ScanState (created either by the previous scan or by
        # _open_session) so:
        #   • trace_lines / trace_agents from the original scan stay intact
        #   • the new sandbox/browser swarms append to that same trace
        #   • scan.findings already has every finding ready for the Findings tab
        if self.scan is None:
            self.scan = ScanState(target=target_dir)
        # Reset the clock so the elapsed counter reflects this verification run.
        self.scan.start_time = time.time()
        self.scan.end_time = None
        # Ensure scan.findings holds the findings we're about to verify so the
        # Findings tab reads them in scanning mode. (When loaded from /sessions
        # the trace got hydrated but findings live on self.last_findings — we
        # mirror them onto scan.findings here.) Use the *same* objects so the
        # verifier's mutations show up on the rendered list.
        if not self.scan.findings:
            self.scan.findings = list(findings)
        self.last_findings = list(findings)
        self.mode = "scanning"
        self.active_tab = "trace"
        self._invalidate()

        session: Optional[Session] = None
        try:
            session = Session(
                target_dir=target_dir,
                on_trace=self._on_trace,
            )
            # Seed the verifier with the findings being verified — same Finding
            # *objects* as scan.findings so the swarm's mutations are visible
            # in the rendered list without copying.
            for f in findings:
                session.findings.append(f)
            self.session = session

            tools = ToolRegistry(target_dir=Path(target_dir))
            llm = LLMClient(
                model=self.model, temperature=0.0, max_tokens=8192,
                provider=self.provider, prompt_cache_key=session.id,
            )

            if kind == "sandbox":
                from openhack.agents.sandbox_verifier_swarm import SandboxVerifierSwarmAgent
                from openhack.sandbox.orchestrator import SandboxConfig
                sandbox_cfg = SandboxConfig(
                    health_check_path=settings.sandbox_health_check_path,
                    health_check_timeout=settings.sandbox_health_check_timeout,
                    teardown_on_complete=settings.sandbox_teardown_on_complete,
                )
                swarm = SandboxVerifierSwarmAgent(
                    llm, tools, session, sandbox_config=sandbox_cfg,
                )
            else:
                from openhack.agents.browser_verifier_swarm import BrowserVerifierSwarmAgent
                from openhack.sandbox.orchestrator import SandboxConfig
                sandbox_cfg = SandboxConfig(
                    health_check_path=settings.sandbox_health_check_path,
                    health_check_timeout=settings.sandbox_health_check_timeout,
                    teardown_on_complete=settings.sandbox_teardown_on_complete,
                )
                swarm = BrowserVerifierSwarmAgent(
                    llm, tools, session, sandbox_config=sandbox_cfg,
                )

            # The swarm reads findings from context["confirmed_findings"] as dicts.
            findings_dicts = [f.to_dict() for f in findings]
            result = await swarm.run(
                f"Run {kind} verification on the loaded findings.",
                context={"confirmed_findings": findings_dicts},
            )

            # The swarm returns lists of {finding_index, status, evidence, ...}.
            # Stamp the matching Finding objects so the Findings tab can render
            # a ✓ next to verified ones. Findings are mutated in place, which
            # `self.scan.findings` shares — the UI picks up the changes on the
            # next invalidate.
            exploitable = (result or {}).get("exploitable") or []
            verified_by = "sandbox" if kind == "sandbox" else "browser"
            verified_count = 0
            for item in exploitable:
                idx = item.get("finding_index")
                if idx is None or idx >= len(findings):
                    continue
                f = findings[idx]
                # source is a comma-joined string when multiple verifiers have
                # validated the same finding (e.g., "sandbox,browser").
                existing = {s.strip() for s in (f.source or "").split(",") if s.strip()}
                existing.add(verified_by)
                f.source = ",".join(sorted(existing))
                evidence = item.get("evidence")
                if evidence and not f.poc:
                    f.poc = evidence
                verified_count += 1

            # Persist the now-annotated findings so the user can find them in /sessions.
            fatal = (result or {}).get("fatal_error")
            status = "failed" if fatal else "completed"
            self._write_report(session, target_dir, status=status)
            self.last_findings = list(session.findings)
            self.last_session = session
            if fatal:
                self.last_status_line = (
                    f"{kind} verification aborted · {fatal}"
                )
            else:
                self.last_status_line = (
                    f"{kind} verification complete · "
                    f"{verified_count}/{len(findings)} verified · "
                    f"report saved to ~/.openhack/scans/{session.id[:8]}.json"
                )

        except asyncio.CancelledError:
            self.last_status_line = f"{kind} verification cancelled"
            if session is not None:
                self._write_report(session, target_dir, status="cancelled")
            raise
        except Exception as exc:
            self.last_status_line = f"{kind} verification failed: {exc}"
            if session is not None:
                self._write_report(session, target_dir, status="failed")
        finally:
            if self.scan is not None:
                self.scan.finish()
            self.scan_task = None
            self.active_tab = "findings"
            self.findings_selected = 0
            self._invalidate()

    async def _run_external(self, awaitable):
        """Suspend the full-screen app, run an external async flow, then resume."""
        # Prompt_toolkit's run_in_terminal lets us yield the terminal to a
        # non-app process. The 'in_executor=False' default suits async work.
        from prompt_toolkit.application.run_in_terminal import in_terminal
        result_holder = {}

        async def _runner():
            try:
                result_holder["v"] = await awaitable
            except Exception as exc:  # surface any exception
                result_holder["err"] = exc

        async with in_terminal():
            await _runner()
        if "err" in result_holder:
            self.last_status_line = f"error: {result_holder['err']}"
            return None
        return result_holder.get("v")

    # ── Scan kickoff ──────────────────────────────────────────────

    def _start_scan(self, target_dir: str) -> None:
        if self.mode == "scanning":
            self.last_status_line = "a scan is already in progress"
            return
        self.scan = ScanState(target=target_dir)
        self.mode = "scanning"
        self.active_tab = "trace"
        self.viewing_target = ""
        self._cancel_armed = False
        self.scan_task = asyncio.create_task(self._run_scan(target_dir))

    def _start_test_scan(self) -> None:
        if self.mode == "scanning":
            self.last_status_line = "a scan is already in progress"
            return
        self.scan = ScanState(target=os.getcwd() + " (test)")
        self.mode = "scanning"
        self.active_tab = "trace"
        self.viewing_target = ""
        self._cancel_armed = False
        self.scan_task = asyncio.create_task(self._run_test_scan())

    def _cancel_scan(self) -> None:
        if self.mode != "scanning":
            self.last_status_line = "no scan is running"
            return
        self.last_status_line = "cancelling…"
        if self.session:
            self.session.cancel()
        if self.scan_task and not self.scan_task.done():
            self.scan_task.cancel()

    def _pause_scan(self) -> None:
        if self.mode != "scanning" or self.session is None:
            self.last_status_line = "no scan is running"
            return
        if self.session.paused:
            self.last_status_line = "scan is already paused · /resume to continue"
            return
        self.session.pause()
        self.last_status_line = "scan paused · /resume to continue · /cancel to stop"
        self._invalidate()

    def _resume_scan(self) -> None:
        if self.mode != "scanning" or self.session is None:
            self.last_status_line = "no scan is running"
            return
        if not self.session.paused:
            self.last_status_line = "scan is not paused"
            return
        self.session.resume()
        self.last_status_line = "scan resumed"
        self._invalidate()

    def _on_trace(self, entry: TraceEntry) -> None:
        if self.scan is None:
            return
        self.scan.update_from_trace(entry)
        # Live-tick the elapsed clock by invalidating.
        self._invalidate()

    async def _run_scan(self, target_dir: str) -> None:
        reload_settings()
        session: Optional[Session] = None
        try:
            project_context = build_project_context(target_dir)
            session = Session(
                target_dir=target_dir,
                on_trace=self._on_trace,
                project_context=project_context,
            )
            self.session = session

            # Wrap on_trace to also persist on key milestones (step_complete,
            # finding_added) so a crashed scan still leaves a readable report.
            def _checkpoint(entry: TraceEntry) -> None:
                self._on_trace(entry)
                if entry.event_type in ("step_complete", "swarm_complete", "finding_added"):
                    self._write_report(session, target_dir, status="running")

            session._on_trace = _checkpoint  # type: ignore[attr-defined]

            # Wrap add_finding to bubble findings into ScanState + persist.
            original_add_finding = session.add_finding

            def _patched_add_finding(f: Finding) -> None:
                original_add_finding(f)
                if self.scan is not None:
                    self.scan.findings.append(f)
                self._write_report(session, target_dir, status="running")
                self._invalidate()

            session.add_finding = _patched_add_finding  # type: ignore[method-assign]

            # Write an initial 'running' report so /sessions sees it immediately.
            self._write_report(session, target_dir, status="running")

            tools = ToolRegistry(target_dir=Path(target_dir))
            llm = LLMClient(
                model=self.model, temperature=0.0, max_tokens=8192,
                provider=self.provider, prompt_cache_key=session.id,
            )
            coordinator = CoordinatorAgent(llm, tools, session)
            await coordinator.run_full_scan()

            self.last_session = session
            self.last_findings = list(session.findings)
            self._write_report(session, target_dir, status="completed")
            self.last_status_line = (
                f"scan complete · {len(session.findings)} findings · "
                f"${session.total_cost:.4f}"
            )

        except asyncio.CancelledError:
            if session is not None:
                self._write_report(session, target_dir, status="cancelled")
                self.last_status_line = (
                    f"scan cancelled · resume with: openhack resume {session.id}"
                )
            else:
                self.last_status_line = "scan cancelled"
            raise
        except Exception as exc:
            if session is not None:
                self._write_report(session, target_dir, status="failed")
                self.last_status_line = (
                    f"scan failed: {exc} · retry with: openhack resume {session.id}"
                )
            else:
                self.last_status_line = f"scan failed: {exc}"
        finally:
            if self.scan is not None:
                self.scan.finish()
            self.scan_task = None
            # On scan completion, jump from Trace → Findings so the user
            # lands on the results without having to switch tabs.
            self.active_tab = "findings"
            self.findings_selected = 0
            self._invalidate()

    def _write_report(
        self,
        session: Session,
        target_dir: str,
        status: Optional[str] = None,
    ) -> None:
        """Atomically write the scan report. Called incrementally during a scan
        (status='running') and at end (status='completed'/'cancelled'/'failed').
        """
        try:
            report_dir = Path.home() / ".openhack" / "scans"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"{session.id}.json"
            elapsed = time.time() - (self.scan.start_time if self.scan else session.created_at)

            # Serialize trace entries so the Trace tab can re-render later.
            def _trace_dict(e: TraceEntry) -> dict:
                tool_output = e.tool_output
                # Tool outputs can be enormous; cap so reports stay sane.
                if tool_output is not None and not isinstance(tool_output, (dict, list, int, float, bool)):
                    s = str(tool_output)
                    tool_output = s if len(s) <= 2000 else s[:2000] + "…"
                return {
                    "timestamp": e.timestamp,
                    "agent": e.agent,
                    "event_type": e.event_type,
                    "content": e.content,
                    "tool_name": e.tool_name,
                    "tool_input": e.tool_input,
                    "tool_output": tool_output,
                }

            report = {
                "version": 2,
                "scan_id": session.id,
                "target_dir": target_dir,
                "provider": self.provider,
                "model": self.model,
                "status": status or session.status.value,
                "pid": os.getpid(),
                "started_at": datetime.fromtimestamp(session.created_at).isoformat(),
                "duration_seconds": round(elapsed, 2),
                "cost": session.get_cost_breakdown(),
                "findings": [f.to_dict() for f in session.findings],
                "trace": [_trace_dict(e) for e in session.trace],
            }
            # Atomic write: temp file + rename to avoid corrupting on crash.
            tmp_path = report_path.with_suffix(".json.tmp")
            with open(tmp_path, "w") as fp:
                json.dump(report, fp, indent=2, default=str, ensure_ascii=False)
            os.replace(tmp_path, report_path)
        except Exception:
            pass

    async def _run_test_scan(self) -> None:
        import random
        from openhack.agents.session import Session as _S

        session = _S(target_dir=os.getcwd(), on_trace=self._on_trace)
        self.session = session

        # Hook live add_finding.
        original_add_finding = session.add_finding

        def _patched_add_finding(f: Finding) -> None:
            original_add_finding(f)
            if self.scan is not None:
                self.scan.findings.append(f)
            self._invalidate()

        session.add_finding = _patched_add_finding  # type: ignore[method-assign]

        def _d():
            return random.uniform(0.05, 0.25)

        try:
            session.add_trace("coordinator", "step_start", "Step 1: Reconnaissance")
            await asyncio.sleep(_d())
            for tool in ["get_project_info", "list_dir", "read_file", "get_route_map",
                         "check_dependencies", "grep", "find_dangerous_patterns"]:
                session.add_trace("recon", "tool_call", "",
                                  tool_name=tool, tool_input={"path": "src"})
                await asyncio.sleep(_d())
                session.add_trace("recon", "tool_result", "", tool_name=tool,
                                  tool_output={"ok": True})
            session.add_trace("coordinator", "step_complete",
                              {"step": "recon", "cost": 0.04, "tokens": 85000})

            groups = ["input_validation", "access_control", "data_handling"]
            session.add_trace("hunter_swarm", "swarm_start",
                              {"groups": groups, "group_count": len(groups)})
            for g in groups:
                a = f"hunter:{g}"
                for tool in ["read_file", "grep", "trace_variable"]:
                    session.add_trace(a, "tool_call", "",
                                      tool_name=tool, tool_input={"path": "src/lib/auth.ts"})
                    await asyncio.sleep(_d())
                    session.add_trace(a, "tool_result", "", tool_name=tool)

            findings = [
                ("IDOR", "critical", "src/app/dashboard/[id]/page.tsx",
                 "IDOR in workspace page — no ownership check"),
                ("SQL Injection", "critical", "src/lib/db.ts",
                 "SQL Injection via queryRawUnsafe"),
                ("XSS", "high", "src/components/note-card.tsx",
                 "Stored XSS via dangerouslySetInnerHTML"),
                ("Auth Bypass", "high", "src/app/api/users/route.ts",
                 "Missing auth check on user list endpoint"),
                ("Open Redirect", "medium", "src/app/api/auth/callback/route.ts",
                 "Unvalidated redirect URL in OAuth callback"),
            ]
            for cat, sev, fp, title in findings:
                session.add_finding(Finding(
                    category=cat, severity=sev, title=title,
                    description=title, file_path=fp,
                ))
                await asyncio.sleep(_d())

            session.add_trace("hunter_swarm", "swarm_complete",
                              {"total_findings": len(findings), "total_cost": 0.18})
            session.add_trace("coordinator", "step_complete",
                              {"step": "hunters", "cost": 0.18, "tokens": 320000})

            session.total_cost = 0.22
            session.status = SessionStatus.COMPLETED
            self.last_session = session
            self.last_findings = list(session.findings)
            self.last_status_line = (
                f"test scan complete · {len(session.findings)} findings"
            )
        except asyncio.CancelledError:
            self.last_status_line = "test scan cancelled"
            raise
        finally:
            if self.scan is not None:
                self.scan.finish()
            self.scan_task = None
            self.active_tab = "findings"
            self.findings_selected = 0
            self._invalidate()

    # ── Chat ──────────────────────────────────────────────────────

    async def _chat(self, user_message: str) -> None:
        self.chat_history.append(Message(role="user", content=user_message))
        reload_settings()
        try:
            llm = LLMClient(
                model=self.model, temperature=0.3, max_tokens=4096,
                provider=self.provider,
            )
        except Exception as exc:
            self.last_status_line = f"llm error: {exc}"
            self.chat_history.pop()
            return

        context_parts = [CHAT_SYSTEM_PROMPT]
        if self.last_session and self.last_session.findings:
            summary = []
            for i, f in enumerate(self.last_session.findings, 1):
                summary.append(
                    f"{i}. [{f.severity.upper()}] {f.category} - {f.title}"
                    + (f" ({f.file_path})" if f.file_path else "")
                )
            context_parts.append("\n\nCurrent scan findings:\n" + "\n".join(summary))

        self.last_status_line = "thinking…"
        self._invalidate()
        try:
            response: LLMResponse = await llm.chat(
                messages=self.chat_history, system="".join(context_parts),
            )
        except Exception as exc:
            self.last_status_line = f"llm error: {exc}"
            self.chat_history.pop()
            return

        reply = (response.content or "").strip() or "(no response)"
        self.chat_history.append(Message(role="assistant", content=reply))
        if len(self.chat_history) > 40:
            self.chat_history = self.chat_history[-30:]
        # Show the reply as a short status line; full reply truncated for
        # the status bar — better display will come in v2.
        self.last_status_line = reply if len(reply) <= 200 else reply[:197] + "…"

    # ── Run ───────────────────────────────────────────────────────

    async def run(self) -> None:
        # Tick the clock every second while scanning.
        async def _ticker():
            while True:
                await asyncio.sleep(1.0)
                if self.mode == "scanning":
                    self._invalidate()

        async def _check_updates():
            info = await fetch_updates()
            if info is None:
                return
            self._update_info = info
            self._invalidate()
            # If there are modal-placement announcements, queue the first one
            # as a modal dialog after a short delay (so it doesn't fight the
            # landing screen initial render).
            modal_anns = [a for a in info.announcements if "modal" in a.placement]
            if modal_anns:
                await asyncio.sleep(0.5)
                self._show_announcement_modal(modal_anns[0])

        tick_task = asyncio.create_task(_ticker())
        asyncio.create_task(_check_updates())
        try:
            await self.app.run_async()
        finally:
            tick_task.cancel()
            if self.scan_task and not self.scan_task.done():
                self.scan_task.cancel()
                try:
                    await self.scan_task
                except (asyncio.CancelledError, Exception):
                    pass


def _configure_logging() -> None:
    """Route all logging to a file so messages don't corrupt the full-screen UI.

    Anything that calls `logger.warning(...)` / `logger.error(..., exc_info=True)`
    (e.g. LLMClient retries, upstream errors) would otherwise hit stderr and
    overlap the layout. The log file lives at ~/.openhack/logs/openhack.log.
    """
    log_dir = Path.home() / ".openhack" / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    log_path = log_dir / "openhack.log"

    root = logging.getLogger()
    # Remove any existing StreamHandlers that would write to the terminal.
    for h in list(root.handlers):
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            root.removeHandler(h)
    # Add our file handler if not already there.
    have_file = any(
        isinstance(h, logging.FileHandler) and Path(getattr(h, "baseFilename", "")) == log_path
        for h in root.handlers
    )
    if not have_file:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(fh)
    if root.level == logging.NOTSET or root.level > logging.INFO:
        root.setLevel(logging.INFO)


def main():
    signal.signal(signal.SIGHUP, lambda *_: os._exit(1))
    signal.signal(signal.SIGTERM, lambda *_: os._exit(1))
    _configure_logging()

    app = OpenHackApp()
    try:
        asyncio.run(app.run())
    except KeyboardInterrupt:
        pass


# ── Back-compat aliases for existing imports ──────────────────────

OpenHackCLI = OpenHackApp  # legacy name used by __main__.py
