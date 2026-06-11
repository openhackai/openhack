"""
Interactive configuration wizard for OpenHack.

Two entry points:
  - run_first_time_setup()  — auto-launched when ~/.openhack/config is absent
  - run_setup_command()     — triggered by /setup inside the TUI (async)

Uses prompt_toolkit for arrow-key driven selection menus, secure password
input for API keys, and a final confirmation screen.
"""

import asyncio
import os
from typing import Optional

from prompt_toolkit import print_formatted_text
from prompt_toolkit.shortcuts import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.application import Application
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.layout import Layout

from openhack.auth import (
    DeviceLoginCancelled,
    DeviceLoginError,
    DeviceLoginExpired,
    device_login,
)
from openhack.config import (
    CONFIG_PATH,
    load_user_config,
    save_user_config,
    resolve_provider,
    reload_settings,
    settings,
)

DIM = '<style fg="ansigray">'
EDIM = '</style>'
B = '<b>'
EB = '</b>'
CYAN = '<ansicyan>'
ECYAN = '</ansicyan>'
GREEN = '<ansigreen>'
EGREEN = '</ansigreen>'
YELLOW = '<ansiyellow>'
EYELLOW = '</ansiyellow>'


def _html(text: str) -> None:
    print_formatted_text(HTML(text))


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _clear() -> None:
    print("\033[2J\033[H", end="", flush=True)


# ── Provider / model definitions ──────────────────────────────────

PROVIDERS = [
    {
        "key": "openhack",
        "display": "OpenHack",
        "hint": "Recommended — no setup required, free tier available",
        "key_field": "openhack_api_key",
        "key_env": "OPENHACK_API_KEY",
        # key_url is built dynamically from settings.openhack_app_url at display time.
        "models": [
            ("kimi-k2.5", "Kimi K2.5", "Flagship security analysis model"),
        ],
        "default_model": "kimi-k2.5",
    },
]


def _mask_key(key: str) -> str:
    if not key:
        return "(not set)"
    if len(key) <= 12:
        return key[:2] + "•" * (len(key) - 2)
    return key[:6] + "•" * 8 + key[-4:]

def _has_running_loop() -> bool:
    try:
        loop = asyncio.get_running_loop()
        return loop.is_running()
    except RuntimeError:
        return False


async def _input_async(message: str, is_password: bool = False) -> str:
    """Async text input with full editing keybindings (word jump/delete)."""
    session: PromptSession = PromptSession()
    return await session.prompt_async(message, is_password=is_password)


# ── Arrow-key selection menu ──────────────────────────────────────

async def _select_menu_async(title: str, items: list[tuple[str, str, str]], default_idx: int = 0) -> int:
    """Render an arrow-key driven selection menu. Returns the chosen index.

    items: list of (value, label, hint)
    """
    selected = [default_idx]

    def _get_text():
        lines = []
        lines.append(("class:title", f"  {title}\n\n"))
        for i, (_, label, hint) in enumerate(items):
            if i == selected[0]:
                lines.append(("class:selected", f"  ❯ {label}"))
                if hint:
                    lines.append(("class:hint.selected", f"  {hint}"))
                lines.append(("", "\n"))
            else:
                lines.append(("class:unselected", f"    {label}"))
                if hint:
                    lines.append(("class:hint", f"  {hint}"))
                lines.append(("", "\n"))
        lines.append(("class:footer", "\n  ↑/↓ to move · Enter to select · q to cancel"))
        return lines

    kb = KeyBindings()
    result = [None]

    @kb.add("up")
    @kb.add("k")
    def _up(event):
        selected[0] = (selected[0] - 1) % len(items)

    @kb.add("down")
    @kb.add("j")
    def _down(event):
        selected[0] = (selected[0] + 1) % len(items)

    @kb.add("enter")
    def _enter(event):
        result[0] = selected[0]
        event.app.exit()

    @kb.add("q")
    @kb.add("escape")
    def _quit(event):
        result[0] = -1
        event.app.exit()

    from prompt_toolkit.styles import Style
    style = Style.from_dict({
        "title": "bold",
        "selected": "bold ansibrightcyan",
        "hint.selected": "ansigray",
        "unselected": "",
        "hint": "ansigray",
        "footer": "ansigray italic",
    })

    control = FormattedTextControl(_get_text)
    window = Window(content=control, always_hide_cursor=True)
    layout = Layout(HSplit([window]))
    app = Application(layout=layout, key_bindings=kb, style=style, full_screen=False)
    await app.run_async()

    return result[0] if result[0] is not None else -1


def _select_menu(title: str, items: list[tuple[str, str, str]], default_idx: int = 0) -> int:
    """Sync wrapper — delegates to async impl."""
    if _has_running_loop():
        raise RuntimeError("Use _select_menu_async from within an event loop")

    return asyncio.run(_select_menu_async(title, items, default_idx))


# ── API key input ─────────────────────────────────────────────────

async def _prompt_api_key(provider: dict, existing_key: Optional[str] = None) -> Optional[str]:
    """Prompt for an API key with masked display."""
    _html("")
    _html(f'  {B}API Key for {_esc(provider["display"])}{EB}')
    key_url = f"{settings.openhack_app_url.rstrip('/')}/settings/api-keys"
    _html(f'  {DIM}Get your key at: {_esc(key_url)}{EDIM}')
    _html("")

    if existing_key:
        _html(f'  {DIM}Current: {_esc(_mask_key(existing_key))}{EDIM}')
        _html(f'  {DIM}Press Enter to keep existing key, or paste a new one{EDIM}')
        _html("")

    env_val = os.environ.get(provider["key_env"])
    if env_val:
        _html(f'  {DIM}Found in environment: ${_esc(provider["key_env"])} = {_esc(_mask_key(env_val))}{EDIM}')
        _html(f'  {DIM}Press Enter to use environment value{EDIM}')
        _html("")

    try:
        key = (await _input_async("  API Key: ", is_password=True)).strip()
    except (EOFError, KeyboardInterrupt):
        return existing_key

    if not key:
        if existing_key:
            return existing_key
        if env_val:
            return env_val
        return None

    return key


# ── Base URL input (for OpenHack provider) ───────────────────────────

async def _prompt_base_url(existing: Optional[str] = None) -> str:
    if not existing:
        existing = settings.openhack_base_url
    _html("")
    _html(f'  {B}OpenHack Base URL{EB}')
    _html(f'  {DIM}Default: {_esc(existing)}{EDIM}')
    _html(f'  {DIM}Press Enter to keep default{EDIM}')
    _html("")
    try:
        url = (await _input_async("  Base URL: ")).strip()
    except (EOFError, KeyboardInterrupt):
        return existing
    return url if url else existing


# ── Summary / confirmation ────────────────────────────────────────

async def _show_summary(provider: dict, model_id: str, api_key: Optional[str], base_url: Optional[str] = None, org_name: Optional[str] = None) -> bool:
    _html("")
    _html(f'  {"━" * 50}')
    _html(f'  {B}Configuration Summary{EB}')
    _html(f'  {"━" * 50}')
    _html("")
    _html(f'  {B}Provider:{EB}  {_esc(provider["display"])}')
    if org_name:
        _html(f'  {B}Org:{EB}       {_esc(org_name)}')
    _html(f'  {B}Model:{EB}     {_esc(model_id)}')
    _html(f'  {B}API Key:{EB}   {_esc(_mask_key(api_key or ""))}')
    if base_url and provider["key"] == "openhack":
        _html(f'  {B}Base URL:{EB}  {_esc(base_url)}')
    _html("")
    _html(f'  {DIM}Config will be saved to {_esc(str(CONFIG_PATH))}{EDIM}')
    _html("")

    try:
        confirm = (await _input_async("  Save this configuration? [Y/n] ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False

    return confirm in ("", "y", "yes")


# ── First-time setup wizard ──────────────────────────────────────

def _banner() -> None:
    _html("")
    _html(f'  <b><ansibrightwhite>            ██</ansibrightwhite></b>')
    _html(f'  <b><ansibrightwhite>            ██</ansibrightwhite></b>')
    _html(f'  <b><ansibrightwhite>            ██</ansibrightwhite></b>')
    _html(f'  <b><ansibrightwhite>     ████████████████</ansibrightwhite></b>')
    _html("")
    _html(f'  <b><ansibrightwhite>       ████████████</ansibrightwhite></b>')
    _html("")
    _html(f'  <b><ansibrightwhite>         ████████</ansibrightwhite></b>')
    _html("")
    _html(f'  <b><ansicyan>  OpenHack</ansicyan></b> — First Time Setup')
    _html("")
    _html(f'  {DIM}Welcome to OpenHack! Let\'s get started with setup.{EDIM}')
    _html("")


def _setup_banner() -> None:
    _html("")
    _html(f'  <b><ansibrightwhite>            ██</ansibrightwhite></b>')
    _html(f'  <b><ansibrightwhite>            ██</ansibrightwhite></b>')
    _html(f'  <b><ansibrightwhite>            ██</ansibrightwhite></b>')
    _html(f'  <b><ansibrightwhite>     ████████████████</ansibrightwhite></b>')
    _html("")
    _html(f'  <b><ansibrightwhite>       ████████████</ansibrightwhite></b>')
    _html("")
    _html(f'  <b><ansibrightwhite>         ████████</ansibrightwhite></b>')
    _html("")
    _html(f'  <b><ansicyan>  OpenHack</ansicyan></b> — Configuration')
    _html("")
    _html(f'  {DIM}Update your settings and API key.{EDIM}')
    _html("")


async def _run_wizard(is_first_time: bool = True) -> bool:
    """Run the interactive configuration wizard. Returns True if config was saved."""
    cfg = load_user_config()

    if is_first_time:
        _banner()
    else:
        _setup_banner()

    provider = PROVIDERS[0]
    default_model = provider["default_model"]
    default_base_url = cfg.get("openhack_base_url") or settings.openhack_base_url

    # ── Step 1: Login / API key / Custom ─────────────────────────
    setup_choice = await _select_menu_async(
        "How would you like to proceed?",
        [
            ("login", "Login with OpenHack account", "(Recommended, free $20 credits on signup)"),
            ("apikey", "Use OpenHack API Key", ""),
            ("custom", "Custom setup", ""),
        ],
    )
    if setup_choice < 0:
        _html(f'  {DIM}Setup cancelled.{EDIM}')
        _html("")
        return False

    api_key: Optional[str] = None
    model_id = default_model
    base_url = default_base_url
    login_result = None

    if setup_choice == 0:
        # Browser-based device-code login.
        app_url = cfg.get("openhack_app_url") or settings.openhack_app_url
        try:
            login_result = await device_login(app_url)
            api_key = login_result.token
        except DeviceLoginCancelled:
            _html(f'  {DIM}Login cancelled.{EDIM}')
            _html("")
            return False
        except DeviceLoginExpired as exc:
            _html(f'  {YELLOW}⚠{EYELLOW}  {_esc(str(exc))}')
            _html("")
            return False
        except DeviceLoginError as exc:
            _html(f'  {YELLOW}⚠{EYELLOW}  Login failed: {_esc(str(exc))}')
            _html("")
            return False
    elif setup_choice == 1:
        # User pastes an existing OpenHack API token from the dashboard.
        existing_key = cfg.get(provider["key_field"])
        api_key = await _prompt_api_key(provider, existing_key)
        if not api_key:
            _html("")
            _html(f'  {YELLOW}⚠{EYELLOW}  An API key is required.')
            _html(f'  {DIM}Sign up at: {_esc(settings.openhack_app_url)}/signup{EDIM}')
            _html("")
    else:
        # Custom: base URL, API key, model string.
        _html("")
        _html(f'  {B}OpenAI-Compatible API Endpoint{EB}')
        existing_base = cfg.get("openhack_base_url") or default_base_url
        _html(f'  {DIM}Current: {_esc(existing_base)}{EDIM}')
        _html(f'  {DIM}Press Enter to keep current{EDIM}')
        _html("")
        try:
            url_input = (await _input_async("  Base URL: ")).strip()
        except (EOFError, KeyboardInterrupt):
            _html(f'  {DIM}Setup cancelled.{EDIM}')
            _html("")
            return False
        base_url = url_input if url_input else existing_base

        existing_key = cfg.get(provider["key_field"])
        api_key = await _prompt_api_key(provider, existing_key)
        if not api_key:
            _html("")
            _html(f'  {YELLOW}⚠{EYELLOW}  An API key is required.')
            _html("")

        _html("")
        _html(f'  {B}Model{EB}')
        existing_model = cfg.get("model") or cfg.get("openhack_model_id") or default_model
        _html(f'  {DIM}Current: {_esc(existing_model)}{EDIM}')
        _html(f'  {DIM}Press Enter to keep current{EDIM}')
        _html("")
        try:
            model_input = (await _input_async("  Model: ")).strip()
        except (EOFError, KeyboardInterrupt):
            _html(f'  {DIM}Setup cancelled.{EDIM}')
            _html("")
            return False
        model_id = model_input if model_input else existing_model

    # ── Step 3: Summary & confirm ─────────────────────────────────
    org_name = login_result.org_name if login_result else None
    if not await _show_summary(provider, model_id, api_key, base_url, org_name):
        _html(f'  {DIM}Setup cancelled. No changes saved.{EDIM}')
        _html("")
        return False

    # ── Save ──────────────────────────────────────────────────────
    new_cfg = {
        "provider": "openhack",
        "model": model_id,
        "openhack_model_id": model_id,
    }
    # Only persist base_url if the user explicitly customized it. Otherwise
    # leave it out so the dev/prod default (driven by OPENHACK_DEV) wins.
    if setup_choice == 2 and base_url and base_url != settings.openhack_base_url:
        new_cfg["openhack_base_url"] = base_url
    if api_key:
        new_cfg["openhack_api_key"] = api_key
    if login_result:
        if login_result.org_id:
            new_cfg["openhack_org_id"] = login_result.org_id
        if login_result.org_slug:
            new_cfg["openhack_org_slug"] = login_result.org_slug
        if login_result.org_name:
            new_cfg["openhack_org_name"] = login_result.org_name
        if login_result.user_email:
            new_cfg["openhack_user_email"] = login_result.user_email
        if login_result.user_first_name:
            new_cfg["openhack_user_first_name"] = login_result.user_first_name
        if login_result.user_last_name:
            new_cfg["openhack_user_last_name"] = login_result.user_last_name

    save_user_config(new_cfg)
    reload_settings()

    _html("")
    _html(f'  {GREEN}✓{EGREEN} {B}Configuration saved!{EB}')
    _html(f'  {DIM}Stored in {_esc(str(CONFIG_PATH))}{EDIM}')
    _html("")

    return True


def needs_first_time_setup() -> bool:
    """Check if this is a first-time run (no config file exists)."""
    if not CONFIG_PATH.exists():
        return True
    cfg = load_user_config()
    if not cfg:
        return True
    has_provider = cfg.get("provider")
    if not has_provider:
        return True
    # All providers now require an API key
    has_any_key = any(
        cfg.get(p["key_field"])
        for p in PROVIDERS
    )
    return not has_any_key


def run_first_time_setup() -> bool:
    """Run the first-time setup wizard. Returns True if setup completed."""
    return asyncio.run(_run_wizard(is_first_time=True))


async def run_setup_command() -> bool:
    """Run the /setup configuration wizard (async, for use inside TUI). Returns True if config was saved."""
    return await _run_wizard(is_first_time=False)
