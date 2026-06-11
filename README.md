# ⏚ [OpenHack](https://openhack.com)

**Open Source Agentic Security Scanner & Verifier for your codebase.**

Like Claude Code Security / Codex Security but open source and **exclusively uses open source models**.

<p align="center">
  <a href="https://openhack.com"><img src="https://img.shields.io/badge/Website-openhack.com-0969da?style=for-the-badge" alt="Website"></a>
  &nbsp;
  <a href="https://openhack.com/discord"><img src="https://img.shields.io/badge/Discord-Join_Server-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  &nbsp;
  <a href="https://x.com/openhackai"><img src="https://img.shields.io/badge/X-@openhackai-000000?style=for-the-badge&logo=x&logoColor=white" alt="Follow on X"></a>
</p>

<p align="center">
  <a href="https://pypi.org/project/openhack/"><img src="https://img.shields.io/pypi/v/openhack?style=for-the-badge&label=pypi&color=3775A9" alt="PyPI"></a>
  &nbsp;
  <a href="https://github.com/openhackai/openhack/blob/main/LICENSE"><img src="https://img.shields.io/github/license/openhackai/openhack?style=for-the-badge" alt="License"></a>
</p>

## Get started

```bash
pipx install openhack
```

Or with pip:

```bash
pip install openhack
```

## How it works
OpenHack does `recon` -> `hunting` -> `validation` -> `verification` all in one pipeline to find high quality verified vulnerabilities.

**Recon**: Does a deep dive and fully understands your application along with any custom context you give it. Builds a full project model before hunting begins.

**Hunter**: Specialized category based hunters get to finding vulnerabilities initially, along with feature based hunters divind deep to find vulnerabilities in risky code areas.

**Validation**: Validation agent performs a review of the finding and it's impact and whether it's even valid.

**Verification**: Verification agent performs a full browser + sandbox based attack to find verify vulnerabilities in a real docker / DOM environment.


## Quick start

```bash
openhack
```

On first run you'll go through a one-time setup:

1. Pick **Login with OpenHack account** (recommended) — opens a browser, you log in, get **$20 in free credits**, and the CLI gets a token automatically.
2. Type `/scan .` to scan the current directory, or `/scan path/to/repo` for somewhere else.
3. While scanning, the **Trace tab** shows live agent activity (recon → hunters → validators). When the scan finishes, the **Findings tab** shows everything that was found.

## What it does

OpenHack runs a multi-agent pipeline against your codebase:

- **Recon** — reads the code, builds a project model
- **Hunters** — multiple specialized agents look for different vulnerability classes (input validation, access control, data handling, …)
- **Feature hunters** — deeper passes on specific risk categories (XSS rendering, raw SQL, command exec, etc.)
- **Validators** — re-read the suspect code to confirm or reject each candidate finding
- **Sandbox verification** (`/verify sandbox`) *(Beta — requires Docker)* — spins up your app in a Docker container and attempts to exploit each finding with live HTTP requests. Findings that are successfully exploited get a ✓ mark.
- **Browser verification** (`/verify browser`) *(Beta — requires Docker when combined with sandbox)* — launches a headless browser against the sandboxed app to verify client-side vulnerabilities (XSS, CSRF, DOM-based issues) with real browser execution.

> **Docker prerequisite.** Sandbox verification requires Docker Desktop (or any working Docker daemon) installed and running on the machine where the scan runs. Browser verification inherits this when used with sandbox. If Docker isn't running, `/verify sandbox` will fail with a clear error before the scan starts.

For every confirmed finding you get: severity, CVSS score, file location, full description, the vulnerable code snippet, and a recommended fix — all rendered with syntax highlighting in the TUI.

## Slash commands


| Command                    | Description                                                                                        |
| -------------------------- | -------------------------------------------------------------------------------------------------- |
| `/scan <path>`             | Full scan on a directory (defaults to current dir)                                                 |
| `/pause` · `/resume`       | Pause and resume a running scan (Ctrl+C also pauses)                                               |
| `/cancel`                  | Permanently cancel a running scan                                                                  |
| `/sessions`                | Browse and re-load past scans (also supports re-running an aborted scan with `r`)                  |
| `/findings`                | Re-display findings from last scan                                                                 |
| `/copy`                    | Copy the selected finding (description + vulnerable code + fix) for Codex / Claude Code / OpenCode |
| `/verify sandbox` *(Beta)* | Spin up a Docker sandbox and exploit-test each finding with live requests                          |
| `/verify browser` *(Beta)* | Launch a headless browser to verify client-side vulns (XSS, CSRF, etc.)                            |
| `/login`                   | Re-login to your OpenHack account                                                                  |
| `/setup`                   | Run the setup wizard again                                                                         |
| `/config`                  | Show current config; `/config <key> <value>` to set                                                |
| `/sidebar`                 | Show/hide the Findings list sidebar (`Ctrl+B`)                                                     |
| `/cost`                    | Cost breakdown for the last scan                                                                   |
| `/clear`                   | Clear scan state and return to landing                                                             |
| `/discord`                 | Open the OpenHack Discord                                                                          |
| `/mouse`                   | Toggle mouse capture (off = native text selection)                                                 |
| `/help`                    | List commands                                                                                      |
| `/quit`                    | Exit                                                                                               |


## Keyboard shortcuts (Findings tab)

- `↑` / `↓` — switch finding
- `[` · `]` — alternate prev / next
- Mouse wheel or `PgUp` / `PgDn` — scroll the details pane
- `y` — yank (copy) selected finding for an AI agent
- `<` · `>` — resize the sidebar
- `Ctrl+B` — toggle sidebar

## Keyboard shortcuts (Trace tab)

- `↑` / `↓` — switch agent in the sidebar tree
- `[` · `]` — alternate prev / next agent
- Mouse wheel or `PgUp` / `PgDn` — scroll the trace
- `Home` — jump to "All" (full trace)
- `End` — resume auto-follow-to-bottom

## Selecting text

The TUI captures mouse events by default (for scrolling and clicking). To select and copy text natively:

- **macOS**: Hold `Option` (⌥) and drag to select, then `Cmd+C` to copy.
- **Linux / Windows**: Hold `Shift` and drag to select.
- **Or**: Run `/mouse` to disable mouse capture entirely — the terminal's native selection works normally until you toggle it back on.

## CLI commands (headless)

For CI, scripts, or one-off scans where you don't want the TUI:

```bash
openhack scan /path/to/repo
```

OpenHack runs the same pipeline as the TUI, prints progress to stdout, writes a JSON report to `~/.openhack/scans/<session-id>.json`, and exits.


| Command                    | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| `openhack`                 | Launch interactive TUI                                   |
| `openhack scan [path]`     | Full scan, headless (defaults to `.`)                    |
| `openhack sessions`        | List all saved scans                                     |
| `openhack resume <id>`     | Resume a scan from its last checkpoint                   |
| `openhack classify [path]` | Classify frameworks + detect entry points (no LLM calls) |
| `openhack login`           | Log in to your OpenHack account                          |
| `openhack setup`           | Run the setup wizard                                     |
| `openhack --help`          | Show usage                                               |


Scans are checkpointed after each pipeline stage. If a scan is interrupted or fails, resume it:

```bash
openhack resume <session-id>
```

## Configuration

Configuration is stored in `~/.openhack/config` (mode `0600` since it contains a bearer token) and persists across sessions.

You can override at runtime via environment variables:


| Variable            | Effect                                                                                                                                 |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `OPENHACK_API_KEY`  | Bearer token for the OpenHack inference API                                                                                            |
| `OPENHACK_DEV=1`    | Point the CLI at local dev servers (app on `:9080`, inference on `:8787`) for self-hosted setups                                       |
| `PROMPT_CACHING=0`  | Stop sending `prompt_cache_key` with API calls — needed for OpenAI-compatible endpoints that reject it (also: `/config prompt_caching false`) |


## Privacy

OpenHack reads and processes your source code **locally** — prompts are built on your machine. Only LLM tokens (not raw source files) are forwarded to the OpenHack inference API. No source code is uploaded or retained.

## Contributing

OpenHack is open source. Issues and PRs welcome on [GitHub](https://github.com/openhackai/openhack).

## License

MIT — see [LICENSE](LICENSE).
