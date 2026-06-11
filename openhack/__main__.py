"""
Entry point for OpenHack.

Usage:
  openhack                          Launch interactive TUI
  openhack scan [path]              Scan a repository (headless, defaults to .)
  openhack sessions                 List all saved scan sessions
  openhack resume <id>              Resume a previous scan session
  openhack classify [path]          Classify frameworks and detect entry points
  openhack login                    Log in to your OpenHack account
  openhack setup                    Run the setup wizard
  openhack --help                   Show usage
"""

import sys


def _cmd_scan():
    """Run a headless scan on a directory."""
    from pathlib import Path

    target_arg = sys.argv[2] if len(sys.argv) > 2 else "."
    target = Path(target_arg).resolve()

    if not target.is_dir():
        print(f"Error: '{target_arg}' is not a directory.")
        print("Usage: openhack scan [path]")
        return

    from openhack.config import settings
    if not settings.openhack_api_key:
        print("Error: not logged in.")
        print("Run 'openhack login' to set up your account, or set OPENHACK_API_KEY.")
        return

    import asyncio
    from openhack.headless_scan import run_headless_scan
    try:
        asyncio.run(run_headless_scan(str(target)))
    except KeyboardInterrupt:
        print()
    except Exception:
        pass


def _cmd_sessions():
    """List all saved scan sessions."""
    import json
    from pathlib import Path

    scans_dir = Path.home() / ".openhack" / "scans"
    if not scans_dir.exists():
        print("\nNo saved scans yet.")
        return

    reports = []
    for p in sorted(scans_dir.glob("*.json"), reverse=True):
        try:
            data = json.loads(p.read_text())
            reports.append(data)
        except (OSError, json.JSONDecodeError):
            continue

    print(f"\nSaved scans: {len(reports)}")
    for r in reports:
        scan_id = (r.get("scan_id") or "?")[:8]
        target = r.get("target_dir", "?")
        status = r.get("status", "?")
        findings = r.get("findings", [])
        started = r.get("started_at", "")[:16]
        print(f"  {scan_id}  {target}  [{status}]  {len(findings)} findings  {started}")


def _cmd_resume():
    """Resume a previous scan session."""
    import json
    from pathlib import Path
    from openhack.agents.checkpoint import CheckpointManager

    session_id = sys.argv[2] if len(sys.argv) > 2 else None
    if not session_id:
        print("Usage: openhack resume <session_id>")
        return

    scans_dir = Path.home() / ".openhack" / "scans"
    report_path = scans_dir / f"{session_id}.json"
    if not report_path.exists():
        matches = list(scans_dir.glob(f"{session_id}*.json"))
        if matches:
            report_path = matches[0]

    if not report_path.exists():
        print(f"Session {session_id} not found in ~/.openhack/scans/")
        return

    try:
        report = json.loads(report_path.read_text())
    except (json.JSONDecodeError, OSError):
        print(f"Could not read session report: {report_path}")
        return

    target_dir = report.get("target_dir")
    if not target_dir or not Path(target_dir).is_dir():
        print(f"Target directory no longer exists: {target_dir}")
        return

    status = report.get("status", "")
    if status == "completed":
        findings = report.get("findings", [])
        print(f"Session {session_id} already completed ({len(findings)} findings).")
        return

    mgr = CheckpointManager(session_id)
    latest = mgr.get_latest_step()
    if latest:
        print(f"Resuming session {session_id} from checkpoint: {latest}")
    else:
        print(f"Resuming session {session_id} (no checkpoint — starting fresh)")

    from openhack.config import settings
    if not settings.openhack_api_key:
        print("Error: not logged in.")
        print("Run 'openhack login' to set up your account, or set OPENHACK_API_KEY.")
        return

    import asyncio
    from openhack.headless_scan import run_headless_scan
    try:
        asyncio.run(run_headless_scan(target_dir, resume_from_checkpoint=session_id))
    except KeyboardInterrupt:
        print()
    except Exception:
        pass


def _cmd_classify():
    """Classify frameworks and detect entry points."""
    from pathlib import Path
    from openhack.tools.registry import ToolRegistry
    from openhack.framework_classifier import classify_frameworks
    from openhack.entry_points import detect_entry_points
    from openhack.scan_session import ScanSession
    import uuid

    target = sys.argv[2] if len(sys.argv) > 2 else "."
    tools = ToolRegistry(target_dir=Path(target))

    print(f"\nClassifying {target}...\n")
    classifications = classify_frameworks(tools.fs_tools)
    for c in classifications:
        print(f"  {c['root']} → {c['language']} [{', '.join(c['frameworks'])}]")

    print(f"\nDetecting entry points...")
    entry_points = detect_entry_points(tools.fs_tools, classifications)
    print(f"  {len(entry_points)} entry points found\n")

    sid = str(uuid.uuid4())[:8]
    session = ScanSession(sid, target)
    session.classifications = classifications
    session.entry_points = entry_points
    session.save()
    print(f"  Session saved: {sid}")
    print(f"  Run 'openhack resume {sid}' to scan\n")


def _cmd_login():
    """Run the device login flow."""
    from openhack.setup import run_first_time_setup
    run_first_time_setup()


def _cmd_setup():
    """Run the setup wizard."""
    from openhack.setup import run_first_time_setup
    run_first_time_setup()


COMMANDS = {
    "scan": _cmd_scan,
    "sessions": _cmd_sessions,
    "resume": _cmd_resume,
    "classify": _cmd_classify,
    "login": _cmd_login,
    "setup": _cmd_setup,
}


def main():
    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd in ("--help", "-h", "help"):
            print(__doc__)
            return

        if cmd in ("--version", "-v", "version"):
            from openhack import __version__
            print(f"openhack {__version__}")
            return

        if cmd in COMMANDS:
            COMMANDS[cmd]()
            return

        print(f"Unknown command: {cmd}")
        print("Run 'openhack --help' for usage.")
        return

    # Default: launch TUI
    from openhack.setup import needs_first_time_setup, run_first_time_setup

    try:
        if needs_first_time_setup():
            completed = run_first_time_setup()
            if not completed:
                print("\nSetup skipped. Run 'openhack' again to retry.\n")
                return

        from openhack.tui import main as tui_main
        tui_main()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
