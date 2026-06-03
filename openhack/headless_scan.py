"""
Headless scan — runs the full pipeline without the TUI.

Uses the same coordinator pipeline as the TUI (recon → hunters →
feature deep dive → validation) with checkpoint support for resume.
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .agents.coordinator import CoordinatorAgent
from .agents.checkpoint import CheckpointManager
from .agents.llm import LLMClient
from .agents.session import Session, Finding, TraceEntry
from .tools.registry import ToolRegistry
from .config import reload_settings, settings
from .prompts.project_context import build_project_context

logger = logging.getLogger(__name__)

SCANS_DIR = Path.home() / ".openhack" / "scans"


def _on_trace(entry: TraceEntry):
    agent = entry.agent or "?"
    event = entry.event_type or ""
    if event == "tool_call":
        pass
    elif "finding" in event.lower():
        print(f"    [{agent}] FINDING: {entry.content}")
    elif event in ("status", "step_start", "step_complete", "resume"):
        snippet = str(entry.content or "")[:120]
        print(f"    [{agent}] {event}: {snippet}")


def _write_report(
    session: Session,
    target_dir: str,
    status: str,
    start_time: float,
) -> Path:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = SCANS_DIR / f"{session.id}.json"
    elapsed = time.time() - start_time

    report = {
        "version": 2,
        "scan_id": session.id,
        "target_dir": target_dir,
        "provider": settings.llm_provider,
        "status": status,
        "pid": os.getpid(),
        "started_at": datetime.fromtimestamp(start_time).isoformat(),
        "duration_seconds": round(elapsed, 2),
        "cost": session.get_cost_breakdown(),
        "findings": [f.to_dict() for f in session.findings],
    }

    tmp_path = report_path.with_suffix(".json.tmp")
    with open(tmp_path, "w") as fp:
        json.dump(report, fp, indent=2, default=str, ensure_ascii=False)
    tmp_path.rename(report_path)

    return report_path


async def run_headless_scan(
    target_dir: str,
    resume_from_checkpoint: Optional[str] = None,
):
    """Run a headless scan using the same coordinator pipeline as the TUI.

    If resume_from_checkpoint is a checkpoint step name (e.g. "recon",
    "hunter", "feature_hunt"), the coordinator skips completed steps.
    If it's a session ID, we look up the latest checkpoint for that session.
    """
    reload_settings()
    provider = settings.llm_provider
    start_time = time.time()

    print(f"\n{'='*60}")
    if resume_from_checkpoint:
        print(f"  RESUMING SCAN — {target_dir}")
    else:
        print(f"  SCANNING — {target_dir}")
    print(f"  Provider: {provider}")
    print(f"{'='*60}\n")

    # Resolve resume: if given a session ID, find its latest checkpoint
    resume_step = None
    reuse_id = None
    if resume_from_checkpoint:
        mgr = CheckpointManager(resume_from_checkpoint)
        latest = mgr.get_latest_step()
        if latest:
            reuse_id = resume_from_checkpoint
            resume_step = latest
            print(f"  Resuming from checkpoint: {latest}")
        elif resume_from_checkpoint in ("recon", "hunter", "feature_hunt"):
            resume_step = resume_from_checkpoint
        else:
            reuse_id = resume_from_checkpoint
            print(f"  No checkpoint found — starting fresh on same session")

    project_context = build_project_context(target_dir)
    session = Session(
        target_dir=target_dir,
        on_trace=_on_trace,
        project_context=project_context,
        scan_id=reuse_id,
    )
    tools = ToolRegistry(target_dir=Path(target_dir))

    if project_context and project_context.get("openhack_md"):
        print(f"  Loaded .openhack.md project context ({len(project_context['openhack_md'])} chars)")

    # Write initial report so --list-sessions shows a running scan
    _write_report(session, target_dir, "running", start_time)

    llm = LLMClient(
        provider=provider,
        temperature=0.0,
        max_tokens=8192,
        prompt_cache_key=session.id,
    )
    coordinator = CoordinatorAgent(
        llm, tools, session,
        resume_from=resume_step,
    )

    try:
        result = await coordinator.run_full_scan()

        # Print results
        findings = session.findings
        print(f"\n{'='*60}")
        print(f"  RESULTS")
        print(f"{'='*60}")

        if not findings:
            print("  No vulnerabilities confirmed.")
        else:
            print(f"  {len(findings)} vulnerability(ies) confirmed:\n")
            for i, f in enumerate(findings, 1):
                sev = f.severity.upper()
                print(f"  {i}. [{sev}] {f.category} — {f.file_path}")
                desc = f.description or ""
                if desc:
                    print(f"     {desc}")
                print()

        cost = session.get_cost_breakdown()
        elapsed = time.time() - start_time
        m, s = divmod(int(elapsed), 60)
        print(f"  Cost:     ${session.total_cost:.4f}")
        print(f"  Duration: {m}m {s:02d}s")

        report_path = _write_report(session, target_dir, "completed", start_time)
        print(f"  Report:   {report_path}")
        print(f"  Session:  {session.id}\n")

    except KeyboardInterrupt:
        print("\n  Scan interrupted.")
        _write_report(session, target_dir, "cancelled", start_time)
        mgr = CheckpointManager(session.id)
        if mgr.get_latest_step():
            print(f"  Resume from checkpoint: openhack --resume {session.id}")
        else:
            print(f"  Retry: openhack --resume {session.id}")
    except Exception as exc:
        logger.debug(f"Scan failed: {exc}", exc_info=True)
        _write_report(session, target_dir, "failed", start_time)
        print(f"\n  Scan failed: {exc}")
        print(f"  Retry: openhack --resume {session.id}")
