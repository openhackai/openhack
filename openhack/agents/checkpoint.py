"""
Intermediate state checkpointing for the scan pipeline.

Saves pipeline state after each major step so that a failed scan
can be resumed without re-running expensive earlier stages.
"""

import json
import logging
import shutil
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

CHECKPOINT_BASE_DIR = Path.home() / ".openhack" / "checkpoints"

STEP_ORDER = ["recon", "hunter", "static_validation"]


class CheckpointManager:
    """Manages checkpoint files for a single scan session."""

    def __init__(self, session_id: str, base_dir: Optional[Path] = None):
        self.session_id = session_id
        self.checkpoint_dir = (base_dir or CHECKPOINT_BASE_DIR) / session_id

    def save(self, step_name: str, data: dict) -> None:
        """Save a checkpoint after a pipeline step completes."""
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        checkpoint = {
            "step": step_name,
            "session_id": self.session_id,
            "timestamp": time.time(),
            "data": data,
        }
        path = self.checkpoint_dir / f"{step_name}.json"
        path.write_text(json.dumps(checkpoint, indent=2, default=str))
        print(f"    Checkpoint saved: {step_name} — resume with: openhack --resume {self.session_id}")
        logger.info(f"Checkpoint saved: {step_name} -> {path}")

    def load(self, step_name: str) -> Optional[dict]:
        """Load a checkpoint for a given step. Returns None if not found."""
        path = self.checkpoint_dir / f"{step_name}.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load checkpoint {path}: {e}")
            return None

    def get_latest_step(self) -> Optional[str]:
        """Find the most advanced completed step by checking which checkpoint files exist."""
        latest = None
        for step in STEP_ORDER:
            if (self.checkpoint_dir / f"{step}.json").exists():
                latest = step
        return latest

    def cleanup(self) -> None:
        """Remove all checkpoints for this session (called on successful completion)."""
        if self.checkpoint_dir.exists():
            shutil.rmtree(self.checkpoint_dir, ignore_errors=True)
            logger.info(f"Checkpoints cleaned up for session {self.session_id}")

    @classmethod
    def list_resumable_sessions(cls, base_dir: Optional[Path] = None) -> list[dict]:
        """List all sessions that have checkpoints available for resume."""
        root = base_dir or CHECKPOINT_BASE_DIR
        sessions = []
        if not root.exists():
            return sessions
        for session_dir in sorted(root.iterdir()):
            if session_dir.is_dir():
                mgr = cls(session_dir.name, base_dir=root)
                latest = mgr.get_latest_step()
                if latest:
                    # Read timestamp from the latest checkpoint
                    checkpoint = mgr.load(latest)
                    ts = checkpoint.get("timestamp") if checkpoint else None
                    sessions.append({
                        "session_id": session_dir.name,
                        "latest_step": latest,
                        "timestamp": ts,
                        "checkpoint_dir": str(session_dir),
                    })
        return sessions
