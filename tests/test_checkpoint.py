import json
import time
from pathlib import Path

from openhack.agents.checkpoint import CheckpointManager


class TestCheckpointSaveLoad:
    def test_save_and_load(self, tmp_path):
        mgr = CheckpointManager("sess-001", base_dir=tmp_path)
        data = {"context": {"recon": {"summary": "found stuff"}}, "total_cost": 0.05}
        mgr.save("recon", data)

        loaded = mgr.load("recon")
        assert loaded is not None
        assert loaded["step"] == "recon"
        assert loaded["session_id"] == "sess-001"
        assert loaded["data"]["total_cost"] == 0.05
        assert loaded["data"]["context"]["recon"]["summary"] == "found stuff"

    def test_load_nonexistent(self, tmp_path):
        mgr = CheckpointManager("sess-002", base_dir=tmp_path)
        assert mgr.load("recon") is None

    def test_overwrite_checkpoint(self, tmp_path):
        mgr = CheckpointManager("sess-003", base_dir=tmp_path)
        mgr.save("recon", {"total_cost": 0.01})
        mgr.save("recon", {"total_cost": 0.99})

        loaded = mgr.load("recon")
        assert loaded["data"]["total_cost"] == 0.99


class TestCheckpointStepOrder:
    def test_get_latest_step_single(self, tmp_path):
        mgr = CheckpointManager("sess-010", base_dir=tmp_path)
        mgr.save("recon", {"step": 1})
        assert mgr.get_latest_step() == "recon"

    def test_get_latest_step_progression(self, tmp_path):
        mgr = CheckpointManager("sess-011", base_dir=tmp_path)
        mgr.save("recon", {"step": 1})
        mgr.save("hunter", {"step": 2})
        assert mgr.get_latest_step() == "hunter"

    def test_get_latest_step_full(self, tmp_path):
        mgr = CheckpointManager("sess-012", base_dir=tmp_path)
        mgr.save("recon", {"step": 1})
        mgr.save("hunter", {"step": 2})
        mgr.save("static_validation", {"step": 3})
        assert mgr.get_latest_step() == "static_validation"

    def test_get_latest_step_empty(self, tmp_path):
        mgr = CheckpointManager("sess-013", base_dir=tmp_path)
        assert mgr.get_latest_step() is None


class TestCheckpointCleanup:
    def test_cleanup_removes_dir(self, tmp_path):
        mgr = CheckpointManager("sess-020", base_dir=tmp_path)
        mgr.save("recon", {"data": "x"})
        mgr.save("hunter", {"data": "y"})

        assert mgr.checkpoint_dir.exists()
        mgr.cleanup()
        assert not mgr.checkpoint_dir.exists()

    def test_cleanup_nonexistent_is_safe(self, tmp_path):
        mgr = CheckpointManager("sess-021", base_dir=tmp_path)
        mgr.cleanup()  # should not raise


class TestListResumable:
    def test_lists_sessions_with_checkpoints(self, tmp_path):
        mgr1 = CheckpointManager("sess-030", base_dir=tmp_path)
        mgr1.save("recon", {"cost": 0.01})

        mgr2 = CheckpointManager("sess-031", base_dir=tmp_path)
        mgr2.save("recon", {"cost": 0.02})
        mgr2.save("hunter", {"cost": 0.05})

        sessions = CheckpointManager.list_resumable_sessions(base_dir=tmp_path)
        assert len(sessions) == 2

        by_id = {s["session_id"]: s for s in sessions}
        assert by_id["sess-030"]["latest_step"] == "recon"
        assert by_id["sess-031"]["latest_step"] == "hunter"

    def test_empty_dir(self, tmp_path):
        sessions = CheckpointManager.list_resumable_sessions(base_dir=tmp_path)
        assert sessions == []

    def test_nonexistent_dir(self, tmp_path):
        sessions = CheckpointManager.list_resumable_sessions(base_dir=tmp_path / "nope")
        assert sessions == []


class TestResumeFlow:
    """Test the checkpoint data roundtrip that coordinator uses."""

    def test_checkpoint_data_preserves_findings(self, tmp_path):
        mgr = CheckpointManager("sess-040", base_dir=tmp_path)

        findings = [
            {"category": "SQL Injection", "severity": "critical", "file_path": "db.py"},
            {"category": "XSS", "severity": "medium", "file_path": "view.py"},
        ]
        checkpoint_data = {
            "context": {"recon": {"summary": "Express app"}},
            "total_cost": 0.12,
            "total_tokens": 5000,
            "total_input_tokens": 3000,
            "total_output_tokens": 2000,
            "potential_findings": findings,
            "all_files_analyzed": ["db.py", "view.py", "auth.py"],
            "step_costs": {"recon": 0.02, "hunter": 0.10},
            "step_tokens": {"recon": 1000, "hunter": 4000},
        }

        mgr.save("hunter", checkpoint_data)
        loaded = mgr.load("hunter")

        assert loaded["data"]["potential_findings"] == findings
        assert loaded["data"]["total_cost"] == 0.12
        assert loaded["data"]["all_files_analyzed"] == ["db.py", "view.py", "auth.py"]
        assert loaded["data"]["step_costs"]["recon"] == 0.02
