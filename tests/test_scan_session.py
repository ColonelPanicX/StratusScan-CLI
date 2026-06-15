"""
Tests for scan session persistence (utils.py SCAN SESSION TRACKING section).
"""

import json
import time
from pathlib import Path

import pytest

# Ensure project root is importable
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import utils


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def patch_output_dir(tmp_path, monkeypatch):
    """Redirect get_output_dir() to a temp directory for every test."""
    monkeypatch.setattr(utils, "get_output_dir", lambda: tmp_path)
    yield tmp_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _session_file(session: dict) -> Path:
    return Path(session["_path"])


def _read_session_file(session: dict) -> dict:
    return json.loads(_session_file(session).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestStartScanSession:
    def test_creates_file(self, tmp_path):
        session = utils.start_scan_session(
            scan_type="org-scan",
            label="Test Run",
            planned=[{"key": "111111111111", "account_id": "111111111111"}],
        )
        assert _session_file(session).exists(), "Session file should be created on disk"

    def test_correct_fields(self, tmp_path):
        planned = [{"key": "abc", "script": "ec2_export.py"}]
        session = utils.start_scan_session("smart-scan", "My Label", planned)

        data = _read_session_file(session)
        assert data["scan_type"] == "smart-scan"
        assert data["label"] == "My Label"
        assert data["status"] == "running"
        assert data["completed_at"] is None
        assert data["planned"] == planned
        assert data["results"] == []
        assert "session_id" in data
        assert "started_at" in data

    def test_path_not_written_to_file(self, tmp_path):
        """Internal _path key must not leak into the JSON file."""
        session = utils.start_scan_session("org-scan", "L", [{"key": "k"}])
        data = _read_session_file(session)
        assert "_path" not in data


class TestRecordScanResult:
    def test_appends_result(self, tmp_path):
        session = utils.start_scan_session("org-scan", "L", [
            {"key": "111"},
            {"key": "222"},
        ])
        utils.record_scan_result(session, "111", "success", 0, 12.3, account_id="111")
        utils.record_scan_result(session, "222", "failed", 1, 7.0, account_id="222")

        data = _read_session_file(session)
        assert len(data["results"]) == 2

    def test_result_fields(self, tmp_path):
        session = utils.start_scan_session("org-scan", "L", [{"key": "999"}])
        utils.record_scan_result(
            session, "999", "success", 0, 45.678,
            account_name="Prod", script="ec2_export.py",
        )

        data = _read_session_file(session)
        r = data["results"][0]
        assert r["key"] == "999"
        assert r["status"] == "success"
        assert r["exit_code"] == 0
        assert r["duration_s"] == 45.7  # rounded to 1 decimal
        assert r["account_name"] == "Prod"
        assert r["script"] == "ec2_export.py"
        assert "completed_at" in r

    def test_in_memory_session_also_updated(self, tmp_path):
        """record_scan_result must update the in-memory session dict too."""
        session = utils.start_scan_session("org-scan", "L", [{"key": "x"}])
        utils.record_scan_result(session, "x", "success", 0, 1.0)
        assert len(session["results"]) == 1


class TestCompleteScanSession:
    def test_marks_completed(self, tmp_path):
        session = utils.start_scan_session("smart-scan", "L", [{"key": "s1"}])
        utils.complete_scan_session(session)

        data = _read_session_file(session)
        assert data["status"] == "completed"
        assert data["completed_at"] is not None

    def test_in_memory_status_updated(self, tmp_path):
        session = utils.start_scan_session("smart-scan", "L", [{"key": "s1"}])
        utils.complete_scan_session(session)
        assert session["status"] == "completed"


class TestGetInterruptedSessions:
    def test_returns_running_only(self, tmp_path):
        running = utils.start_scan_session("org-scan", "Running", [{"key": "a"}])
        time.sleep(1.1)  # ensure distinct session_id (1-second filename resolution)
        completed = utils.start_scan_session("org-scan", "Completed", [{"key": "b"}])
        utils.complete_scan_session(completed)

        interrupted = utils.get_interrupted_sessions()
        session_ids = [s["session_id"] for s in interrupted]
        assert running["session_id"] in session_ids
        assert completed["session_id"] not in session_ids

    def test_empty_when_none_running(self, tmp_path):
        session = utils.start_scan_session("org-scan", "Done", [{"key": "a"}])
        utils.complete_scan_session(session)
        assert utils.get_interrupted_sessions() == []


class TestLoadScanSessions:
    def test_limit_respected(self, tmp_path):
        # Create 3 sessions with small time gaps so filenames differ
        for i in range(3):
            utils.start_scan_session("org-scan", f"Run {i}", [{"key": str(i)}])
            # Tiny sleep so strftime timestamps differ (1-second resolution)
            time.sleep(1.1)

        loaded = utils.load_scan_sessions(limit=2)
        assert len(loaded) == 2

    def test_newest_first(self, tmp_path):
        s1 = utils.start_scan_session("org-scan", "First", [{"key": "1"}])
        time.sleep(1.1)
        s2 = utils.start_scan_session("org-scan", "Second", [{"key": "2"}])

        loaded = utils.load_scan_sessions(limit=10)
        ids = [s["session_id"] for s in loaded]
        assert ids.index(s2["session_id"]) < ids.index(s1["session_id"])

    def test_path_injected(self, tmp_path):
        utils.start_scan_session("org-scan", "L", [{"key": "k"}])
        loaded = utils.load_scan_sessions()
        assert all("_path" in s for s in loaded)


class TestResumeScanSession:
    def test_resets_to_running(self, tmp_path):
        session = utils.start_scan_session("org-scan", "L", [{"key": "a"}])
        utils.complete_scan_session(session)
        assert session["status"] == "completed"

        utils.resume_scan_session(session)
        assert session["status"] == "running"
        assert session["completed_at"] is None

        data = _read_session_file(session)
        assert data["status"] == "running"
        assert data["completed_at"] is None
