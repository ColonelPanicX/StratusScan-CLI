"""
Regression tests for the CWE-78 containment guard in ``stratusscan.execute_script``.

Background: PR #228 (Veracode remediation) added a subprocess-containment guard
that only permitted targets located directly under ``scripts/``. That silently
broke the two root-level menu entry points — ``[0] Configure StratusScan``
(``configure.py``) and ``[1] Service Discovery`` (``smart_scan.py``) — which live
at the project root, not under ``scripts/``. The guard refused them and the main
menu just looped. These tests lock in that both legitimate root entry points are
runnable while arbitrary / traversal paths stay refused.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

import stratusscan

PROJECT_ROOT = Path(stratusscan.__file__).resolve().parent


def _run_guard(script_path):
    """
    Drive execute_script() far enough to exercise only the containment guard.

    subprocess.run is mocked to a benign success so a target that PASSES the
    guard returns True without actually spawning anything; a target that FAILS
    the guard returns False before subprocess is ever reached.
    """
    class _Result:
        returncode = 0

    with patch("stratusscan.subprocess.run", return_value=_Result()) as mock_run, \
         patch("stratusscan.clear_screen"):
        result = stratusscan.execute_script(script_path)
    return result, mock_run


class TestRootEntryPointsAllowed:
    """The two root-level menu entry points must pass the guard (the #228 regression)."""

    @pytest.mark.parametrize("name", ["configure.py", "smart_scan.py"])
    def test_root_entry_point_is_permitted(self, name):
        target = PROJECT_ROOT / name
        assert target.is_file(), f"expected root entry point {name} to exist"

        result, mock_run = _run_guard(target)

        assert result is True
        mock_run.assert_called_once()

    def test_allowlist_matches_menu_entry_points(self):
        # Guard against drift: the allowlist should name exactly the root scripts
        # the menu dispatches via execute_script().
        assert set(stratusscan.ROOT_ENTRY_POINT_SCRIPTS) == {
            "configure.py",
            "smart_scan.py",
        }


class TestExporterScriptsAllowed:
    """Normal exporters under scripts/ must still run."""

    def test_scripts_dir_exporter_is_permitted(self):
        target = PROJECT_ROOT / "scripts" / "ec2_export.py"
        assert target.is_file()

        result, mock_run = _run_guard(target)

        assert result is True
        mock_run.assert_called_once()


class TestUnsafeTargetsRefused:
    """Containment must hold: nothing outside the allowed set reaches subprocess."""

    def test_traversal_root_script_name_is_refused(self, tmp_path):
        # A file NAMED like an entry point but living elsewhere must not slip through.
        decoy = tmp_path / "configure.py"
        decoy.write_text("print('should never run')\n")

        result, mock_run = _run_guard(decoy)

        assert result is False
        mock_run.assert_not_called()

    def test_non_allowlisted_root_script_is_refused(self, tmp_path):
        # A root-level .py that is not on the allowlist is refused even at the
        # real project root name check — use a name that isn't an entry point.
        target = PROJECT_ROOT / "utils.py"  # real root .py, but not an entry point
        assert target.is_file()

        result, mock_run = _run_guard(target)

        assert result is False
        mock_run.assert_not_called()

    def test_nonexistent_scripts_target_is_refused(self):
        target = PROJECT_ROOT / "scripts" / "does_not_exist_export.py"

        result, mock_run = _run_guard(target)

        assert result is False
        mock_run.assert_not_called()

    def test_non_py_suffix_is_refused(self, tmp_path):
        target = tmp_path / "payload.sh"
        target.write_text("echo nope\n")

        result, mock_run = _run_guard(target)

        assert result is False
        mock_run.assert_not_called()
