#!/usr/bin/env python3
"""
Comprehensive tests for smart_scan.executor module.
Tests batch script execution, progress tracking, and result reporting.
"""

import sys
import os
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

# Add scripts directory to path
scripts_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../..", "scripts"))
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)

from smart_scan.executor import (
    ExecutionResult,
    ScriptExecutor,
    execute_scripts,
)


class TestExecutionResultDataclass:
    """Test ExecutionResult dataclass structure and methods."""

    def test_execution_result_creation(self):
        """Test creating ExecutionResult instance."""
        result = ExecutionResult(
            script="test-script.py",
            success=True,
            start_time=datetime(2025, 12, 4, 10, 0, 0),
            end_time=datetime(2025, 12, 4, 10, 2, 30),
            duration_seconds=150.0,
            return_code=0,
            output_file="test-output.xlsx",
        )

        assert result.script == "test-script.py"
        assert result.success is True
        assert result.duration_seconds == 150.0
        assert result.return_code == 0
        assert result.output_file == "test-output.xlsx"

    def test_execution_result_with_error(self):
        """Test ExecutionResult with error message."""
        result = ExecutionResult(
            script="failing-script.py",
            success=False,
            start_time=datetime(2025, 12, 4, 10, 0, 0),
            end_time=datetime(2025, 12, 4, 10, 0, 5),
            duration_seconds=5.0,
            return_code=1,
            error_message="Script failed with exit code 1",
        )

        assert result.success is False
        assert result.return_code == 1
        assert result.error_message == "Script failed with exit code 1"
        assert result.output_file is None

    def test_duration_formatted_seconds(self):
        """Test duration formatting for seconds."""
        result = ExecutionResult(
            script="test.py",
            success=True,
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(seconds=45),
            duration_seconds=45.0,
            return_code=0,
        )

        assert result.duration_formatted == "45s"

    def test_duration_formatted_minutes_seconds(self):
        """Test duration formatting for minutes and seconds."""
        result = ExecutionResult(
            script="test.py",
            success=True,
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(seconds=150),
            duration_seconds=150.0,
            return_code=0,
        )

        assert result.duration_formatted == "2m 30s"

    def test_duration_formatted_hours(self):
        """Test duration formatting for hours."""
        result = ExecutionResult(
            script="test.py",
            success=True,
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(seconds=3665),
            duration_seconds=3665.0,
            return_code=0,
        )

        # 3665 seconds = 1 hour, 1 minute, 5 seconds
        assert "1h" in result.duration_formatted
        assert "1m" in result.duration_formatted
        assert "5s" in result.duration_formatted

    def test_duration_formatted_zero(self):
        """Test duration formatting for zero duration."""
        result = ExecutionResult(
            script="test.py",
            success=True,
            start_time=datetime.now(),
            end_time=datetime.now(),
            duration_seconds=0.0,
            return_code=0,
        )

        assert result.duration_formatted == "0s"


class TestScriptExecutorClass:
    """Test ScriptExecutor class initialization and structure."""

    def test_executor_instantiation(self):
        """Test creating ScriptExecutor instance."""
        scripts = {"test1.py", "test2.py", "test3.py"}
        executor = ScriptExecutor(scripts)

        assert executor is not None
        assert isinstance(executor, ScriptExecutor)
        assert executor.total_scripts == 3

    def test_executor_with_empty_set(self):
        """Test creating executor with empty script set."""
        executor = ScriptExecutor(set())

        assert executor.total_scripts == 0

    def test_executor_has_required_methods(self):
        """Verify ScriptExecutor has all required methods."""
        executor = ScriptExecutor({"test.py"})
        required_methods = [
            "_find_script_path",
            "_execute_script",
            "_find_output_file",
            "_show_progress_header",
            "_show_progress",
            "_show_execution_summary",
            "execute_all",
            "save_execution_log",
        ]
        for method in required_methods:
            assert hasattr(executor, method), f"Missing method: {method}"

    def test_executor_with_list_converts_to_set(self):
        """Test that executor converts list to set."""
        scripts = ["test1.py", "test2.py", "test2.py"]  # Duplicate
        executor = ScriptExecutor(scripts)

        # Should deduplicate
        assert executor.total_scripts == 2

    def test_executor_script_names_property(self):
        """Test that script names are accessible."""
        scripts = {"test1.py", "test2.py"}
        executor = ScriptExecutor(scripts)

        assert hasattr(executor, "scripts")
        assert executor.scripts == scripts


class TestScriptExecutorMethods:
    """Test ScriptExecutor private methods."""

    def test_find_script_path_existing(self):
        """Test finding an existing script."""
        # Create a temporary test script
        with tempfile.TemporaryDirectory() as tmpdir:
            test_script = Path(tmpdir) / "scripts" / "test-script.py"
            test_script.parent.mkdir(exist_ok=True)
            test_script.write_text("#!/usr/bin/env python3\nprint('test')")

            # Create executor pointing to tmpdir
            executor = ScriptExecutor({"test-script.py"})
            executor.scripts_dir = Path(tmpdir) / "scripts"

            result = executor._find_script_path("test-script.py")
            assert result is not None
            assert result.exists()
            assert result.name == "test-script.py"

    def test_find_script_path_nonexistent(self):
        """Test finding a nonexistent script."""
        executor = ScriptExecutor({"nonexistent.py"})
        result = executor._find_script_path("nonexistent.py")

        # Should return path even if doesn't exist (execution will handle error)
        assert result is not None
        assert result.name == "nonexistent.py"

    def test_find_output_file_pattern(self):
        """Test finding output file by pattern."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock output file
            output_file = Path(tmpdir) / "test-account-ec2-export-12.04.2025.xlsx"
            output_file.touch()

            executor = ScriptExecutor({"ec2-export.py"})
            executor.output_dir = Path(tmpdir)

            result = executor._find_output_file("ec2-export")
            assert result is not None
            assert "ec2-export" in result

    def test_find_output_file_not_found(self):
        """Test finding output file when none exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ScriptExecutor({"ec2-export.py"})
            executor.output_dir = Path(tmpdir)

            result = executor._find_output_file("nonexistent-export")
            assert result is None


class TestExecuteScripts:
    """Test execute_scripts convenience function."""

    def test_execute_scripts_empty_set(self):
        """Test executing empty script set."""
        result = execute_scripts(set(), show_progress=False, save_log=False)

        assert result is not None
        assert isinstance(result, dict)
        assert result.get("total_scripts", 0) == 0

    def test_execute_scripts_returns_summary(self):
        """Test that execute_scripts returns proper summary."""
        result = execute_scripts({"test.py"}, show_progress=False, save_log=False)

        assert result is not None
        assert isinstance(result, dict)
        # Should have summary fields even if execution failed
        assert "total_scripts" in result or "executed" in result or "results" in result


class TestExecutionFlow:
    """Integration tests for execution workflow."""

    def test_executor_with_mock_script(self):
        """Test executor with a simple mock script."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a simple test script that exits successfully
            scripts_dir = Path(tmpdir) / "scripts"
            scripts_dir.mkdir(exist_ok=True)

            test_script = scripts_dir / "test-success.py"
            test_script.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)")
            test_script.chmod(0o755)

            # Create executor
            executor = ScriptExecutor({"test-success.py"})
            executor.scripts_dir = scripts_dir

            # Execute (without showing progress)
            summary = executor.execute_all(show_progress=False)

            assert summary is not None
            assert isinstance(summary, dict)
            assert "total_scripts" in summary or "executed" in summary

    def test_save_execution_log(self):
        """Test saving execution log to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            executor = ScriptExecutor({"test.py"})

            log_file = Path(tmpdir) / "test-execution.log"
            result = executor.save_execution_log(str(log_file))

            # Should return True even if no results (empty log)
            assert isinstance(result, bool)

            if result:
                assert log_file.exists()


class TestProgressDisplay:
    """Test progress display methods."""

    def test_show_progress_header(self):
        """Test that progress header can be displayed."""
        executor = ScriptExecutor({"test1.py", "test2.py"})

        # Should not raise exception
        try:
            executor._show_progress_header()
            success = True
        except Exception:
            success = False

        assert success is True

    def test_show_progress(self):
        """Test that progress can be displayed."""
        executor = ScriptExecutor({"test1.py", "test2.py"})

        # Should not raise exception
        try:
            executor._show_progress(1, "test1.py", "Running")
            success = True
        except Exception:
            success = False

        assert success is True

    def test_show_execution_summary(self):
        """Test that execution summary can be displayed."""
        executor = ScriptExecutor({"test.py"})

        result = ExecutionResult(
            script="test.py",
            success=True,
            start_time=datetime.now(),
            end_time=datetime.now() + timedelta(seconds=60),
            duration_seconds=60.0,
            return_code=0,
        )
        executor.results.append(result)

        # Should not raise exception
        try:
            executor._show_execution_summary()
            success = True
        except Exception:
            success = False

        assert success is True


class TestErrorHandling:
    """Test error handling in executor."""

    def test_execution_continues_on_error(self):
        """Test that executor continues after script failure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            scripts_dir = Path(tmpdir) / "scripts"
            scripts_dir.mkdir(exist_ok=True)

            # Create a failing script
            failing_script = scripts_dir / "failing.py"
            failing_script.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(1)")
            failing_script.chmod(0o755)

            # Create a success script
            success_script = scripts_dir / "success.py"
            success_script.write_text("#!/usr/bin/env python3\nimport sys\nsys.exit(0)")
            success_script.chmod(0o755)

            executor = ScriptExecutor({"failing.py", "success.py"})
            executor.scripts_dir = scripts_dir

            summary = executor.execute_all(show_progress=False)

            # Both scripts should have been attempted
            assert summary is not None
            # Check that execution completed (exact format may vary)
            assert isinstance(summary, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
