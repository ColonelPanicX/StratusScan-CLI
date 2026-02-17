"""
Batch Script Executor

Executes multiple export scripts sequentially with progress tracking,
error handling, and result aggregation.
"""

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

# Add parent directory to path for utils import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
import utils


@dataclass
class ExecutionResult:
    """Result of a single script execution."""

    script: str
    success: bool
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    return_code: int
    output_file: Optional[str] = None
    error_message: Optional[str] = None
    # Full stderr content for persistence/diagnostics (console display is truncated)
    full_error_message: Optional[str] = None

    @property
    def duration_formatted(self) -> str:
        """Format duration as human-readable string."""
        seconds = int(self.duration_seconds)
        minutes = seconds // 60
        secs = seconds % 60
        if minutes > 0:
            return f"{minutes}m {secs}s"
        return f"{secs}s"


class ScriptExecutor:
    """Executes multiple export scripts with progress tracking."""

    def __init__(
        self,
        scripts: Set[str],
        scripts_dir: Optional[str] = None,
        python_executable: str = "python3",
    ):
        """
        Initialize the executor.

        Args:
            scripts: Set of script filenames to execute
            scripts_dir: Directory containing the scripts (uses utils.get_scripts_dir() if None)
            python_executable: Python interpreter to use
        """
        self.scripts = sorted(scripts)  # Sort for consistent ordering

        # Use utils to get the proper scripts directory
        if scripts_dir is None:
            self.scripts_dir = utils.get_scripts_dir()
        else:
            self.scripts_dir = Path(scripts_dir)

        self.python_executable = python_executable
        self.results: List[ExecutionResult] = []
        self.total_scripts = len(self.scripts)
        self.current_index = 0

    def _find_script_path(self, script_name: str) -> Optional[Path]:
        """
        Find the full path to a script.

        Args:
            script_name: Script filename

        Returns:
            Path to script, or None if not found
        """
        # Check in scripts directory
        script_path = self.scripts_dir / script_name
        if script_path.exists():
            return script_path

        # Check if script_name is already a full path
        if Path(script_name).exists():
            return Path(script_name)

        utils.log_warning(f"Script not found: {script_name}")
        return None

    def _execute_script(self, script_path: Path) -> ExecutionResult:
        """
        Execute a single script and capture results.

        Args:
            script_path: Path to the script to execute

        Returns:
            ExecutionResult with execution details
        """
        script_name = script_path.name
        start_time = datetime.now()

        utils.log_info(f"Executing: {script_name}")

        # Snapshot existing output files before execution to detect new ones afterward
        pre_run_files = self._snapshot_output_files()

        try:
            # Execute the script
            result = subprocess.run(
                [self.python_executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minute timeout per script
            )

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            # Check if execution was successful
            success = result.returncode == 0

            # Try to find output file by detecting newly created Excel files
            output_file = self._find_output_file(script_name, pre_run_files)

            # Get error message if failed
            error_message = None
            full_error_message = None
            if not success:
                full_error_message = result.stderr.strip() if result.stderr else "Unknown error"
                # Truncate for console display; full text persisted in full_error_message
                error_message = (
                    full_error_message[:100] + "..."
                    if len(full_error_message) > 100
                    else full_error_message
                )

            execution_result = ExecutionResult(
                script=script_name,
                success=success,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                return_code=result.returncode,
                output_file=output_file,
                error_message=error_message,
                full_error_message=full_error_message,
            )

            if success:
                utils.log_info(
                    f"✓ {script_name} completed successfully in {execution_result.duration_formatted}"
                )
            else:
                utils.log_error(
                    f"✗ {script_name} failed with code {result.returncode}",
                    Exception(error_message or "Script execution failed"),
                )

            return execution_result

        except subprocess.TimeoutExpired:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            utils.log_error(f"✗ {script_name} timed out after 30 minutes", None)

            return ExecutionResult(
                script=script_name,
                success=False,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                return_code=-1,
                error_message="Execution timed out (30 minutes)",
            )

        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            utils.log_error(f"✗ {script_name} failed with exception", e)

            return ExecutionResult(
                script=script_name,
                success=False,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
                return_code=-1,
                error_message=str(e),
            )

    def _snapshot_output_files(self) -> tuple:
        """
        Capture the current set of xlsx file paths and the snapshot epoch time.

        Returns:
            Tuple of (set of file path strings, epoch float of snapshot time)
        """
        import time as _time
        try:
            output_dir = utils.get_output_dir()
            snapshot_time = _time.time()
            return ({str(p) for p in output_dir.glob("*.xlsx")}, snapshot_time)
        except Exception:
            return (set(), 0.0)

    def _find_output_file(self, script_name: str, pre_run_files=None) -> Optional[str]:
        """
        Try to find the output file created by a script.

        Args:
            script_name: Name of the script that was executed
            pre_run_files: Tuple of (set of pre-run xlsx paths, snapshot epoch time),
                           or a plain set for backwards compatibility

        Returns:
            Path to output file if found, None otherwise
        """
        try:
            output_dir = utils.get_output_dir()
            xlsx_files = list(output_dir.glob("*.xlsx"))

            if not xlsx_files:
                return None

            # Unpack snapshot tuple if provided
            if isinstance(pre_run_files, tuple):
                pre_run_set, start_time_epoch = pre_run_files
            elif isinstance(pre_run_files, set):
                pre_run_set = pre_run_files
                start_time_epoch = 0.0
            else:
                pre_run_set = None
                start_time_epoch = 0.0

            if pre_run_set is not None:
                # Prefer files that are both new (not in pre-run set) AND written
                # after the snapshot time to eliminate false matches on same-day files
                new_files = [
                    p for p in xlsx_files
                    if str(p) not in pre_run_set
                    and (start_time_epoch == 0.0 or p.stat().st_mtime >= start_time_epoch)
                ]
                if new_files:
                    new_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
                    return str(new_files[0])

            # Fall back to newest file overall
            xlsx_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            return str(xlsx_files[0])

        except Exception:
            return None

    def _show_progress_header(self) -> None:
        """Display progress header."""
        print()
        print("=" * 80)
        print(" " * 28 + "BATCH EXECUTION")
        print("=" * 80)
        print()
        print(f"Total Scripts: {self.total_scripts}")
        print()
        print("=" * 80)
        print()

    def _show_progress(self, script_name: str) -> None:
        """
        Display progress for current script.

        Args:
            script_name: Name of script being executed
        """
        self.current_index += 1
        progress_pct = (self.current_index / self.total_scripts) * 100

        print(f"[{self.current_index}/{self.total_scripts}] ({progress_pct:.0f}%) {script_name}")
        print("-" * 80)

    def _show_execution_summary(self) -> None:
        """Display summary of execution results."""
        print()
        print("=" * 80)
        print(" " * 28 + "EXECUTION SUMMARY")
        print("=" * 80)
        print()

        # Count successes and failures
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]

        # Calculate total time
        if self.results:
            total_start = min(r.start_time for r in self.results)
            total_end = max(r.end_time for r in self.results)
            total_duration = (total_end - total_start).total_seconds()
            total_minutes = int(total_duration // 60)
            total_seconds = int(total_duration % 60)
        else:
            total_minutes = 0
            total_seconds = 0

        # Overall statistics
        print(f"Total Scripts:     {self.total_scripts}")
        print(f"Successful:        {len(successful)} ✓")
        print(f"Failed:            {len(failed)} ✗")
        print(f"Success Rate:      {(len(successful)/self.total_scripts*100):.1f}%")
        print(f"Total Time:        {total_minutes}m {total_seconds}s")
        print()

        # Show successful scripts
        if successful:
            print("SUCCESSFUL SCRIPTS:")
            print("-" * 80)
            for result in successful:
                output_info = f" → {result.output_file}" if result.output_file else ""
                print(f"  ✓ {result.script:<45} {result.duration_formatted:>8}{output_info}")
            print()

        # Show failed scripts with error details
        if failed:
            print("FAILED SCRIPTS:")
            print("-" * 80)
            for result in failed:
                print(f"  ✗ {result.script:<45} {result.duration_formatted:>8}")
                if result.error_message:
                    # error_message is already truncated to 100 chars for console;
                    # full text is available in result.full_error_message
                    print(f"     Error: {result.error_message}")
            print()

        print("=" * 80)
        print()

    def execute_all(self, show_progress: bool = True) -> Dict[str, any]:
        """
        Execute all scripts in sequence.

        Args:
            show_progress: Whether to show progress display

        Returns:
            Dictionary with execution summary:
                - total: Total scripts
                - successful: Number of successful executions
                - failed: Number of failed executions
                - results: List of ExecutionResult objects
                - duration_seconds: Total execution time
        """
        if show_progress:
            self._show_progress_header()

        batch_start = datetime.now()

        for script_name in self.scripts:
            # Find script path
            script_path = self._find_script_path(script_name)

            if script_path is None:
                # Script not found, record as failure
                result = ExecutionResult(
                    script=script_name,
                    success=False,
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    duration_seconds=0,
                    return_code=-1,
                    error_message="Script file not found",
                )
                self.results.append(result)
                if show_progress:
                    self._show_progress(script_name)
                    print(f"✗ Script not found: {script_name}")
                    print()
                continue

            # Show progress
            if show_progress:
                self._show_progress(script_name)

            # Execute script
            result = self._execute_script(script_path)
            self.results.append(result)

            # Brief pause between scripts
            if show_progress:
                print()
                time.sleep(0.5)

        batch_end = datetime.now()
        total_duration = (batch_end - batch_start).total_seconds()

        # Show summary
        if show_progress:
            self._show_execution_summary()

        # Return summary
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]

        return {
            "total": self.total_scripts,
            "successful": len(successful),
            "failed": len(failed),
            "results": self.results,
            "duration_seconds": total_duration,
            "success_rate": (len(successful) / self.total_scripts * 100) if self.total_scripts > 0 else 0,
        }

    def save_execution_log(self, filename: Optional[str] = None) -> bool:
        """
        Save execution results to a log file.

        Args:
            filename: Output filename (auto-generated if None)

        Returns:
            True if saved successfully, False otherwise
        """
        if filename is None:
            timestamp = datetime.now().strftime("%m.%d.%Y-%H%M")
            filename = f"smart-scan-execution-log-{timestamp}.txt"

        try:
            with open(filename, "w", encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write(" " * 26 + "SMART SCAN EXECUTION LOG\n")
                f.write("=" * 80 + "\n\n")

                # Summary
                successful = [r for r in self.results if r.success]
                failed = [r for r in self.results if not r.success]

                f.write(f"Execution Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Scripts: {self.total_scripts}\n")
                f.write(f"Successful: {len(successful)}\n")
                f.write(f"Failed: {len(failed)}\n")
                f.write(f"Success Rate: {(len(successful)/self.total_scripts*100):.1f}%\n\n")
                f.write("=" * 80 + "\n\n")

                # Detailed results
                f.write("EXECUTION DETAILS:\n")
                f.write("-" * 80 + "\n\n")

                for result in self.results:
                    status = "SUCCESS" if result.success else "FAILED"
                    f.write(f"Script: {result.script}\n")
                    f.write(f"Status: {status}\n")
                    f.write(f"Duration: {result.duration_formatted}\n")
                    f.write(f"Start Time: {result.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"End Time: {result.end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")

                    if result.output_file:
                        f.write(f"Output File: {result.output_file}\n")

                    if result.error_message:
                        f.write(f"Error: {result.error_message}\n")

                    f.write("\n" + "-" * 80 + "\n\n")

                f.write("=" * 80 + "\n")

            utils.log_info(f"Execution log saved to: {filename}")
            return True

        except Exception as e:
            utils.log_error(f"Error saving execution log to {filename}", e)
            return False


def execute_scripts(
    scripts: Set[str], show_progress: bool = True, save_log: bool = False
) -> Dict[str, any]:
    """
    Execute multiple scripts in batch.

    Args:
        scripts: Set of script filenames to execute
        show_progress: Whether to show progress display
        save_log: Whether to save execution log to file

    Returns:
        Execution summary dictionary
    """
    executor = ScriptExecutor(scripts)
    summary = executor.execute_all(show_progress=show_progress)

    if save_log:
        executor.save_execution_log()

    return summary
