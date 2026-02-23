#!/usr/bin/env python3
"""
Storage Resources All-in-One Export Script

Orchestrates all storage resource exporters as subprocesses and archives
every output file into a single zip.  Runs non-interactively against each
child script via STRATUSSCAN_AUTO_RUN / STRATUSSCAN_REGIONS env vars so
the individual exporters receive region selection without prompting.

Covered services (multi-select at runtime):
  EBS Volumes, EBS Snapshots, S3, EFS, FSx, AWS Backup, S3 Access Points,
  DataSync, Transfer Family, Storage Gateway, Glacier Vaults
"""

import os
import sys
import subprocess
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import utils
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent))
    import utils

utils.setup_logging('storage-resources')

# ---------------------------------------------------------------------------
# Script registry — (display_name, filename) ordered to match the menu
# ---------------------------------------------------------------------------
STORAGE_SCRIPTS: List[Tuple[str, str]] = [
    ("EBS Volumes",       "ebs_volumes_export.py"),
    ("EBS Snapshots",     "ebs_snapshots_export.py"),
    ("S3",                "s3_export.py"),
    ("EFS",               "efs_export.py"),
    ("FSx",               "fsx_export.py"),
    ("AWS Backup",        "backup_export.py"),
    ("S3 Access Points",  "s3_accesspoints_export.py"),
    ("DataSync",          "datasync_export.py"),
    ("Transfer Family",   "transfer_family_export.py"),
    ("Storage Gateway",   "storagegateway_export.py"),
    ("Glacier Vaults",    "glacier_export.py"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    s = int(seconds)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {sec}s"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


def _snapshot_xlsx(output_dir: Path) -> Tuple[set, float]:
    """Capture existing .xlsx filenames and current epoch time."""
    try:
        return {str(p) for p in output_dir.glob("*.xlsx")}, time.time()
    except Exception:
        return set(), 0.0


def _detect_new_xlsx(
    output_dir: Path,
    pre: Tuple[set, float],
) -> Optional[str]:
    """Return the path of the newest .xlsx file created after *pre*."""
    try:
        pre_set, snap_time = pre
        candidates = [
            p for p in output_dir.glob("*.xlsx")
            if str(p) not in pre_set and p.stat().st_mtime >= snap_time
        ]
        if candidates:
            return str(max(candidates, key=lambda p: p.stat().st_mtime))
        all_xlsx = list(output_dir.glob("*.xlsx"))
        if all_xlsx:
            return str(max(all_xlsx, key=lambda p: p.stat().st_mtime))
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Multi-select script menu
# ---------------------------------------------------------------------------

def prompt_script_selection(
    scripts: List[Tuple[str, str]],
) -> List[Tuple[str, str]]:
    """
    Present a numbered multi-select menu for script selection.

    Returns a list of selected (display_name, filename) tuples,
    or the strings 'back' or 'exit'.
    """
    if utils.is_auto_run():
        return list(scripts)

    while True:
        print("\nSELECT STORAGE RESOURCES TO EXPORT")
        print("=" * 64)
        print("   0. All  (export all storage resources)")
        for i, (name, _) in enumerate(scripts, 1):
            print(f"  {i:2d}. {name}")
        print("=" * 64)
        print("   b. Back    x. Exit")
        print("=" * 64)

        try:
            raw = input(
                "Enter number(s) separated by spaces (e.g. 1  or  1 3 5): "
            ).strip().lower()
        except KeyboardInterrupt:
            print()
            return 'exit'  # type: ignore[return-value]

        if raw == 'b':
            return 'back'  # type: ignore[return-value]
        if raw == 'x':
            return 'exit'  # type: ignore[return-value]
        if raw == '0':
            return list(scripts)

        tokens = raw.split()
        selected: List[Tuple[str, str]] = []
        seen: set = set()
        valid = True

        for tok in tokens:
            try:
                idx = int(tok)
                if 1 <= idx <= len(scripts):
                    if idx not in seen:
                        selected.append(scripts[idx - 1])
                        seen.add(idx)
                else:
                    print(
                        f"  Invalid number {tok}. "
                        f"Enter values between 0 and {len(scripts)}."
                    )
                    valid = False
                    break
            except ValueError:
                print(f"  Invalid input '{tok}'. Please enter numbers only.")
                valid = False
                break

        if valid and selected:
            return selected
        if valid and not selected:
            print("  No scripts selected. Please enter at least one number.")


# ---------------------------------------------------------------------------
# Subprocess execution
# ---------------------------------------------------------------------------

@dataclass
class ScriptResult:
    """Result of a single child-script execution."""
    name: str
    filename: str
    success: bool
    duration_seconds: float
    output_file: Optional[str] = None
    error: Optional[str] = None


def run_script(
    name: str,
    script_path: Path,
    regions: List[str],
    output_dir: Path,
    index: int,
    total: int,
) -> ScriptResult:
    """Invoke a single exporter script as a subprocess."""
    print(f"\n{'=' * 70}")
    print(f"[{index}/{total}] {name.upper()}")
    print(f"{'=' * 70}")

    if not script_path.exists():
        utils.log_error(f"Script not found: {script_path.name}")
        return ScriptResult(
            name=name,
            filename=script_path.name,
            success=False,
            duration_seconds=0.0,
            error="Script file not found",
        )

    env = os.environ.copy()
    env['STRATUSSCAN_AUTO_RUN'] = '1'
    env['STRATUSSCAN_REGIONS'] = ','.join(regions)

    pre = _snapshot_xlsx(output_dir)
    start = time.time()

    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=False,
            text=True,
            env=env,
            timeout=1800,
        )
        duration = time.time() - start
        success = result.returncode == 0
        output_file = _detect_new_xlsx(output_dir, pre) if success else None

        if success:
            utils.log_success(
                f"{name} completed in {_fmt_duration(duration)}"
            )
        else:
            utils.log_error(
                f"{name} failed (exit code {result.returncode})"
            )

        return ScriptResult(
            name=name,
            filename=script_path.name,
            success=success,
            duration_seconds=duration,
            output_file=output_file,
            error=None if success else f"Exit code {result.returncode}",
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start
        utils.log_error(f"{name} timed out after 30 minutes")
        return ScriptResult(
            name=name,
            filename=script_path.name,
            success=False,
            duration_seconds=duration,
            error="Timed out (30 min)",
        )

    except Exception as e:
        duration = time.time() - start
        utils.log_error(f"{name} failed with exception", e)
        return ScriptResult(
            name=name,
            filename=script_path.name,
            success=False,
            duration_seconds=duration,
            error=str(e),
        )


# ---------------------------------------------------------------------------
# Zip archive
# ---------------------------------------------------------------------------

def create_zip_archive(
    output_files: List[str],
    account_name: str,
    output_dir: Path,
) -> Optional[Path]:
    """Zip all successful export files into a single archive."""
    valid = [f for f in output_files if f and Path(f).exists()]
    if not valid:
        utils.log_error("No output files to archive")
        return None

    date = utils.get_export_date()
    zip_name = f"{account_name}-storage-resources-all-export-{date}.zip"
    zip_path = output_dir / zip_name

    if zip_path.exists():
        v = 2
        while True:
            candidate = output_dir / (
                f"{account_name}-storage-resources-all-export-{date}-v{v}.zip"
            )
            if not candidate.exists():
                zip_path = candidate
                break
            v += 1

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for f in valid:
                p = Path(f)
                zf.write(p, p.name)
                utils.log_info(f"  Archived: {p.name}")

        size_mb = zip_path.stat().st_size / (1024 * 1024)
        utils.log_success(
            f"Archive created: {zip_path.name} "
            f"({size_mb:.1f} MB, {len(valid)} file(s))"
        )
        return zip_path

    except Exception as e:
        utils.log_error("Failed to create zip archive", e)
        return None


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(
    results: List[ScriptResult],
    zip_path: Optional[Path],
) -> None:
    """Print a formatted completion summary table."""
    print(f"\n{'=' * 70}")
    print("STORAGE RESOURCES EXPORT — SUMMARY")
    print(f"{'=' * 70}")

    for r in results:
        status = "✓" if r.success else "✗"
        print(f"  {status} {r.name:<35} {_fmt_duration(r.duration_seconds):>8}")
        if not r.success and r.error:
            print(f"      Error: {r.error}")

    successful = sum(1 for r in results if r.success)
    failed = len(results) - successful

    print(f"{'=' * 70}")
    print(f"  Completed: {successful}/{len(results)}   Failed: {failed}")
    if zip_path:
        print(f"  Archive:   {zip_path.name}")
    elif failed == len(results):
        print("  No archive created — all exports failed")
    print(f"{'=' * 70}")


# ---------------------------------------------------------------------------
# Main — gold-standard 3-step state machine
# ---------------------------------------------------------------------------

def main() -> None:
    account_id, account_name = utils.print_script_banner(
        "STORAGE RESOURCES ALL-IN-ONE EXPORT"
    )

    scripts_dir = utils.get_scripts_dir()
    output_dir  = utils.get_output_dir()

    step = 1
    selected_regions: List[str] = []
    selected_scripts: List[Tuple[str, str]] = []

    while True:
        # ── Step 1: Region selection ──────────────────────────────────────
        if step == 1:
            result = utils.prompt_region_selection("Storage Resources")
            if result == 'back':
                sys.exit(10)
            if result == 'exit':
                sys.exit(11)
            selected_regions = result
            step = 2

        # ── Step 2: Script selection ──────────────────────────────────────
        elif step == 2:
            result = prompt_script_selection(STORAGE_SCRIPTS)
            if result == 'back':
                step = 1
                continue
            if result == 'exit':
                sys.exit(11)
            selected_scripts = result
            step = 3

        # ── Step 3: Confirmation ──────────────────────────────────────────
        elif step == 3:
            script_lines = '\n'.join(
                f"    • {name}" for name, _ in selected_scripts
            )
            region_str = ', '.join(selected_regions)
            msg = (
                f"Ready to export {len(selected_scripts)} "
                f"storage resource(s):\n"
                f"{script_lines}\n\n"
                f"  Regions : {region_str}\n"
                f"  Output  : {output_dir / (account_name + '-storage-resources-all-export-<date>.zip')}"
            )
            result = utils.prompt_confirmation(msg)
            if result == 'back':
                step = 2
                continue
            if result == 'exit':
                sys.exit(11)
            break

    # ── Execution ─────────────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print(f"EXECUTING {len(selected_scripts)} EXPORT SCRIPT(S)")
    print(f"Regions: {', '.join(selected_regions)}")
    print(f"{'=' * 70}")

    results: List[ScriptResult] = []
    total = len(selected_scripts)

    for i, (name, filename) in enumerate(selected_scripts, 1):
        script_path = scripts_dir / filename
        r = run_script(name, script_path, selected_regions, output_dir, i, total)
        results.append(r)

    # ── Archive ───────────────────────────────────────────────────────────
    output_files = [r.output_file for r in results if r.output_file]
    zip_path: Optional[Path] = None

    if output_files:
        print(f"\n{'=' * 70}")
        print("CREATING ARCHIVE")
        print(f"{'=' * 70}")
        zip_path = create_zip_archive(output_files, account_name, output_dir)
    else:
        utils.log_warning(
            "No output files were generated — skipping archive creation"
        )

    # ── Summary ───────────────────────────────────────────────────────────
    print_summary(results, zip_path)


if __name__ == "__main__":
    main()
