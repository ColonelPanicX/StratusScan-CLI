#!/usr/bin/env python3
"""
StratusScan Smart Scan

Unified service discovery and script recommendation workflow.

Discovers all AWS services in use, generates a report (console + Markdown +
Excel), then optionally executes the recommended export scripts.

Usage:
    python smart_scan.py               # interactive
    STRATUSSCAN_AUTO_RUN=1 python smart_scan.py  # CI / headless (Quick Scan)
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure the project root is on sys.path for utils
_root = Path(__file__).parent.absolute()
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

# Ensure scripts/ is on sys.path so services_in_use_export and smart_scan package
# are importable as top-level names
_scripts_dir = _root / 'scripts'
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

try:
    import utils
except ImportError as exc:
    print(f"Error: could not import utils from {_root}: {exc}")
    sys.exit(1)

logger = utils.setup_logging('smart-scan')

try:
    import pandas as pd
except ImportError:
    print("Error: pandas is not installed. Install with: pip install pandas")
    sys.exit(1)

try:
    from services_in_use_export import (
        discover_services,
        generate_summary,
        create_detailed_export,
        create_category_sheets,
        create_recommendations_sheet,
    )
except ImportError as exc:
    utils.log_error(f"Could not import services_in_use_export: {exc}", exc)
    sys.exit(1)

try:
    from smart_scan.analyzer import analyze_services_from_dict
    from smart_scan.executor import execute_scripts
    from smart_scan.mapping import ALWAYS_RUN_SCRIPTS
except ImportError as exc:
    utils.log_error(f"Could not import smart_scan package: {exc}", exc)
    sys.exit(1)


def _prompt_scan_mode() -> str:
    """Prompt user for Quick or Deep scan mode."""
    print()
    print("  ─── SCAN MODE ───────────────────────────────────────────────")
    print("  [1] Quick Scan  — service presence and resource counts")
    print("  [2] Deep Scan   — counts + asset breakdown per service (slower)")
    print("  ─────────────────────────────────────────────────────────────")
    choice = input("  Enter choice [1]: ").strip() or "1"
    return 'deep' if choice == '2' else 'quick'


def _format_detail(detail: Dict[str, int]) -> str:
    """Format a detail dict as a readable inline string."""
    return "  |  ".join(f"{k}: {v}" for k, v in detail.items() if v > 0)


def _print_discovery_summary(services: Dict[str, Any], mode: str) -> None:
    """Print formatted discovery results to console."""
    print()
    print("=" * 70)
    print("  SERVICES DISCOVERED")
    print("=" * 70)

    # Group by category
    by_category: Dict[str, list] = {}
    for name, data in sorted(services.items()):
        cat = data['category']
        by_category.setdefault(cat, []).append((name, data))

    for category, items in sorted(by_category.items()):
        print(f"\n  {category}")
        print(f"  {'─' * 60}")
        for name, data in items:
            region_str = (
                ', '.join(sorted(data['regions']))
                if data['regional'] and data['regions']
                else 'global'
            )
            print(f"  {name:<35} {data['count']:>5} {data['unit']}")
            if mode == 'deep' and data.get('detail'):
                print(f"    └─ {_format_detail(data['detail'])}")
            print(f"    └─ {region_str}")

    total_resources = sum(s['count'] for s in services.values())
    print()
    print("=" * 70)
    print(f"  Total services: {len(services)}   Total resources: {total_resources:,}")
    print("=" * 70)


def _write_markdown_report(
    services: Dict[str, Any],
    recommendations: Dict[str, Any],
    account_name: str,
    account_id: str,
    regions: List[str],
    mode: str,
) -> Optional[Path]:
    """
    Write discovery report as Markdown to reports/ directory.

    Returns the path to the written file, or None on failure.
    """
    reports_dir = _root / 'reports'
    reports_dir.mkdir(exist_ok=True)

    timestamp = utils.get_current_timestamp()
    filename = f"{account_name}-discovery-{timestamp}.md"
    filepath = reports_dir / filename

    now = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
    scan_label = 'Deep Scan' if mode == 'deep' else 'Quick Scan'

    lines = [
        "# AWS Service Discovery Report",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Account | {account_name} ({utils.mask_account_id(account_id)}) |",
        f"| Scan Date | {now} |",
        f"| Scan Mode | {scan_label} |",
        f"| Regions | {', '.join(regions)} |",
        f"| Services Found | {len(services)} |",
        f"| Total Resources | {sum(s['count'] for s in services.values()):,} |",
        "",
        "---",
        "",
        "## Services Discovered",
        "",
    ]

    # Group by category
    by_category: Dict[str, list] = {}
    for name, data in sorted(services.items()):
        by_category.setdefault(data['category'], []).append((name, data))

    for category, items in sorted(by_category.items()):
        lines.append(f"### {category}")
        lines.append("")
        if mode == 'deep':
            lines.append("| Service | Count | Unit | Regions | Detail |")
            lines.append("|---|---|---|---|---|")
            for name, data in items:
                region_str = (
                    ', '.join(sorted(data['regions'])) if data['regional'] else 'global'
                )
                detail_str = _format_detail(data.get('detail', {})) or '—'
                lines.append(
                    f"| {name} | {data['count']} | {data['unit']} | {region_str} | {detail_str} |"
                )
        else:
            lines.append("| Service | Count | Unit | Regions |")
            lines.append("|---|---|---|---|")
            for name, data in items:
                region_str = (
                    ', '.join(sorted(data['regions'])) if data['regional'] else 'global'
                )
                lines.append(
                    f"| {name} | {data['count']} | {data['unit']} | {region_str} |"
                )
        lines.append("")

    n_baseline = len(recommendations.get('always_run', []))
    n_service = recommendations.get('coverage_stats', {}).get('service_based_count', 0)
    lines += [
        "---",
        "",
        "## Recommended Export Scripts",
        "",
        f"**{len(recommendations.get('all_scripts', set()))} scripts recommended** "
        f"({n_baseline} security baseline + {n_service} service-specific)",
        "",
    ]

    always_run = recommendations.get('always_run', [])
    if always_run:
        lines.append("### Security Baseline (Always Run)")
        lines.append("")
        for script in sorted(always_run):
            lines.append(f"- `{script}`")
        lines.append("")

    for category, scripts in sorted(recommendations.get('by_category', {}).items()):
        service_scripts = [s for s in scripts if s not in always_run]
        if not service_scripts:
            continue
        lines.append(f"### {category}")
        lines.append("")
        for script in service_scripts:
            lines.append(f"- `{script}`")
        lines.append("")

    try:
        filepath.write_text('\n'.join(lines), encoding='utf-8')
        return filepath
    except Exception as e:
        utils.log_warning(f"Failed to write Markdown report: {e}")
        return None


def main() -> None:
    """Main Smart Scan workflow."""
    utils.log_script_start('smart-scan')

    account_id, account_name = utils.print_script_banner(
        "SMART SCAN — SERVICE DISCOVERY & RECOMMENDATIONS"
    )
    if not account_id:
        utils.log_error("Unable to determine AWS account ID. Check credentials.", None)
        return

    utils.log_info(f"Account: {account_name} ({utils.mask_account_id(account_id)})")

    # Scan mode selection
    if utils.is_auto_run():
        scan_mode = 'quick'
        utils.log_info("Auto-run mode: defaulting to Quick Scan")
    else:
        scan_mode = _prompt_scan_mode()

    # Region selection
    regions = utils.prompt_region_selection()

    # Discovery
    print(f"\n  Running {scan_mode.title()} Scan across {len(regions)} region(s)...\n")
    services, errors = discover_services(regions, mode=scan_mode)

    if not services:
        utils.log_warning("No services with resources found.")
        return

    if errors:
        utils.log_warning(f"  {len(errors)} service(s) had unexpected check failures (see log)")

    # Console summary
    _print_discovery_summary(services, scan_mode)

    # Recommendations — in-memory, no Excel roundtrip
    utils.log_info("Generating recommendations...")
    recommendations = analyze_services_from_dict(services)

    n_scripts = len(recommendations.get('all_scripts', set()))
    n_baseline = len(recommendations.get('always_run', []))
    n_service = recommendations.get('coverage_stats', {}).get('service_based_count', 0)
    print(
        f"\n  Recommended scripts: {n_scripts}"
        f"  ({n_baseline} security baseline + {n_service} service-specific)"
    )

    # Write Markdown report
    md_path = _write_markdown_report(
        services, recommendations, account_name, account_id, regions, scan_mode
    )
    if md_path:
        utils.log_success(f"  Report saved: {md_path}")

    # Write Excel report (existing pipeline)
    try:
        summary_data = generate_summary(services)
        df_summary = pd.DataFrame(summary_data)
        df_summary = utils.prepare_dataframe_for_export(df_summary)

        df_details = create_detailed_export(services)
        df_details = utils.prepare_dataframe_for_export(df_details)

        category_sheets = create_category_sheets(services)

        df_recs = create_recommendations_sheet(services)
        df_recs = utils.prepare_dataframe_for_export(df_recs)

        dataframes: Dict[str, Any] = {
            'Summary': df_summary,
            'Recommended Scripts': df_recs,
            'All Services': df_details,
        }
        for category, df in category_sheets.items():
            sheet_name = category.replace(' Resources', '').replace('&', 'and')[:31]
            dataframes[sheet_name] = utils.prepare_dataframe_for_export(df)

        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'services-in-use', region_suffix)
        utils.save_multiple_dataframes_to_excel(dataframes, filename)
        utils.log_success(f"  Excel saved: {utils.get_output_filepath(filename)}")
    except Exception as e:
        utils.log_warning(f"Excel export failed (continuing): {e}")

    # Execution prompt — skip in CI/headless mode
    if utils.is_auto_run():
        utils.log_info("Auto-run mode: skipping execution prompt")
        return

    print()
    print("  ─── RUN SCRIPTS ─────────────────────────────────────────────")
    print(f"  {n_scripts} export scripts are recommended for this account.")
    print("  [Y] Run all recommended scripts now")
    print("  [N] Exit — report saved, run scripts later")
    print("  [C] Customize — choose specific scripts to run")
    print("  ─────────────────────────────────────────────────────────────")
    choice = input("  Enter choice [N]: ").strip().upper() or "N"

    if choice == 'N':
        utils.log_info("Exiting. Reports saved.")
        return

    selected_scripts = recommendations.get('all_scripts', set())

    if choice == 'C':
        try:
            from smart_scan.selector import interactive_select, QUESTIONARY_AVAILABLE
            if QUESTIONARY_AVAILABLE:
                selected_scripts = interactive_select(recommendations) or set()
            else:
                utils.log_warning("questionary not installed — running all recommended scripts")
        except ImportError:
            utils.log_warning("Selector unavailable — running all recommended scripts")

    if not selected_scripts:
        utils.log_info("No scripts selected. Exiting.")
        return

    print(f"\n  Executing {len(selected_scripts)} scripts...\n")
    summary = execute_scripts(
        selected_scripts,
        show_progress=True,
        save_log=True,
        regions=regions,
        show_output=True,
    )

    print()
    print("=" * 70)
    print("  EXECUTION COMPLETE")
    print("=" * 70)
    print(f"  Total:        {summary['total']}")
    print(f"  Successful:   {summary['successful']}")
    print(f"  Failed:       {summary['failed']}")
    print(f"  Success Rate: {summary['success_rate']:.1f}%")
    print("=" * 70)


if __name__ == "__main__":
    main()
