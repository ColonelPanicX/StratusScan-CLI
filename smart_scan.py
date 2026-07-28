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

import os
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

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
        create_category_sheets,
        create_detailed_export,
        create_recommendations_sheet,
        discover_services,
        generate_summary,
    )
except ImportError as exc:
    utils.log_error(f"Could not import services_in_use_export: {exc}", exc)
    sys.exit(1)

try:
    from smart_scan.analyzer import analyze_services_from_dict
    from smart_scan.executor import execute_scripts
    from smart_scan.mapping import (
        ALWAYS_RUN_SCRIPTS,  # noqa: F401  # part of the import-or-die package check
    )
except ImportError as exc:
    utils.log_error(f"Could not import smart_scan package: {exc}", exc)
    sys.exit(1)


def _prompt_scan_mode() -> str:
    """Prompt user for Quick or Deep scan mode. Exits on b/x/q."""
    try:
        choice = utils.prompt_menu(
            "SCAN MODE",
            [
                "Quick Scan  — discover services, save a report, done",
                "Deep Scan   — discover services, then run export scripts",
            ],
        )
    except (utils.BackSignal, utils.ExitToMainSignal, utils.QuitSignal):
        sys.exit(0)
    return 'deep' if choice == 2 else 'quick'


def _format_detail(detail: dict[str, int]) -> str:
    """Format a detail dict as a readable inline string."""
    return "  |  ".join(f"{k}: {v}" for k, v in detail.items() if v > 0)


def _print_discovery_summary(
    services: dict[str, Any],
    recommendations: Optional[dict[str, Any]] = None,
) -> None:
    """Print formatted discovery results to console (Deep Scan only)."""
    print()
    print("=" * 70)
    print("  SERVICES DISCOVERED")
    print("=" * 70)

    # Group by category
    by_category: dict[str, list] = {}
    for name, data in sorted(services.items()):
        cat = data['category']
        by_category.setdefault(cat, []).append((name, data))

    service_scripts = (recommendations or {}).get('service_based', {})

    for category, items in sorted(by_category.items()):
        print(f"\n  {category}")
        print(f"  {'─' * 60}")
        for name, data in items:
            capped = data.get('capped', False)
            count_str = f"{'500+':>5}" if capped else f"{data['count']:>5}"
            print(f"  {name:<35} {count_str} {data['unit']}")
            if data.get('detail'):
                print(f"    └─ {_format_detail(data['detail'])}")
            if data['regional'] and data['regions']:
                region_breakdown = "  |  ".join(
                    f"{r}: {c}" for r, c in sorted(data['regions'].items())
                )
                print(f"    └─ {region_breakdown}")
            else:
                print("    └─ global")
            if capped:
                scripts = service_scripts.get(name, [])
                script_hint = f" — run {scripts[0]} for the complete inventory" if scripts else ""
                print(f"    └─ 500+ found{script_hint}")

    total_resources = sum(s['count'] for s in services.values())
    print()
    print("=" * 70)
    print(f"  Total services: {len(services)}   Total resources: {total_resources:,}")
    print("=" * 70)


def _write_quick_scan_excel(
    recommendations: dict[str, Any],
    account_name: str,
    regions: list[str],
) -> None:
    """
    Write a minimal two-column Excel for Quick Scan results.

    Columns: Service In Use | Recommended Script
    One row per service × script pair. Security baseline scripts are
    grouped under a 'Security Baseline' service label.
    """
    rows = []

    for script in sorted(recommendations.get('always_run', [])):
        rows.append({'Service In Use': 'Security Baseline', 'Recommended Script': script})

    for service_name, scripts in sorted(recommendations.get('service_based', {}).items()):
        for script in sorted(scripts):
            rows.append({'Service In Use': service_name, 'Recommended Script': script})

    if not rows:
        return

    df = pd.DataFrame(rows)
    df = utils.prepare_dataframe_for_export(df)

    region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
    filename = utils.create_export_filename(account_name, 'quick-scan', region_suffix)
    utils.save_dataframe_to_excel(df, filename)
    utils.log_success(f"  Excel saved: {utils.get_output_filepath(filename)}")


def _write_markdown_report(
    services: dict[str, Any],
    recommendations: dict[str, Any],
    account_name: str,
    account_id: str,
    regions: list[str],
    mode: str,
    crosscheck: Optional[dict[str, Any]] = None,
) -> Optional[Path]:
    """
    Write discovery report as Markdown to reports/ directory.

    Returns the path to the written file, or None on failure.
    """
    reports_dir = _root / 'reports'
    reports_dir.mkdir(exist_ok=True)

    mode_label = 'deep' if mode == 'deep' else 'quick'
    timestamp = utils.get_export_date()
    filename = f"{account_name}-discovery-{mode_label}-{timestamp}.md"
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
    by_category: dict[str, list] = {}
    for name, data in sorted(services.items()):
        by_category.setdefault(data['category'], []).append((name, data))

    service_scripts = recommendations.get('service_based', {})

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
                count_str = '500+' if data.get('capped') else str(data['count'])
                if data.get('capped'):
                    scripts = service_scripts.get(name, [])
                    if scripts:
                        detail_str = f"500+ found — run `{scripts[0]}` for complete data"
                lines.append(
                    f"| {name} | {count_str} | {data['unit']} | {region_str} | {detail_str} |"
                )
        else:
            lines.append("| Service | Count | Unit | Regions |")
            lines.append("|---|---|---|---|")
            for name, data in items:
                region_str = (
                    ', '.join(sorted(data['regions'])) if data['regional'] else 'global'
                )
                count_str = '500+' if data.get('capped') else str(data['count'])
                lines.append(
                    f"| {name} | {count_str} | {data['unit']} | {region_str} |"
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

    lines += _crosscheck_markdown_lines(crosscheck)

    try:
        filepath.write_text('\n'.join(lines), encoding='utf-8')
        return filepath
    except Exception as e:
        utils.log_warning(f"Failed to write Markdown report: {e}")
        return None


def _zip_export_files(results: list, account_name: str) -> Optional[Path]:
    """
    Zip all output files produced by the batch execution into a single archive.

    Args:
        results: List of ExecutionResult objects from execute_all()
        account_name: AWS account name (used in the zip filename)

    Returns:
        Path to the zip file, or None if no files to zip or on failure.
    """
    output_files = [Path(r.output_file) for r in results if r.output_file]
    if not output_files:
        return None

    timestamp = utils.get_export_date()
    zip_name = f"{account_name}-service-discovery-export-{timestamp}.zip"
    zip_path = utils.get_output_dir() / zip_name

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in output_files:
                if file_path.exists():
                    zf.write(file_path, file_path.name)

        # Remove individual files now that they are safely inside the zip
        for file_path in output_files:
            try:
                file_path.unlink(missing_ok=True)
            except Exception as e:
                utils.log_warning(f"Could not remove {file_path.name} after zipping: {e}")

        return zip_path
    except Exception as e:
        utils.log_warning(f"Failed to create zip archive: {e}")
        return None


def _resume_from_session(session_path: str) -> None:
    """
    Execute the remaining scripts from an interrupted smart-scan session.
    Skips service discovery entirely — uses the planned list from the session file.
    """
    import json
    try:
        session: dict = json.loads(Path(session_path).read_text(encoding="utf-8"))
        session["_path"] = session_path
    except Exception as exc:
        print(f"\n  ❌ Could not load session: {exc}")
        return

    done_keys = {r["key"] for r in session.get("results", []) if r.get("status") == "success"}
    all_planned = {p["key"] for p in session.get("planned", [])}
    remaining = all_planned - done_keys

    n_done = len(done_keys)
    n_total = len(session.get("planned", []))

    print(f"\n  Resuming Smart Scan: {n_done}/{n_total} scripts already complete")
    print(f"  {len(remaining)} script(s) remaining\n")

    if not remaining:
        print("  ✅ All scripts already completed.")
        utils.complete_scan_session(session)
        return

    regions = utils.prompt_region_selection()
    utils.resume_scan_session(session)

    print(f"\n  Executing {len(remaining)} scripts...\n")
    execute_scripts(
        remaining,
        show_progress=True,
        save_log=False,
        regions=regions,
        show_output=False,
        session=session,
        skip_scripts=None,
    )


def _run_bill_crosscheck(
    services: dict[str, Any], regions: list[str]
) -> Optional[dict[str, Any]]:
    """Run the Cost Explorer ground-truth cross-check unless opted out.

    Never raises — returns the cross-check result, a skip status dict, or None
    when disabled/unavailable so callers can always proceed.
    """
    if os.environ.get("STRATUSSCAN_SKIP_BILL_CROSSCHECK") == "1":
        utils.log_info("Bill cross-check disabled (STRATUSSCAN_SKIP_BILL_CROSSCHECK=1)")
        return None
    try:
        from smart_scan.bill_crosscheck import run_crosscheck
    except ImportError as exc:
        utils.log_warning(f"Bill cross-check unavailable: {exc}")
        return None
    partition = utils.detect_partition(regions[0]) if regions else None
    return run_crosscheck(set(services.keys()), partition=partition)


# (result bucket, human label) in audit-priority order.
_CROSSCHECK_STATUS_ORDER = [
    ('not_collected', 'SPEND, NOT COLLECTED'),
    ('confirmed', 'CONFIRMED'),
    ('unmapped', 'SPEND, UNMAPPED'),
    ('ignored', 'IGNORED (billing line item)'),
]


def _crosscheck_dataframe(result: dict[str, Any]) -> "pd.DataFrame":
    """Flatten a cross-check result into a single status-tagged DataFrame."""
    rows = []
    for bucket, label in _CROSSCHECK_STATUS_ORDER:
        for r in result.get(bucket, []):
            rows.append({
                'Status': label,
                'Billed Service (Cost Explorer)': r['ce_service'],
                'Mapped Service': r.get('service', ''),
                'Monthly Cost (USD)': r['monthly_cost'],
                'Exporters': ', '.join(r.get('exporters', [])),
            })
    return pd.DataFrame(rows)


def _crosscheck_markdown_lines(result: Optional[dict[str, Any]]) -> list[str]:
    """Render the cross-check as a Markdown report section."""
    if not result:
        return []
    lines = ["---", "", "## Bill Cross-Check", ""]
    if result.get('status') != 'ok':
        return lines + [f"_Skipped: {result.get('reason', 'unavailable')}_", ""]

    p = result['period']
    lines += [
        f"Cost Explorer spend for {p['start']} to {p['end']} "
        f"({result['total_services_billed']} billed services), reconciled against discovery.",
        "",
    ]
    not_collected = result.get('not_collected', [])
    if not_collected:
        lines += [
            "### ⚠ Spend detected but NOT collected",
            "",
            "| Billed Service | Mapped Service | Monthly Cost (USD) | Exporter(s) |",
            "|---|---|---|---|",
        ]
        for r in not_collected:
            lines.append(
                f"| {r['ce_service']} | {r['service']} | {r['monthly_cost']:,.2f} "
                f"| {', '.join(r['exporters'])} |"
            )
        lines.append("")
    else:
        lines += ["Every billed service was discovered. ✅", ""]

    unmapped = result.get('unmapped', [])
    if unmapped:
        lines += [
            "### Billed but unmapped (no known service)",
            "",
            "| Billed Service | Monthly Cost (USD) |",
            "|---|---|",
        ]
        for r in unmapped:
            lines.append(f"| {r['ce_service']} | {r['monthly_cost']:,.2f} |")
        lines.append("")
    return lines


def _print_crosscheck_summary(result: Optional[dict[str, Any]]) -> None:
    """Print a concise cross-check summary to the console."""
    if not result:
        return
    if result.get('status') != 'ok':
        print(f"\n  Bill cross-check skipped: {result.get('reason', 'unavailable')}")
        return
    not_collected = result.get('not_collected', [])
    unmapped = result.get('unmapped', [])
    print()
    print("  ─── BILL CROSS-CHECK ────────────────────────────────────────")
    print(
        f"  Period {result['period']['start']} → {result['period']['end']}  "
        f"({result['total_services_billed']} billed services)"
    )
    if not_collected:
        print(f"  ⚠ {len(not_collected)} service(s) with spend NOT collected by discovery:")
        for r in not_collected[:10]:
            print(f"      ${r['monthly_cost']:>12,.2f}  {r['service']}")
        if len(not_collected) > 10:
            print(f"      ... and {len(not_collected) - 10} more (see report)")
    else:
        print("  ✓ Every billed service was discovered.")
    if unmapped:
        print(f"  • {len(unmapped)} billed service(s) could not be mapped (see report).")
    print("  ─────────────────────────────────────────────────────────────")


def main() -> None:
    """Main Smart Scan workflow."""
    utils.log_script_start('smart-scan')

    # Startup resume: stratusscan.py passes session path via env var
    resume_path = os.environ.get("STRATUSSCAN_RESUME_SESSION_PATH", "")
    if resume_path:
        utils.print_script_banner("SMART SCAN — RESUME INTERRUPTED SESSION")
        _resume_from_session(resume_path)
        return

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

    # Bill cross-check (Cost Explorer ground truth). Opt out with
    # STRATUSSCAN_SKIP_BILL_CROSSCHECK=1; skips cleanly in GovCloud / without perms.
    crosscheck = _run_bill_crosscheck(services, regions)
    _print_crosscheck_summary(crosscheck)

    # Quick Scan: write lightweight reports and exit
    if scan_mode == 'quick':
        md_path = _write_markdown_report(
            services, recommendations, account_name, account_id, regions, scan_mode,
            crosscheck=crosscheck,
        )
        if md_path:
            utils.log_success(f"  Report saved: {md_path}")

        _write_quick_scan_excel(recommendations, account_name, regions)

        print()
        print("  Quick Scan complete.")
        print(f"  {n_scripts} export scripts are recommended for this account.")
        print("  Run a Deep Scan or individual scripts to collect full resource data.")
        if not utils.is_auto_run():
            input("\n  Press Enter to return to menu...")
        return

    # Deep Scan: show full discovery table
    _print_discovery_summary(services, recommendations=recommendations)

    # Write Markdown report
    md_path = _write_markdown_report(
        services, recommendations, account_name, account_id, regions, scan_mode,
        crosscheck=crosscheck,
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

        dataframes: dict[str, Any] = {
            'Summary': df_summary,
            'Recommended Scripts': df_recs,
            'All Services': df_details,
        }
        for category, df in category_sheets.items():
            sheet_name = category.replace(' Resources', '').replace('&', 'and')[:31]
            dataframes[sheet_name] = utils.prepare_dataframe_for_export(df)

        if crosscheck and crosscheck.get('status') == 'ok':
            df_cc = _crosscheck_dataframe(crosscheck)
            if not df_cc.empty:
                dataframes['Bill Cross-Check'] = utils.prepare_dataframe_for_export(df_cc)

        region_suffix = 'all-regions' if len(regions) > 1 else regions[0]
        filename = utils.create_export_filename(account_name, 'services-in-use', region_suffix)
        utils.save_multiple_dataframes_to_excel(dataframes, filename)
        utils.log_success(f"  Excel saved: {utils.get_output_filepath(filename)}")
    except Exception as e:
        utils.log_warning(f"Excel export failed (continuing): {e}")

    # Deep Scan: prompt to execute recommended scripts
    # Skip execution prompt in CI/headless mode
    if utils.is_auto_run():
        utils.log_info("Auto-run mode: skipping execution prompt")
        return

    print()
    print(f"  {n_scripts} export scripts are recommended for this account.")
    try:
        gate = utils.prompt_menu(
            "RUN SCRIPTS",
            [
                "Run all recommended scripts now",
                "Exit — report saved, run scripts later",
                "Customize — choose specific scripts to run",
            ],
        )
    except (utils.BackSignal, utils.ExitToMainSignal, utils.QuitSignal):
        utils.log_info("Exiting. Reports saved.")
        return

    if gate == 2:
        utils.log_info("Exiting. Reports saved.")
        return

    selected_scripts = recommendations.get('all_scripts', set())

    if gate == 3:
        # interactive_select handles the questionary / plain-text fallback itself.
        try:
            from smart_scan.selector import interactive_select
            selected_scripts = interactive_select(recommendations) or set()
        except ImportError:
            utils.log_warning("Selector unavailable — running all recommended scripts")

    if not selected_scripts:
        utils.log_info("No scripts selected. Exiting.")
        return

    # Build planned list for session persistence
    planned = [{"key": s, "script": s} for s in sorted(selected_scripts)]

    # Offer resume of an interrupted smart-scan session
    session: dict
    skip_scripts: Optional[set] = None
    interrupted_smart = [
        s for s in utils.get_interrupted_sessions()
        if s.get("scan_type") == "smart-scan"
    ]
    if interrupted_smart and not utils.is_auto_run():
        prev = interrupted_smart[0]
        n_done = len(prev.get("results", []))
        n_total = len(prev.get("planned", []))
        if utils.prompt_for_confirmation(
            f"Resume interrupted smart scan? ({n_done}/{n_total} scripts done)",
            default=False,
        ):
            utils.resume_scan_session(prev)
            session = prev
            done_keys = {r["key"] for r in prev.get("results", []) if r.get("status") == "success"}
            selected_scripts = selected_scripts - done_keys
            skip_scripts = None  # already filtered from selected_scripts
        else:
            session = utils.start_scan_session(
                "smart-scan",
                f"Smart Scan ({len(selected_scripts)} scripts)",
                planned,
            )
    else:
        session = utils.start_scan_session(
            "smart-scan",
            f"Smart Scan ({len(selected_scripts)} scripts)",
            planned,
        )

    print(f"\n  Executing {len(selected_scripts)} scripts...\n")
    summary = execute_scripts(
        selected_scripts,
        show_progress=True,
        save_log=True,
        regions=regions,
        show_output=False,
        session=session,
        skip_scripts=skip_scripts,
    )

    # Zip all output files produced by this run
    zip_path = _zip_export_files(summary.get('results', []), account_name)
    if zip_path:
        utils.log_success(f"  Exports zipped: {zip_path}")

    print()
    print("=" * 70)
    print("  EXECUTION COMPLETE")
    print("=" * 70)
    print(f"  Total:        {summary['total']}")
    print(f"  Successful:   {summary['successful']}")
    print(f"  Failed:       {summary['failed']}")
    print(f"  Success Rate: {summary['success_rate']:.1f}%")
    print("=" * 70)
    if not utils.is_auto_run():
        input("\n  Press Enter to return to menu...")


if __name__ == "__main__":
    main()
