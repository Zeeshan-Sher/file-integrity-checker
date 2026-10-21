#!/usr/bin/env python3
"""File Integrity Checker command-line application."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys

from core.baseline import load_baseline, save_baseline, signature_path
from core.comparer import compare_files, has_changes
from core.reporter import log_changes, write_csv_report, write_html_report
from core.scanner import scan_directory


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("folder", help="Directory to monitor")
    parser.add_argument("--baseline", default="baseline.json", help="Baseline JSON path (default: ./baseline.json)")
    parser.add_argument("--log", default="logs/integrity.log", help="Log file (default: ./logs/integrity.log)")
    parser.add_argument("--report-dir", default="reports", help="Directory for generated reports (default: ./reports)")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN", help="Exclude a relative path/glob; may be repeated")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect new, modified, and deleted files using SHA-256 fingerprints.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser("init", help="Create a first trusted baseline")
    _add_common(init_parser)
    init_parser.add_argument("--force", action="store_true", help="Replace an existing baseline")
    check_parser = subparsers.add_parser("check", help="Compare the current folder with its baseline")
    _add_common(check_parser)
    update_parser = subparsers.add_parser("update", help="Compare, report, then refresh the trusted baseline")
    _add_common(update_parser)
    report_parser = subparsers.add_parser("report", help="Run a check and generate HTML and CSV reports")
    _add_common(report_parser)
    return parser


def _paths_to_exclude(args: argparse.Namespace, root: Path) -> tuple[list[Path], list[str]]:
    baseline = Path(args.baseline).expanduser().resolve(strict=False)
    log = Path(args.log).expanduser().resolve(strict=False)
    report_dir = Path(args.report_dir).expanduser().resolve(strict=False)
    ignored = [baseline, signature_path(baseline).resolve(strict=False), log]
    patterns = list(args.exclude)
    try:
        report_relative = report_dir.relative_to(root).as_posix()
        if report_relative != ".":
            patterns.extend([report_relative, report_relative + "/*"])
    except ValueError:
        pass
    return ignored, patterns


def _scan(args: argparse.Namespace, root: Path) -> dict:
    excluded, patterns = _paths_to_exclude(args, root)
    return scan_directory(root, exclude_patterns=patterns, exclude_paths=excluded)


def _write_reports(args: argparse.Namespace, changes: dict) -> tuple[Path, Path]:
    folder = Path(args.report_dir).expanduser()
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    html_path = write_html_report(changes, folder / f"integrity-{stamp}.html")
    csv_path = write_csv_report(changes, folder / f"integrity-{stamp}.csv")
    return html_path, csv_path


def _print_summary(changes: dict) -> None:
    for category in ("modified", "new", "deleted"):
        items = changes[category]
        print(f"{category.title():9}: {len(items)}")
        for item in items:
            print(f"  - {item['path']}")
    print("Status: CHANGES DETECTED" if has_changes(changes) else "Status: CLEAN")


def run(args: argparse.Namespace) -> int:
    root = Path(args.folder).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")
    baseline_path = Path(args.baseline).expanduser()

    if args.command == "init":
        if baseline_path.exists() and not args.force:
            raise FileExistsError(f"Baseline already exists: {baseline_path}. Use --force to replace it.")
        files = _scan(args, root)
        save_baseline(baseline_path, root, files)
        print(f"Baseline created: {baseline_path.resolve()} ({len(files)} files)")
        print(f"Baseline SHA-256 sidecar: {signature_path(baseline_path).resolve()}")
        return 0

    baseline = load_baseline(baseline_path)
    current = _scan(args, root)
    changes = compare_files(baseline["files"], current)
    log_changes(changes, args.log)
    _print_summary(changes)
    html_report, csv_report = _write_reports(args, changes)
    print(f"HTML report: {html_report.resolve()}")
    print(f"CSV report:  {csv_report.resolve()}")

    if args.command == "update":
        # Update intentionally adopts the current state as trusted after reporting differences.
        save_baseline(baseline_path, root, current)
        print(f"Baseline refreshed: {baseline_path.resolve()} ({len(current)} files)")
        return 0
    return 1 if has_changes(changes) else 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
