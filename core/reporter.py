"""Human-readable reports and append-only local event logging."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import html
import logging
from pathlib import Path
from typing import Any

CATEGORIES = ("modified", "new", "deleted")


def configure_logger(log_path: str | Path = "logs/integrity.log") -> logging.Logger:
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("file_integrity_checker")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    target = str(path.resolve())
    if not any(isinstance(handler, logging.FileHandler) and handler.baseFilename == target for handler in logger.handlers):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s UTC %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
        logger.addHandler(handler)
    return logger


def log_changes(changes: dict[str, list[dict[str, Any]]], log_path: str | Path = "logs/integrity.log") -> None:
    logger = configure_logger(log_path)
    if not any(changes.get(category) for category in CATEGORIES):
        logger.info("Check completed: no content changes detected.")
        return
    for category in CATEGORIES:
        for item in changes.get(category, []):
            logger.warning("%s: %s", category.upper(), item["path"])


def _rows(changes: dict[str, list[dict[str, Any]]]):
    for category in CATEGORIES:
        for item in changes.get(category, []):
            before, after = item.get("before", {}), item.get("after", {})
            yield {
                "status": category,
                "path": item["path"],
                "previous_sha256": before.get("sha256", ""),
                "current_sha256": after.get("sha256", ""),
                "previous_size": before.get("size", ""),
                "current_size": after.get("size", ""),
                "previous_modified_time": before.get("modified_time", ""),
                "current_modified_time": after.get("modified_time", ""),
            }


def write_csv_report(changes: dict[str, list[dict[str, Any]]], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["status", "path", "previous_sha256", "current_sha256", "previous_size", "current_size", "previous_modified_time", "current_modified_time"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(_rows(changes))
    return path


def write_html_report(changes: dict[str, list[dict[str, Any]]], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()
    sections = []
    for category in CATEGORIES:
        entries = changes.get(category, [])
        if entries:
            rows = "".join(f"<tr><td>{html.escape(item['path'])}</td><td>{html.escape(str(item.get('before', {}).get('sha256', '')))}</td><td>{html.escape(str(item.get('after', {}).get('sha256', '')))}</td></tr>" for item in entries)
            sections.append(f"<section><h2>{category.title()} ({len(entries)})</h2><table><thead><tr><th>Path</th><th>Previous SHA-256</th><th>Current SHA-256</th></tr></thead><tbody>{rows}</tbody></table></section>")
        else:
            sections.append(f"<section><h2>{category.title()} (0)</h2><p>None</p></section>")
    body = "\n".join(sections)
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>File Integrity Report</title><style>body{{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}}h1{{color:#123b63}}table{{border-collapse:collapse;width:100%;margin:1rem 0 2rem}}th,td{{border:1px solid #ccd4df;padding:.55rem;text-align:left;overflow-wrap:anywhere}}th{{background:#eef3f8}}code{{font-size:.85em}}</style></head>
<body><h1>File Integrity Report</h1><p>Generated: {html.escape(timestamp)}</p>{body}</body></html>"""
    path.write_text(document, encoding="utf-8")
    return path
