"""Compare two file inventories."""
from __future__ import annotations
from typing import Any


def compare_files(
    baseline_files: dict[str, dict[str, Any]], current_files: dict[str, dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Return deterministic lists for modified, new, and deleted files.

    Content hash determines modification; metadata-only changes (for example, touching a file)
    are intentionally not reported as content changes.
    """
    old_paths, new_paths = set(baseline_files), set(current_files)
    modified = [
        {"path": name, "before": baseline_files[name], "after": current_files[name]}
        for name in sorted(old_paths & new_paths)
        if baseline_files[name].get("sha256") != current_files[name].get("sha256")
    ]
    new = [{"path": name, "after": current_files[name]} for name in sorted(new_paths - old_paths)]
    deleted = [{"path": name, "before": baseline_files[name]} for name in sorted(old_paths - new_paths)]
    return {"modified": modified, "new": new, "deleted": deleted}


def has_changes(changes: dict[str, list[dict[str, Any]]]) -> bool:
    return any(changes.get(category) for category in ("modified", "new", "deleted"))
