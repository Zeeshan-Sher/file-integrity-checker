"""Directory traversal and file fingerprinting."""
from __future__ import annotations

from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
import os

from .hasher import sha256_file

DEFAULT_EXCLUDES = (".git", ".venv", "venv", "__pycache__", ".pytest_cache")


def _is_excluded(relative: str, patterns: tuple[str, ...]) -> bool:
    parts = relative.split("/")
    return any(
        fnmatch(relative, pattern) or any(fnmatch(part, pattern) for part in parts)
        for pattern in patterns
    )


def scan_directory(
    root: str | Path,
    exclude_patterns: tuple[str, ...] | list[str] = (),
    exclude_paths: tuple[str | Path, ...] | list[str | Path] = (),
) -> dict[str, dict[str, object]]:
    """Scan regular files under root and return fingerprints keyed by relative POSIX path.

    Symlinks are deliberately skipped so traversal cannot escape the selected tree or loop.
    Individual files that disappear or become unreadable during a scan are skipped; callers
    should review stderr/log output if their use case requires strict completeness.
    """
    base = Path(root).expanduser().resolve(strict=True)
    if not base.is_dir():
        raise NotADirectoryError(f"Not a directory: {base}")

    patterns = tuple(DEFAULT_EXCLUDES) + tuple(exclude_patterns)
    ignored = {Path(p).expanduser().resolve(strict=False) for p in exclude_paths}
    results: dict[str, dict[str, object]] = {}

    def on_walk_error(error: OSError) -> None:
        raise error

    for current, directories, filenames in os.walk(base, topdown=True, followlinks=False, onerror=on_walk_error):
        current_path = Path(current)
        directories[:] = sorted(
            name for name in directories
            if not (current_path / name).is_symlink()
            and not _is_excluded((current_path / name).relative_to(base).as_posix(), patterns)
        )
        for filename in sorted(filenames):
            path = current_path / filename
            relative = path.relative_to(base).as_posix()
            if path.is_symlink() or _is_excluded(relative, patterns):
                continue
            if path.resolve(strict=False) in ignored or not path.is_file():
                continue
            try:
                stat = path.stat()
                digest = sha256_file(path)
                # Check metadata after hashing to reduce inconsistent fingerprints if a file
                # changes while it is being read. The next check will detect any later change.
                after = path.stat()
                if (stat.st_size, stat.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    stat = after
                    digest = sha256_file(path)
                    after = path.stat()
                    if (stat.st_size, stat.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        raise OSError("file changed repeatedly while being scanned")
                results[relative] = {
                    "sha256": digest,
                    "size": int(after.st_size),
                    "modified_time": datetime.fromtimestamp(after.st_mtime, timezone.utc).isoformat(),
                    "modified_time_ns": int(after.st_mtime_ns),
                }
            except (OSError, PermissionError) as exc:
                print(f"Warning: skipped {relative}: {exc}")
    return results
