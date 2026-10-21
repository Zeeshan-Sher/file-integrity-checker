"""Read/write the trusted baseline and its external SHA-256 sidecar."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
from typing import Any

FORMAT_VERSION = 1


def signature_path(baseline_path: str | Path) -> Path:
    path = Path(baseline_path)
    return path.with_name(path.name + ".sha256")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def save_baseline(path: str | Path, root: str | Path, files: dict[str, dict[str, Any]]) -> None:
    """Write a baseline and a separate digest file used to detect accidental edits."""
    baseline = {
        "format_version": FORMAT_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": str(Path(root).expanduser().resolve()),
        "files": files,
    }
    data = (json.dumps(baseline, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    _atomic_write(Path(path), data)
    _atomic_write(signature_path(path), f"{digest}  {Path(path).name}\n".encode("ascii"))


def load_baseline(path: str | Path, verify: bool = True) -> dict[str, Any]:
    """Load and validate baseline JSON; fail closed if its signature is absent or wrong."""
    baseline_file = Path(path)
    if not baseline_file.is_file():
        raise FileNotFoundError(f"Baseline not found: {baseline_file}")
    raw = baseline_file.read_bytes()
    if verify:
        sig_file = signature_path(baseline_file)
        if not sig_file.is_file():
            raise ValueError(f"Baseline signature is missing: {sig_file}. Re-create the baseline with init.")
        expected = sig_file.read_text(encoding="ascii").strip().split()[0]
        actual = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(expected, actual):
            raise ValueError("Baseline integrity check failed: baseline.json does not match its .sha256 sidecar.")
    try:
        baseline = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid baseline JSON: {exc}") from exc
    if baseline.get("format_version") != FORMAT_VERSION or not isinstance(baseline.get("files"), dict):
        raise ValueError("Unsupported or malformed baseline format.")
    for relative, entry in baseline["files"].items():
        if not isinstance(relative, str) or not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
            raise ValueError("Malformed file entry in baseline.")
    return baseline
