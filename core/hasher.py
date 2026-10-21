"""Chunked SHA-256 helpers."""
from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 4096


def sha256_file(path: str | Path, chunk_size: int = CHUNK_SIZE) -> str:
    """Return the SHA-256 hex digest of a file, reading it in bounded chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    digest = hashlib.sha256()
    with Path(path).open("rb") as file_handle:
        while chunk := file_handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()
