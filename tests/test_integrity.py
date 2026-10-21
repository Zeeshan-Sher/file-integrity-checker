"""Unit tests for hashing, baseline integrity, and tamper detection."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from core.baseline import load_baseline, save_baseline
from core.comparer import compare_files, has_changes
from core.hasher import sha256_file
from core.scanner import scan_directory


class IntegrityCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.monitored = self.base / "monitored"
        self.monitored.mkdir()
        self.baseline = self.base / "baseline.json"

    def tearDown(self):
        self.temp.cleanup()

    def inventory(self):
        return scan_directory(self.monitored)

    def test_sha256_empty_file(self):
        empty = self.monitored / "empty.bin"
        empty.write_bytes(b"")
        self.assertEqual(sha256_file(empty), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_hashes_across_chunk_boundary(self):
        sample = self.monitored / "large.dat"
        sample.write_bytes(b"abc123" * 2000)
        import hashlib
        self.assertEqual(sha256_file(sample), hashlib.sha256(sample.read_bytes()).hexdigest())

    def test_clean_scan_has_no_changes(self):
        (self.monitored / "one.txt").write_text("steady", encoding="utf-8")
        snapshot = self.inventory()
        save_baseline(self.baseline, self.monitored, snapshot)
        loaded = load_baseline(self.baseline)
        self.assertFalse(has_changes(compare_files(loaded["files"], self.inventory())))

    def test_detects_modified_new_and_deleted_files(self):
        (self.monitored / "modify.txt").write_text("before", encoding="utf-8")
        (self.monitored / "delete.txt").write_text("remove", encoding="utf-8")
        save_baseline(self.baseline, self.monitored, self.inventory())
        (self.monitored / "modify.txt").write_text("after", encoding="utf-8")
        (self.monitored / "delete.txt").unlink()
        (self.monitored / "new.txt").write_text("added", encoding="utf-8")
        changes = compare_files(load_baseline(self.baseline)["files"], self.inventory())
        self.assertEqual([x["path"] for x in changes["modified"]], ["modify.txt"])
        self.assertEqual([x["path"] for x in changes["new"]], ["new.txt"])
        self.assertEqual([x["path"] for x in changes["deleted"]], ["delete.txt"])

    def test_detects_baseline_tampering(self):
        (self.monitored / "file.txt").write_text("safe", encoding="utf-8")
        save_baseline(self.baseline, self.monitored, self.inventory())
        content = json.loads(self.baseline.read_text(encoding="utf-8"))
        content["files"]["file.txt"]["sha256"] = "0" * 64
        self.baseline.write_text(json.dumps(content), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "integrity check failed"):
            load_baseline(self.baseline)

    def test_missing_signature_is_rejected(self):
        save_baseline(self.baseline, self.monitored, self.inventory())
        self.baseline.with_name(self.baseline.name + ".sha256").unlink()
        with self.assertRaisesRegex(ValueError, "signature is missing"):
            load_baseline(self.baseline)

    def test_touch_without_content_change_is_not_modified(self):
        path = self.monitored / "file.txt"
        path.write_text("unchanged", encoding="utf-8")
        old = self.inventory()
        path.touch()
        new = self.inventory()
        self.assertFalse(has_changes(compare_files(old, new)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
