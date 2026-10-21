"""Optional Tkinter front end for basic baseline/check operations."""
from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from core.baseline import load_baseline, save_baseline
from core.comparer import compare_files, has_changes
from core.scanner import scan_directory
from core.reporter import log_changes, write_csv_report, write_html_report
from datetime import datetime, timezone


class IntegrityCheckerGUI:
    def __init__(self, window: tk.Tk):
        self.window = window
        self.window.title("File Integrity Checker")
        self.window.geometry("740x500")
        self.folder = tk.StringVar()
        tk.Label(window, text="Folder to monitor:").pack(anchor="w", padx=12, pady=(12, 0))
        row = tk.Frame(window)
        row.pack(fill="x", padx=12, pady=6)
        tk.Entry(row, textvariable=self.folder).pack(side="left", fill="x", expand=True)
        tk.Button(row, text="Browse…", command=self.browse).pack(side="left", padx=(8, 0))
        buttons = tk.Frame(window)
        buttons.pack(anchor="w", padx=12, pady=4)
        tk.Button(buttons, text="Create baseline", command=self.initialize).pack(side="left", padx=(0, 8))
        tk.Button(buttons, text="Check now", command=self.check).pack(side="left", padx=(0, 8))
        tk.Button(buttons, text="Update baseline", command=self.update).pack(side="left")
        self.output = scrolledtext.ScrolledText(window, wrap="word", height=20)
        self.output.pack(fill="both", expand=True, padx=12, pady=12)
        self.baseline = Path(__file__).resolve().parent / "baseline.json"
        self.log = Path(__file__).resolve().parent / "logs" / "integrity.log"
        self.reports = Path(__file__).resolve().parent / "reports"

    def browse(self):
        selected = filedialog.askdirectory(title="Select folder to monitor")
        if selected:
            self.folder.set(selected)

    def scan(self):
        if not self.folder.get():
            raise ValueError("Select a folder first.")
        root = Path(self.folder.get()).expanduser().resolve(strict=True)
        excludes = [self.baseline.resolve(), self.baseline.with_name(self.baseline.name + ".sha256").resolve(), self.log.resolve()]
        patterns = []
        try:
            patterns.append(self.reports.resolve().relative_to(root).as_posix())
        except ValueError:
            pass
        return root, scan_directory(root, exclude_patterns=patterns, exclude_paths=excludes)

    def initialize(self):
        try:
            root, current = self.scan()
            save_baseline(self.baseline, root, current)
            self.output.insert("end", f"Baseline created for {len(current)} files: {self.baseline}\n")
        except Exception as exc:
            messagebox.showerror("Could not create baseline", str(exc))

    def check(self, refresh=False):
        try:
            root, current = self.scan()
            baseline = load_baseline(self.baseline)
            changes = compare_files(baseline["files"], current)
            log_changes(changes, self.log)
            self.reports.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            html_file = write_html_report(changes, self.reports / f"integrity-{stamp}.html")
            csv_file = write_csv_report(changes, self.reports / f"integrity-{stamp}.csv")
            self.output.insert("end", f"\nCheck for {root}\n")
            for category in ("modified", "new", "deleted"):
                self.output.insert("end", f"{category.title()}: {len(changes[category])}\n")
                for item in changes[category]:
                    self.output.insert("end", f"  {item['path']}\n")
            self.output.insert("end", f"Status: {'CHANGES DETECTED' if has_changes(changes) else 'CLEAN'}\nHTML: {html_file}\nCSV: {csv_file}\n")
            if refresh:
                save_baseline(self.baseline, root, current)
                self.output.insert("end", "Baseline refreshed to current state.\n")
            self.output.see("end")
        except Exception as exc:
            messagebox.showerror("Integrity check failed", str(exc))

    def update(self):
        self.check(refresh=True)


def main():
    root = tk.Tk()
    IntegrityCheckerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
