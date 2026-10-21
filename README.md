# File Integrity Checker

A dependency-free Python 3 command-line utility for establishing a trusted snapshot of a directory and later detecting content changes. It classifies files as **modified**, **new**, or **deleted**, writes an event log, and creates timestamped HTML and CSV reports. A small Tkinter GUI is included as an optional front end.

## Objectives

- Provide a simple way to notice unexpected file changes.
- Store each monitored file's relative path, SHA-256 digest, size, and modification time in a JSON baseline.
- Stream files through SHA-256 in 4 KB chunks so memory use stays bounded for large files.
- Detect edits to the baseline JSON itself with a separate `.sha256` sidecar.
- Provide repeatable tests for ordinary changes and tampering.

> **Security note:** the baseline sidecar is a tamper-evident check, not a cryptographic signature. Anyone who can replace both the JSON and sidecar can forge a new pair. For stronger protection, keep the baseline and sidecar read-only or off the monitored machine, and sign the baseline using a separately protected key.

## Features and technologies

- Python 3.10+; standard library only (`hashlib`, `os`, `pathlib`, `json`, `csv`, `logging`, `argparse`, and optional `tkinter`).
- SHA-256 content fingerprints and filesystem metadata.
- CLI commands: `init`, `check`, `update`, and `report`.
- HTML/CSV report generation and `logs/integrity.log` event logging.
- Symlinks are skipped to avoid following links outside the selected directory or entering traversal loops.
- Default exclusions: `.git`, `.venv`, `venv`, `__pycache__`, and `.pytest_cache`. Add custom exclusions with `--exclude`.

## Project structure

```text
file-integrity-checker/
├── fic.py
├── core/
│   ├── __init__.py
│   ├── hasher.py
│   ├── scanner.py
│   ├── baseline.py
│   ├── comparer.py
│   └── reporter.py
├── gui.py
├── tests/
│   └── test_integrity.py
├── logs/                 # generated log output
├── reports/              # generated timestamped HTML and CSV reports
├── screenshots/          # add your own VS Code / demo screenshots here
├── requirements.txt
└── README.md
```

`baseline.json` and `baseline.json.sha256` are generated on initialization. By default these, the log file, and the report output directory are excluded from the scan when they fall within the monitored directory.

## Installation and VS Code setup

1. Install Python 3.10 or newer and open this folder in VS Code (`File > Open Folder…`).
2. (Recommended) Create and activate a virtual environment:

   **Windows PowerShell**
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   **macOS/Linux**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. There are no third-party packages. `requirements.txt` is intentionally empty of dependencies. Select the virtual environment interpreter in VS Code if prompted.
4. Open the integrated terminal and run commands from the project folder.

## Usage

Replace `PATH_TO_FOLDER` with the directory you want to monitor. The baseline defaults to `baseline.json` in the current working directory; the log defaults to `logs/integrity.log`; reports default to `reports/`.

```bash
# First run: record current file state
python fic.py init PATH_TO_FOLDER

# Later: compare with baseline; exit code 0 means clean, 1 means changes, 2 means an operational error
python fic.py check PATH_TO_FOLDER

# Generate the same check, report and log, then accept the current state as the new baseline
python fic.py update PATH_TO_FOLDER

# Run a check and explicitly generate HTML/CSV reports
python fic.py report PATH_TO_FOLDER

# Optional glob/pattern exclusions can be repeated
python fic.py init PATH_TO_FOLDER --exclude "*.tmp" --exclude "cache/*"

# Use explicit paths for state and output
python fic.py check PATH_TO_FOLDER --baseline ./state/baseline.json --log ./logs/integrity.log --report-dir ./reports

# Replace an existing baseline deliberately
python fic.py init PATH_TO_FOLDER --force
```

`update` intentionally adopts the current contents as trusted after displaying and recording the detected differences. Review the report before using it. Do not use `--force` or `update` to silence an alert without investigating it.

The optional Tkinter UI can be launched with:

```bash
python gui.py
```

It supports folder selection, baseline creation, checking, and updating. GUI state/report files are stored beside the application source.

## Workflow / architecture

```text
Select folder
    ↓
Scanner walks regular files (symlinks skipped; configured exclusions applied)
    ↓
Hasher streams each file in 4 KB chunks → SHA-256 + size + modified time
    ↓
First run: write baseline.json and baseline.json.sha256
Later run: validate baseline sidecar → compare current inventory with baseline
    ↓
Modified / New / Deleted classifications
    ↓
Print summary + append logs/integrity.log + write HTML and CSV reports
```

The baseline stores paths relative to the monitored root. File content hashes, not timestamp-only differences, determine whether a file is marked modified. Metadata remains available in the baseline and reports. The baseline digest is stored in a separate sidecar because a JSON file cannot safely contain a checksum of its own complete contents.

## Testing and expected results

Run the test suite from the project directory:

```bash
python -m unittest discover -s tests -v
```

Tests cover the known SHA-256 digest of an empty file, a file crossing the 4 KB chunk boundary, a clean scan, modified/new/deleted classification, metadata-only touches, and detection of edited or missing baseline sidecars. Expected result: all tests pass.

For a manual tamper demo, create a small folder with one text file, run `init`, edit the text file, then run `check`; the file should appear under **Modified**. Add and remove files to see **New** and **Deleted**. Edit `baseline.json` by hand and re-run a command; the tool should refuse the baseline because the sidecar no longer matches.

## Reports, screenshots, and final submission

Generated reports are saved in `reports/`; logs are appended to `logs/integrity.log`. Capture your own VS Code screenshots (for example, the clean check, detected tampering, and report output) and place them in `screenshots/`. This source-code project is not deployed; a live URL is therefore not included. If a video demonstration is required by your course, record the manual demo flow above.

To submit on GitHub, create a repository and push this folder. Example:

```bash
git init
git add .
git commit -m "Build file integrity checker"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/file-integrity-checker.git
git push -u origin main
```

Do not commit private or sensitive monitored files, local virtual environments, or real integrity baselines unless that is specifically appropriate for your assignment.

## Challenges and future improvements

The main design trade-off is that a sidecar checksum detects accidental or one-sided baseline edits but is not an authenticated signature. Additional improvements could include HMAC/signing with key management, immutable/offline baseline storage, scheduled checks, optional email alerts, platform-specific file-system event monitoring, stronger handling for files changing during scans, configurable permissions/ACL checks, and packaging as an installable command.

## Conclusion

This project provides a runnable, testable foundation for file-integrity monitoring using only Python's standard library. It establishes a directory baseline, detects content changes, and generates logs and reports, while keeping the implementation small enough to study and extend.

## References

- Python `hashlib`: https://docs.python.org/3/library/hashlib.html
- Python `pathlib`: https://docs.python.org/3/library/pathlib.html
- Python `os.walk`: https://docs.python.org/3/library/os.html#os.walk
- Python `json`: https://docs.python.org/3/library/json.html
- Python `unittest`: https://docs.python.org/3/library/unittest.html
