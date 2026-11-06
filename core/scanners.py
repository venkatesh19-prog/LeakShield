import os
import zipfile
import subprocess
from typing import List, Dict, Any, Tuple
from core.engine import SecretDetectionEngine

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".php", ".rb",
    ".env", ".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".conf",
    ".properties", ".log", ".txt", ".tf", ".sh", ".bash"
}

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_ARCHIVE_SIZE = 50 * 1024 * 1024
MAX_ZIP_ENTRIES = 500

def is_supported_file(filename: str) -> bool:
    base = os.path.basename(filename).lower()
    if base in {"dockerfile", ".env", "gemfile", "vagrantfile", "makefile"}:
        return True
    return os.path.splitext(filename)[1].lower() in SUPPORTED_EXTENSIONS

def scan_text_buffer(engine: SecretDetectionEngine, content: str, source_name: str) -> List[Dict[str, Any]]:
    return engine.scan_content(content, source_name)

def scan_safe_zip(engine: SecretDetectionEngine, zip_bytes) -> Tuple[List[Dict[str, Any]], int]:
    findings = []
    files_scanned = 0
    total_uncompressed_bytes = 0

    with zipfile.ZipFile(zip_bytes, "r") as zf:
        infolist = zf.infolist()
        if len(infolist) > MAX_ZIP_ENTRIES:
            raise ValueError(f"Security Alert: Archive exceeds entry limit ({len(infolist)} > {MAX_ZIP_ENTRIES}).")

        for info in infolist:
            normalized = os.path.normpath(info.filename)
            if normalized.startswith("..") or os.path.isabs(normalized) or info.is_dir():
                continue

            total_uncompressed_bytes += info.file_size
            if total_uncompressed_bytes > MAX_TOTAL_ARCHIVE_SIZE:
                raise ValueError("Security Alert: Archive exceeds uncompressed size limits (Zip Bomb protection).")

            if info.file_size > MAX_FILE_SIZE_BYTES:
                continue

            if is_supported_file(info.filename):
                try:
                    with zf.open(info) as f:
                        raw = f.read().decode("utf-8", errors="ignore")
                        findings.extend(engine.scan_content(raw, info.filename))
                        files_scanned += 1
                except Exception:
                    continue

    return findings, files_scanned

def scan_local_directory(engine: SecretDetectionEngine, directory_path: str) -> Tuple[List[Dict[str, Any]], int]:
    findings = []
    files_scanned = 0

    if not os.path.isdir(directory_path):
        raise ValueError(f"Path is not a valid directory: {directory_path}")

    for root, dirs, files in os.walk(directory_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__", ".idea"}]
        for file in files:
            full_path = os.path.join(root, file)
            if is_supported_file(file):
                try:
                    if os.path.getsize(full_path) > MAX_FILE_SIZE_BYTES:
                        continue
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        rel_path = os.path.relpath(full_path, directory_path)
                        findings.extend(engine.scan_content(content, rel_path))
                        files_scanned += 1
                except Exception:
                    continue

    return findings, files_scanned

def scan_git_history(engine: SecretDetectionEngine, repo_path: str, max_commits: int = 50) -> Tuple[List[Dict[str, Any]], int]:
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        raise ValueError("Directory does not contain a valid .git repository.")

    findings = []
    seen_fingerprints = set()
    commits_scanned = 0

    cmd_log = ["git", "-C", repo_path, "log", f"-n{max_commits}", "--pretty=format:%H|%an|%ad|%s", "--date=iso"]
    proc = subprocess.run(cmd_log, capture_output=True, text=True, check=True, timeout=30)

    for cline in proc.stdout.strip().splitlines():
        if not cline:
            continue
        parts = cline.split("|", 3)
        commit_hash, author, date_str, message = parts[0], parts[1], parts[2], parts[3]
        commits_scanned += 1

        cmd_diff = ["git", "-C", repo_path, "show", "--no-color", "--unified=0", commit_hash]
        diff_proc = subprocess.run(cmd_diff, capture_output=True, text=True, check=True, timeout=20)

        current_file = "unknown"
        for diff_line in diff_proc.stdout.splitlines():
            if diff_line.startswith("+++ b/"):
                current_file = diff_line[6:].strip()
                continue
            if diff_line.startswith("+") and not diff_line.startswith("+++"):
                added_code = diff_line[1:]
                for f in engine.scan_content(added_code, current_file):
                    if f["fingerprint"] in seen_fingerprints:
                        continue
                    seen_fingerprints.add(f["fingerprint"])
                    f["file_path"] = f"{current_file} (commit {commit_hash[:8]})"
                    f["description"] += f" | Commit by {author} on {date_str}: \"{message}\""
                    findings.append(f)

    return findings, commits_scanned
