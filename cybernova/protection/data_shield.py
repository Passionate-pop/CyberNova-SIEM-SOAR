from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

log = logging.getLogger("cybernova.protection.data_shield")

RANSOMWARE_EXTENSIONS: Set[str] = {
    ".crypted", ".locked", ".encrypted", ".enc", ". ransomware", ".crypt",
    ".aes", ".rijndael", ".bla", ".zepto", ".cerber", ".locky", ".ezzze",
    ".wallet", ".onion", ".cryptolocker", ".filock", ".scarab", ".dmde",
    ".vvv", ".xxx", ".ttt", ".micro", ".cry", ".crypt", ".crptr",
}
RANSOMWARE_FILES: Set[str] = {
    "ransomnote", "ransomware", "decrypt", "how_to_decrypt", "readme",
    "restore", "recovery", "contact", "help_your_files", "help_restore",
    "how_to_back", "where_my_files", "files_back", "recover",
}
RANSOMWARE_PROCESSES: Set[str] = {
    "tor.exe", "firefox.exe", "chrome.exe", "browser.exe",
}
MASS_DELETE_THRESHOLD = 50
MASS_RENAME_THRESHOLD = 30
MASS_ENCRYPT_THRESHOLD = 20
RANSOMWARE_WINDOW = 120

SENSITIVE_REGISTRY_KEYS: List[str] = [
    r"HKLM\SAM", r"HKLM\SECURITY", r"HKLM\SYSTEM\CurrentControlSet\Services\NTDS",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
]
SHADOW_COPY_PATHS: List[str] = [
    r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy",
    r"\\?\GLOBALROOT\Device\HarddiskVolumeSnapshot",
]

SENSITIVE_DATA_PATTERNS: Dict[str, re.Pattern] = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "gcp_key": re.compile(r"\"type\":\s*\"service_account\""),
    "ssh_private_key": re.compile(r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----"),
    "pgp_private_key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    "jwt_token": re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    "github_token": re.compile(r"(ghp_|gho_|github_pat_)[0-9a-zA-Z]{36,}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9a-zA-Z-]{24,}"),
    "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "basic_auth": re.compile(r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}", re.I),
    "bearer_token": re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._-]{10,}", re.I),
    "database_url": re.compile(r"(postgresql|mysql|mongodb|redis|sqlite)://[^\s]{10,}"),
    "password_inline": re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.I),
    "secret_inline": re.compile(r"(?:secret|api_key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-+/=]{8,}['\"]", re.I),
}

CRITICAL_PATHS: List[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/crontab", "/var/log/auth.log", "/var/log/secure",
    "/boot/grub/grub.cfg", "/boot/grub2/grub.cfg",
    "/etc/fstab", "/etc/resolv.conf",
]

SENSITIVE_EXTENSIONS: Set[str] = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".raw",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".sql", ".db", ".mdb", ".accdb",
    ".pst", ".ost", ".eml", ".msg",
    ".key", ".pem", ".ppk", ".p12", ".pfx", ".cer",
    ".vmx", ".vmdk", ".vhd", ".vhdx", ".qcow2",
    ".m4a", ".mp3", ".mp4", ".avi", ".mkv", ".mov",
}


class DataShield:
    def __init__(self):
        self._rename_events: Dict[str, List[float]] = defaultdict(list)
        self._delete_events: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._entropy_cache: Dict[str, float] = {}
        self._exfil_bytes: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._shadow_copy_check: float = 0
        self._file_baseline: Dict[str, str] = {}

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        """Analyze event for data-level threats (ransomware, exfil, DLP, mass changes)."""
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        extra = event.get("extra_data") or event.get("extra", {})
        file_path = extra.get("file", extra.get("path", ""))
        message = event.get("message", "")

        if etype == "file_changed":
            self._check_ransomware_encryption(file_path, results)
        if etype in ("file_deleted", "file_remove"):
            self._detect_mass_delete(file_path, message, results)
        if etype == "file_rename":
            self._detect_mass_rename(file_path, message, results)
        if etype == "dlp_leak_detected":
            self._analyze_dlp(extra, results)
        if etype in ("data_transfer", "large_upload", "bulk_transfer"):
            self._detect_exfiltration(extra, results)
        if etype == "registry_changed" and any(rk.lower() in message.lower() for rk in SENSITIVE_REGISTRY_KEYS):
            self._add_finding(results, "sensitive_registry_access", f"Sensitive registry access: {message[:120]}", 85, {"key": message[:120]})
        if etype == "shadow_copy_event":
            self._add_finding(results, "shadow_copy_deletion", "Volume Shadow Copy deletion detected — ransomware indicator", 95, extra)
        self._check_critical_files(results)
        return results

    def _check_ransomware_encryption(self, file_path: str, res: dict):
        if not file_path:
            return
        ext = Path(file_path).suffix.lower()
        name = Path(file_path).stem.lower()
        now = time.time()
        self._rename_events[file_path].append(now)
        self._rename_events[file_path] = [t for t in self._rename_events[file_path] if t > now - RANSOMWARE_WINDOW]

        if ext in RANSOMWARE_EXTENSIONS:
            count = len(self._rename_events[file_path])
            if count >= 5:
                self._add_finding(res, "ransomware_encryption", f"Ransomware encryption pattern: {count} files with ext '{ext}' in {RANSOMWARE_WINDOW}s", 98, {"extension": ext, "count": count})
            else:
                self._add_finding(res, "suspicious_extension", f"Suspicious file extension: {ext} — {file_path}", 75, {"extension": ext})
        for rname in RANSOMWARE_FILES:
            if rname in name:
                self._add_finding(res, "ransomware_note", f"Possible ransomware note: {file_path}", 88, {"filename": file_path})
                break

    def _detect_mass_delete(self, file_path: str, message: str, res: dict):
        if not file_path:
            return
        now = time.time()
        ext = Path(file_path).suffix.lower()
        self._delete_events[ext].append((now, file_path))
        self._delete_events[ext] = [(t, f) for t, f in self._delete_events[ext] if t > now - RANSOMWARE_WINDOW]
        if len(self._delete_events[ext]) >= MASS_DELETE_THRESHOLD:
            self._add_finding(res, "mass_file_deletion", f"Mass deletion: {len(self._delete_events[ext])} '{ext}' files in {RANSOMWARE_WINDOW}s — wiper/ransomware", 95, {"extension": ext, "count": len(self._delete_events[ext])})
        for crit in CRITICAL_PATHS:
            if crit in file_path.lower():
                self._add_finding(res, "critical_file_deleted", f"Critical file deleted: {file_path}", 92, {"file": file_path})

    def _detect_mass_rename(self, file_path: str, message: str, res: dict):
        if not file_path:
            return
        now = time.time()
        ext = os.path.splitext(file_path)[1].lower()
        key = f"rename:{ext}" if ext else "rename:noext"
        self._rename_events[key].append(now)
        self._rename_events[key] = [t for t in self._rename_events[key] if t > now - RANSOMWARE_WINDOW]
        if len(self._rename_events[key]) >= MASS_RENAME_THRESHOLD:
            self._add_finding(res, "mass_file_rename", f"Mass rename: {len(self._rename_events[key])} files in {RANSOMWARE_WINDOW}s — ransomware indicator", 92, {"extension": ext, "count": len(self._rename_events[key])})

    def _analyze_dlp(self, extra: dict, res: dict):
        for name, pattern in SENSITIVE_DATA_PATTERNS.items():
            text = str(extra.get("message", "")) + " " + str(extra.get("data", ""))
            matches = pattern.findall(text)
            if matches:
                sev = "critical" if name in ("ssh_private_key", "pgp_private_key", "credit_card", "ssn") else "high"
                risk = 90 if sev == "critical" else 75
                masked = [m[:6] + "..." + m[-4:] if len(str(m)) > 12 else str(m) for m in matches[:3]]
                self._add_finding(res, f"dlp_{name}", f"Sensitive {name} detected", risk, {"pattern": name, "matches": masked})

    def _detect_exfiltration(self, extra: dict, res: dict):
        bytes_transferred = extra.get("bytes", extra.get("size", 0))
        dest = extra.get("dest_ip", extra.get("destination", ""))
        if bytes_transferred > 100_000_000:
            self._add_finding(res, "large_data_transfer", f"Large data transfer: {bytes_transferred // 1024 // 1024}MB to {dest}", 85, {"bytes": bytes_transferred, "dest": dest})
        if extra.get("protocol", "").upper() in ("DNS", "ICMP") and bytes_transferred > 10000:
            self._add_finding(res, "covert_channel_exfil", f"Covert channel exfiltration via {extra.get('protocol')}: {bytes_transferred}B", 90, extra)

    def _check_critical_files(self, res: dict):
        for path in CRITICAL_PATHS:
            p = Path(path)
            if p.exists():
                try:
                    new_hash = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                    if path in self._file_baseline and self._file_baseline[path] != new_hash:
                        self._add_finding(res, "critical_file_modified", f"Critical system file modified: {path}", 90, {"file": path, "previous": self._file_baseline[path], "current": new_hash})
                    self._file_baseline[path] = new_hash
                except Exception as e:
                    log.warning("Critical file hash error %s: %s", path, e)
            else:
                if path in self._file_baseline:
                    self._add_finding(res, "critical_file_deleted", f"Critical system file deleted: {path}", 95, {"file": path})
                    del self._file_baseline[path]

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        res["threat_detected"] = True


data_shield = DataShield()
