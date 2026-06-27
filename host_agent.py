"""
CyberNova — HOST AGENT (Enterprise)
Full-Server Security Monitoring Agent
Monitors: All drives, all users, kernel, services, boot, network, registry, persistence, everything
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import platform
import re
import socket
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import httpx

# ── Real-time file system monitoring ──────────────────────────────────
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    # Dummy classes so the handler definitions below don't crash at import time
    class FileSystemEventHandler:  # type: ignore
        def on_created(self, event): pass
        def on_moved(self, event): pass
    Observer = None  # type: ignore
    log.warning("watchdog not installed — run 'pip install watchdog' for real-time file monitoring")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)
log = logging.getLogger("cybernova.agent")


# ═══════════════════════════════════════════════════════════════════════════════
# Security Event Model
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityEvent:
    """Properly formatted security event for CyberNova"""
    def __init__(
        self,
        event_type: str,
        severity: str,
        source: str,
        message: str,
        timestamp: str,
        source_ip: str = "",
        dest_ip: str = "",
        user: str = "",
        hostname: str = "",
        **kwargs
    ):
        self.event_type = event_type
        self.severity = severity
        self.source = source
        self.message = message
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.user = user
        self.hostname = hostname
        self.extra = kwargs

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "user": self.user,
            "hostname": self.hostname,
        }
        data.update(self.extra)
        return {k: v for k, v in data.items() if v is not None and v != ""}


# ═══════════════════════════════════════════════════════════════════════════════
# REAL-TIME FILE MONITOR — Uses OS-native APIs via watchdog
# Monitors: FSEvents (macOS), inotify (Linux), ReadDirectoryChangesW (Windows)
# ═══════════════════════════════════════════════════════════════════════════════

class _RealtimeFileHandler(FileSystemEventHandler):
    """Handler that fires on file creation/move — immediately analyzes suspicious files."""

    def __init__(self, analyze_callback, loop, seen_files: Set[str], dangerous_exts: Set[str]):
        super().__init__()
        self._analyze = analyze_callback
        self._loop = loop  # reference to the main asyncio event loop
        self._seen_files = seen_files  # shared set with HostAgent
        self._dangerous_exts = dangerous_exts

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle_new_file(Path(event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return
        if event.dest_path:
            self._handle_new_file(Path(event.dest_path))

    def _handle_new_file(self, fpath: Path):
        path_str = str(fpath)
        # Skip if we've already seen it via polling
        if path_str in self._seen_files:
            return
        self._seen_files.add(path_str)

        # Fast extension check before firing off the full async analysis
        ext = fpath.suffix.lower()
        if ext and ext in self._dangerous_exts:
            # Dispatch to the main event loop — no new threads needed
            asyncio.run_coroutine_threadsafe(
                self._analyze(fpath),
                self._loop
            )


class RealTimeFileWatcher:
    """
    Real-time file system monitoring using watchdog library.
    
    Watches critical user directories for file creation events and
    immediately analyzes new files for threats. Uses the OS-native API:
      - macOS: FSEvents
      - Linux: inotify
      - Windows: ReadDirectoryChangesW
    
    Sub-second detection vs. the polling loop's ~2.5 minute scan.
    """

    def __init__(self, analyze_callback, loop, seen_files: Set[str], dangerous_exts: Set[str]):
        self._observer = Observer()
        self._watched_dirs: List[str] = []
        self._handler = _RealtimeFileHandler(analyze_callback, loop, seen_files, dangerous_exts)
        self._running = False

    def add_watched_dir(self, path: str):
        """Add a directory to watch recursively."""
        if os.path.isdir(path):
            if path not in self._watched_dirs:
                self._watched_dirs.append(path)

    def start(self):
        """Start watching all registered directories."""
        if not HAS_WATCHDOG:
            log.warning("Real-time file watcher unavailable — install watchdog")
            return

        for dir_path in self._watched_dirs:
            try:
                self._observer.schedule(
                    self._handler,
                    dir_path,
                    recursive=True  # Watch subdirectories too
                )
                log.info("Real-time watching (recursive): %s", dir_path)
            except Exception as e:
                log.warning("Cannot watch %s: %s", dir_path, e)

        if self._watched_dirs:
            self._observer.start()
            self._running = True
            log.info("Real-time file watcher started (%d directories)", len(self._watched_dirs))

    def stop(self):
        """Stop watching."""
        if self._running and HAS_WATCHDOG:
            self._observer.stop()
            self._observer.join()
            self._running = False
            log.info("Real-time file watcher stopped")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE HOST AGENT — Full Server Monitoring
# ═══════════════════════════════════════════════════════════════════════════════

class HostAgent:
    """
    Enterprise Host Security Agent
    Monitors the ENTIRE server — all drives, all users, kernel, network, everything.
    No blind spots. No gaps.
    """

    # ── Critical attack patterns (process command-lines) ──────────────────
    CRITICAL_PATTERNS = [
        r"mimikatz", r"pwdump", r"procdump", r"lsass",
        r"invoke-shellcode", r"invoke-mimikatz",
        r"downloadstring.*http", r"DownloadString\(",
        r"iex\s*\(", r"Invoke-Expression",
        r"encodedcommand", r"-enc\s",
        r"new-object.*webclient.*download",
        r"certutil.*-decode",
        r"mshta.*vbscript:",
        r"wscript.*shell",
        r"rundll32.*javascript",
        r"regsvr32.*shell32",
        r"bypass.*execution.policy",
        r"amsi.*(?:bypass|disable|patch)",
        r"etw.*(?:bypass|disable)",
        r"ntds\.dit",
        r"sam\.hive",
        r"lsass\.dump",
        r"wce\.exe",
        r"gsecdump",
        r"cain\.exe",
        r"nc\.exe.*-e",
        r"ncat.*-e",
        r"powersploit",
        r"empire.*http",
        r"cobainstrike",
        r"metasploit",
        r"beacon",
        r"cobaltstrike",
        r"sliver.*http",
        r"havoc",
        r"bruteratel",
        r"villain",
    ]

    # ── Suspicious but lower-confidence patterns ─────────────────────────
    SUSPICIOUS_PATTERNS = [
        r"powershell.*-wmi",
        r"powershell.*-exec",
        r"net\s+user\s+.*\s+/add",
        r"net\s+localgroup\s+.*\s+/add",
        r"new-service",
        r"schtasks\s+/create",
        r"wmic\s+process\s+call\s+create",
        r"wmic\s+useraccount\s+create",
        r"bcdedit.*delete",
        r"bcdedit.*debug",
        r"vssadmin\s+delete\s+shadows",
        r"wmic\s+shadowcopy\s+delete",
        r"reg\s+delete\s+.*\\(?:run|runonce)",
        r"takeown.*/f\s+.*system32",
        r"icacls.*/grant.*:F",
        r"attrib\s+-r\s+-h\s+-s",
        r"copy\s+.*\\temp\\.*exe",
        r"move\s+.*\\temp\\.*exe",
        r"wevtutil\s+cl\s+",
        r"wevtutil\s+clear-log",
        r"fsutil\s+behavior\s+set\s+disablelastaccess",
        r"net\s+stop\s+(?:win)|(?:defend)|(?:firewall)",
        r"sc\s+stop\s+",
        r"sc\s+config\s+.*start=\s+disabled",
    ]

    # ── Safe domains (whitelist for PTR validation) ─────────────────────
    SAFE_DOMAIN_SUFFIXES = {
        "microsoft.com", "windows.com", "msft.net", "msftauth.net", "msauth.net",
        "microsoftonline.com", "microsoftonline-p.com", "microsoftonline-p.net",
        "msappproxy.net", "office.com", "office365.com", "sharepoint.com",
        "onedrive.live.com", "windowsupdate.com", "windowsupdate.microsoft.com",
        "cloudflare.com", "cloudflaressl.com", "gstatic.com", "google.com",
        "googleusercontent.com", "googlevideo.com", "ytimg.com", "ggpht.com",
        "apple.com", "apple.com.edgesuite.net", "akamaiedge.net", "akamai.net",
        "akamaihd.net", "akamaitechnologies.com", "akamai-staging.net",
        "facebook.com", "fbcdn.net", "facebook.net", "fb.com",
        "twitter.com", "twimg.com", "tiktok.com", "tiktokv.com",
        "amazonaws.com", "amazon.com", "awsstatic.com",
        "github.com", "githubusercontent.com",
        "gitlab.com", "gitlab-static.com",
        "docker.com", "docker.io",
        "npmjs.com", "npmjs.org",
        "python.org", "pypi.org",
        "nuget.org", "nugetcdn.com",
        "rubygems.org",
        "crates.io",
        "sentry.io", "datadoghq.com", "newrelic.com",
        "slack.com", "slack-edge.com",
        "zoom.us", "zoom.com",
        "teams.microsoft.com",
        "discord.com", "discordapp.com",
        "reddit.com", "redditmedia.com",
        "linkedin.com", "licdn.com",
        "youtube.com", "googlevideo.com",
        "cloudfront.net", "azureedge.net", "azurefd.net",
        "trafficmanager.net", "servicebus.windows.net",
        "digicert.com", "godaddy.com", "verisign.com",
    }

    # ── Safe processes (never alert on these) ───────────────────────────
    SAFE_PROCESSES = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "explorer.exe", "svchost.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe",
        "taskmgr.exe", "dwm.exe", "conhost.exe", "sihost.exe",
        "taskhostw.exe", "runtimebroker.exe",
        "system", "system idle process",
        "registry", "memory compression",
        "wininit.exe", "lsaiso.exe",
        "fontdrvhost.exe", "sedsvc.exe",
        "audiodg.exe", "spoolsv.exe",
        "wermgr.exe", "wlanext.exe",
        "ctfmon.exe", "shellexperiencehost.exe",
        "searchapp.exe", "searchfilterhost.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
        "sppsvc.exe", "trustedinstaller.exe",
        "vmtoolsd.exe", "vgauthservice.exe",
        "vssvc.exe", "wmiadap.exe", "wmiprvse.exe",
        "wsearchindexer.exe", "wsqmcons.exe",
        "defrag.exe", "cleanmgr.exe", "msmpeng.exe",
        "smartscreen.exe", "securityhealthservice.exe",
        "ntoskrnl.exe", "hal.dll", "win32k.sys",
    }

    # ── Dangerous file extensions (comprehensive) ───────────────────────
    DANGEROUS_EXTENSIONS = {
        # Executables
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".msp", ".mst",
        ".cpl", ".scf", ".inf",
        # Scripts
        ".ps1", ".psm1", ".psd1", ".ps1xml", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".wsc", ".hta", ".php", ".py", ".rb", ".pl", ".awk", ".tcl",
        # Office macros
        ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".ppsm", ".potm", ".slm", ".xlam",
        # Shortcuts
        ".lnk", ".url", ".website",
        # Disk images (bypass Mark-of-the-Web)
        ".iso", ".vhd", ".vhdx", ".vmdk", ".img", ".dmg",
        # Archives
        ".zip", ".rar", ".7z", ".gz", ".tar", ".cab", ".arj", ".lzh", ".bz2",
        # Help files
        ".chm", ".hlp",
        # PowerShell / certs
        ".psc1", ".ps2", ".psc2", ".cer", ".crt", ".der",
        # Java / .NET
        ".jar", ".jnlp", ".application", ".gadget",
        # Other attack vectors
        ".sct", ".msu", ".deskthemepack", ".themepack",
        ".dllx", ".drv", ".ocx", ".sys",
    }

    # ── Known malicious kernel driver hashes (example: major rootkits) ──
    KNOWN_BAD_DRIVERS = {
        # Placeholder — real deployment should populate from threat intel
        "capcom.sys", "gdrv.sys", "kprocesshacker.sys",
        "pci.sys",  # common rootkit name collision
        "msio64.sys", "asupio64.sys",
    }

    # ── Hosts file hijacking patterns ────────────────────────────────────
    HOSTS_HIJACK_PATTERNS = [
        r"^\s*0\.0\.0\.0\s+.*(?:google|facebook|microsoft|windowsupdate|github|bitbucket)",
        r"^\s*127\.0\.0\.1\s+.*(?:google|facebook|microsoft|windowsupdate)",
    ]

    # ── Known WMI persistence locations ─────────────────────────────────
    WMI_PERSISTENCE_NAMESPACES = [
        r"root\subscription",
        r"root\default",
        r"root\cimv2",
    ]

    # ── Suspicious service binary paths ─────────────────────────────────
    SUSPICIOUS_SERVICE_PATHS = [
        r"\\temp\\", r"\\users\\public\\", r"\\windows\\temp\\",
        r"\\appdata\\", r"\\downloads\\", r"\\desktop\\",
        r"\\documents\\", r"\\perflogs\\",
    ]

    # ── Magic bytes for file type validation ────────────────────────────
    MAGIC_BYTES = {
        b"MZ": ".exe",
        b"\x7fELF": ".elf",
        b"\x89PNG": ".png",
        b"\xff\xd8\xff": ".jpg",
        b"GIF8": ".gif",
        b"%PDF": ".pdf",
        b"PK\x03\x04": ".zip",
        b"Rar!\x1a\x07": ".rar",
        b"\x1f\x8b": ".gz",
        b"BZh": ".bz2",
        b"\xfd7zZ": ".7z",
        b"{\n": ".json",
        b"<html": ".html",
        b"<!DOCT": ".html",
        b"{\"": ".json",
        b"\xcf\xfa\xed\xfe": ".macho",
        b"\xca\xfe\xba\xbe": ".class",
        b"\x4d\x53\x43\x46": ".msi",
        b"\xd0\xcf\x11\xe0": ".ole2",
        b"\x50\x4b\x03\x04\x14\x00\x06\x00": ".docx",
    }

    # ── Certificate store known bad issuers (example) ───────────────────
    KNOWN_BAD_CERT_ISSUERS = [
        "DO_NOT_TRUST", "Fake", "Test", "Untrusted",
    ]

    def __init__(self, backend_url: str, username: str = "", password: str = "",
                 tenant_id: str = "default"):
        self.backend_url = backend_url.rstrip('/')
        self.username = username or os.environ.get("AGENT_USERNAME", "")
        self.password = password or os.environ.get("AGENT_PASSWORD", "")
        if not self.username or not self.password:
            raise ValueError(
                "Username and password required — set AGENT_USERNAME and AGENT_PASSWORD env vars"
            )
        self.hostname = socket.gethostname()
        self._running = False
        self._auth_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: float = 0
        self._token_refresh_buffer = 60
        self._task: Optional[asyncio.Task] = None
        self._start_time = datetime.now(timezone.utc)

        # ── Deduplication / tracking sets ───────────────────────────────
        self._seen_files: Set[str] = set()
        self._seen_processes: Set[str] = set()
        self._seen_services: Set[str] = set()
        self._seen_scheduled_tasks: Set[str] = set()
        self._seen_drivers: Set[str] = set()
        self._seen_firewall_rules: Set[str] = set()
        self._seen_startup_items: Set[str] = set()
        self._seen_wmi_subscriptions: Set[str] = set()
        self._seen_usb: Set[str] = set()
        self._seen_hosts_hash: str = ""
        self._seen_bcd_hash: str = ""
        self._seen_cert_hashes: Set[str] = set()
        self._seen_shadow_copies: int = -1  # -1 = not yet checked
        self._seen_listening_ports: Set[str] = set()
        self._seen_arp_entries: Set[str] = set()
        self._seen_arp_alerts: Set[str] = set()  # MACs already alerted for ARP poisoning
        self._seen_system_events: Set[str] = set()
        self._seen_dns_entries: Set[str] = set()

        # ── Cached drive list (refreshed hourly) ────────────────────────
        self._cached_drives: List[str] = []
        self._cached_drives_time: float = 0
        self._DRIVE_CACHE_TTL = 3600  # 1 hour

        # ── Rate limiting and dedup ─────────────────────────────────────
        self._dedup_cache: Dict[str, float] = {}
        self._event_type_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._event_counts: Dict[str, List[float]] = defaultdict(list)
        self._ptr_cache: Dict[str, tuple] = {}
        self._PTR_CACHE_VALIDITY = 300

        # ── System state snapshots for change detection ─────────────────
        self._boot_time: Optional[str] = None
        self._last_heartbeat: float = 0
        self._cleanup_counter: int = 0

        # ── SOAR integration ────────────────────────────────────────────
        self._soar_enabled = str(os.environ.get("CYBERNOVA_SOAR_ENABLED", "false")).lower() in {"1", "true", "yes"}
        self._soar_webhook = os.environ.get("CYBERNOVA_SOAR_WEBHOOK")

        # ── Real-time file watcher (initialized in start()) ─────────────
        self._real_time_watcher: Optional[RealTimeFileWatcher] = None

        # Initialize file tracking
        self._initialize_all_drives_file_index()

    # ════════════════════════════════════════════════════════════════════
    # INITIALIZATION — Pre-index existing files across ALL drives
    # ════════════════════════════════════════════════════════════════════

    def _initialize_all_drives_file_index(self):
        """Pre-index files on ALL drives to avoid alerting on existing files."""
        log.info("Pre-indexing existing files across all drives (one-time)...")
        count = 0
        for drive in self._get_all_drives():
            try:
                for root, dirs, files in os.walk(drive):
                    # Skip deep system folders for speed
                    rel_depth = root.replace(drive, "").count(os.sep)
                    if rel_depth > 2:
                        dirs.clear()
                        continue
                    for f in files:
                        try:
                            fp = Path(root) / f
                            self._seen_files.add(str(fp))
                            count += 1
                        except Exception:
                            continue
                    if count > 100000:  # cap initial indexing
                        log.info("Pre-indexed %d files (cap reached)", count)
                        return
            except Exception:
                continue
        log.info("Pre-indexed %d existing files across all drives", count)

    def _get_all_drives(self) -> List[str]:
        """Get ALL fixed/removable drives (cached for 1 hour)."""
        now = time.time()
        if self._cached_drives and (now - self._cached_drives_time) < self._DRIVE_CACHE_TTL:
            return self._cached_drives

        drives = []
        try:
            # Single WMI query gets all drives at once instead of 26 subprocesses
            output = subprocess.check_output(
                'powershell -Command "Get-WmiObject Win32_LogicalDisk | '
                'Where-Object {$_.DriveType -eq 3 -or $_.DriveType -eq 2} | '
                'Select-Object DeviceID | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            ).strip()
            if output:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                drives = [d["DeviceID"] + "\\" for d in data if d.get("DeviceID")]
        except Exception:
            pass

        if not drives:
            drives = ["C:\\"]

        self._cached_drives = drives
        self._cached_drives_time = now
        return drives

    def _get_all_user_profiles(self) -> List[str]:
        """Get ALL user profile directories on the system."""
        users_path = Path("C:\\Users")
        profiles = []
        if users_path.exists():
            for entry in users_path.iterdir():
                if entry.is_dir():
                    name = entry.name.lower()
                    # Skip system profiles
                    if name in ("public", "default", "default user", "all users",
                                "default user profile", "desktop.ini"):
                        continue
                    profiles.append(str(entry))
        return profiles

    def _get_current_user(self) -> str:
        try:
            return os.environ.get("USERNAME", "Unknown")
        except Exception:
            return "Unknown"

    # ════════════════════════════════════════════════════════════════════
    # MAIN ENTRY POINTS
    # ════════════════════════════════════════════════════════════════════

    async def start(self):
        log.info("=" * 70)
        log.info("CYBERNOVA HOST AGENT — ENTERPRISE EDITION")
        log.info("=" * 70)
        log.info("Host:     %s", self.hostname)
        log.info("Backend:  %s", self.backend_url)
        log.info("Drives:   %s", ", ".join(self._get_all_drives()))
        log.info("Users:    %d profiles found", len(self._get_all_user_profiles()))
        log.info("Mode:     Full server monitoring (all drives, all users, kernel, network)")

        await self._authenticate()
        if not self._auth_token:
            log.error("AUTH FAILED! Agent cannot start.")
            return

        # ── Start real-time file watcher ───────────────────────────────
        self._start_real_time_watcher()

        self._running = True
        self._task = asyncio.create_task(self._monitoring_loop())

        try:
            await self._task
        except asyncio.CancelledError:
            log.info("Agent stopped")
        finally:
            self._running = False
            if self._real_time_watcher:
                self._real_time_watcher.stop()

    async def stop(self):
        self._running = False
        if self._real_time_watcher:
            self._real_time_watcher.stop()
        if self._task:
            self._task.cancel()

    # ════════════════════════════════════════════════════════════════════
    # REAL-TIME FILE WATCHER — Start watching critical user directories
    # ════════════════════════════════════════════════════════════════════

    def _get_critical_watch_dirs(self) -> List[str]:
        """Get the list of critical user directories to watch in real-time.
        Works cross-platform: Windows, macOS, Linux.
        """
        dirs = []
        home = Path.home()

        # User home subdirectories (Downloads, Desktop, Documents)
        for sub in ["Downloads", "Desktop", "Documents", "tmp", "AppData/Local/Temp"]:
            target = home / sub
            if target.exists() and target.is_dir():
                dirs.append(str(target))

        # System-wide temp directories
        for tmp in [Path("/tmp"), Path("/private/tmp")]:
            if tmp.exists():
                dirs.append(str(tmp))

        # Windows temp
        win_tmp = os.environ.get("TEMP") or os.environ.get("TMP")
        if win_tmp and Path(win_tmp).exists():
            dirs.append(win_tmp)

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for d in dirs:
            if d not in seen:
                seen.add(d)
                unique.append(d)
        return unique

    def _start_real_time_watcher(self):
        """Initialize and start the real-time file watcher."""
        if not HAS_WATCHDOG:
            log.warning("Real-time file watcher unavailable — install 'watchdog' package")
            return

        try:
            watcher = RealTimeFileWatcher(
                analyze_callback=self._analyze_file,
                loop=asyncio.get_running_loop(),
                seen_files=self._seen_files,
                dangerous_exts=self.DANGEROUS_EXTENSIONS,
            )

            for d in self._get_critical_watch_dirs():
                watcher.add_watched_dir(d)

            watcher.start()
            self._real_time_watcher = watcher
        except Exception as e:
            log.error("Failed to start real-time file watcher: %s", e)

    async def _ensure_valid_token(self):
        if self._is_token_valid():
            return
        if self._refresh_token:
            await self._refresh_token_if_needed()
        if not self._is_token_valid():
            await self._authenticate()

    # ════════════════════════════════════════════════════════════════════
    # AUTHENTICATION
    # ════════════════════════════════════════════════════════════════════

    async def _authenticate(self):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{self.backend_url}/api/v1/auth/login",
                    json={"username": self.username, "password": self.password}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._auth_token = data.get("access_token")
                    self._refresh_token = data.get("refresh_token")
                    self._token_expires_at = time.time() + (15 * 60 - self._token_refresh_buffer)
                    log.info("Authenticated OK")
                else:
                    log.error("Auth failed: %d %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.error("Auth error: %s", e)

    async def _refresh_token_if_needed(self):
        if time.time() >= self._token_expires_at and self._refresh_token:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        f"{self.backend_url}/api/v1/auth/refresh",
                        json={"refresh_token": self._refresh_token}
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        self._auth_token = data.get("access_token")
                        new_refresh = data.get("refresh_token")
                        if new_refresh:
                            self._refresh_token = new_refresh
                        self._token_expires_at = time.time() + (15 * 60 - self._token_refresh_buffer)
                        log.info("Token refreshed")
                    else:
                        await self._authenticate()
            except Exception as e:
                log.error("Token refresh error: %s", e)
                await self._authenticate()

    def _is_token_valid(self) -> bool:
        if not self._auth_token:
            return False
        return time.time() < self._token_expires_at

    # ════════════════════════════════════════════════════════════════════
    # EVENT SENDING
    # ════════════════════════════════════════════════════════════════════

    async def _send_event(self, event: SecurityEvent):
        try:
            if event.extra.get("whitelist"):
                return

            # Dedup (60s window)
            dedup_key = self._get_dedupe_key(event)
            now = time.time()
            last = self._dedup_cache.get(dedup_key)
            if last is not None and (now - last) < 60:
                return
            self._dedup_cache[dedup_key] = now

            # Rate-limit high-volume event types
            _HIGH_VOLUME = {"external_connection", "suspicious_network",
                            "agent_heartbeat", "usb_connected"}
            etype = event.event_type
            if etype in _HIGH_VOLUME:
                self._event_type_timestamps[etype] = [
                    t for t in self._event_type_timestamps[etype] if now - t < 60
                ]
                if len(self._event_type_timestamps[etype]) >= 30:
                    self._event_type_timestamps[etype].append(now)
                    return
                self._event_type_timestamps[etype].append(now)

            event.severity = self._map_severity(event.event_type, event.extra, event.severity)

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{self.backend_url}/api/v1/ingest/agent",
                    json={
                        "events": [event.to_dict()],
                        "source": "host_agent",
                        "source_type": "agent"
                    },
                    headers={
                        "Authorization": f"Bearer {self._auth_token}",
                        "Content-Type": "application/json"
                    }
                )
                if resp.status_code in (200, 201):
                    log.info("-> ALERT: [%s] %s — %s",
                             event.severity.upper(), event.event_type,
                             event.message[:80])
                    await self._maybeTriggerSoar(event)
                else:
                    log.warning("-> SEND FAILED: %d for %s", resp.status_code, event.event_type)
        except Exception as e:
            log.error("Send failed: %s", e)

    def _get_dedupe_key(self, event: SecurityEvent) -> str:
        sig = str(event.extra.get("signature", ""))
        base = f"{event.event_type}:{event.dest_ip or ''}:{sig}:{event.hostname}"
        return hashlib.sha256(base.encode()).hexdigest()

    async def _maybeTriggerSoar(self, event: SecurityEvent):
        if not self._soar_enabled or not self._soar_webhook:
            return
        try:
            payload = {
                "incident": {
                    "type": event.event_type,
                    "severity": event.severity,
                    "title": f"{event.event_type} on {event.hostname}",
                    "message": event.message,
                    "timestamp": event.timestamp,
                    "dest_ip": event.dest_ip,
                    "source": event.source,
                }
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(self._soar_webhook, json=payload)
        except Exception as e:
            log.debug("SOAR webhook error: %s", e)

    def _map_severity(self, event_type: str, details=None, current=None) -> str:
        mapping = {
            "malicious_process": "critical",
            "malicious_script": "critical",
            "kernel_rootkit": "critical",
            "boot_config_changed": "critical",
            "service_binary_tampered": "critical",
            "wmi_persistence": "critical",
            "shadow_copy_deleted": "critical",
            "defender_disabled": "critical",
            "certificate_anomaly": "high",
            "hosts_hijacked": "high",
            "firewall_rule_changed": "high",
            "suspicious_file": "high",
            "suspicious_driver": "high",
            "new_scheduled_task": "high",
            "startup_item": "high",
            "new_download": "high",
            "user_created": "high",
            "account_lockout": "high",
            "suspicious_network": "medium",
            "failed_login": "medium",
            "usb_connected": "low",
            "agent_heartbeat": "info",
        }
        return mapping.get(event_type, current or "medium")

    # ════════════════════════════════════════════════════════════════════
    # MONITORING LOOP
    # ════════════════════════════════════════════════════════════════════

    async def _monitoring_loop(self):
        cycle = 0
        while self._running:
            cycle += 1
            log.info("=== Cycle %d ===", cycle)

            await self._ensure_valid_token()

            try:
                # ── EVERY CYCLE (30s) ─────────────────────────────────
                await self._check_processes()           # All process creation + cmdline
                await self._check_network()              # External connections
                await self._check_listening_ports()       # New listening ports
                await self._check_drivers()              # Kernel drivers
                await self._check_services()             # Service binaries
                await self._check_scheduled_tasks()       # New scheduled tasks
                await self._check_startup_folders()       # All users startup folders
                await self._check_registry_run_keys()     # ALL run keys
                await self._check_hosts_file()            # Hosts hijacking
                await self._check_firewall_rules()        # Firewall changes
                await self._check_wmi_persistence()       # WMI subscriptions
                await self._check_usb()                   # USB + file scan

                # ── FILE SCAN + INFREQUENT CHECKS (every 5th cycle ≈ 2.5 min) ─
                if cycle % 5 == 0:
                    await self._check_files_all_drives()  # ALL drives, ALL users
                    await self._check_boot_config()       # BCD integrity
                    await self._check_defender_status()    # AV status
                    await self._check_certificate_store()  # Cert anomalies
                    await self._check_shadow_copies()      # Ransomware indicator
                    await self._check_arp_cache()          # ARP poisoning
                    await self._check_dns_cache()          # DNS poisoning
                    await self._check_system_events()      # Windows Event Log

                # ── HOURLY (every 120 cycles ≈ 1 hour) ──────────────
                if cycle % 120 == 0:
                    await self._check_full_drive_entropy_scan()  # Deep entropy scan

                await self._heartbeat()

                # Cleanup
                self._cleanup_counter += 1
                if self._cleanup_counter >= 10:
                    self._cleanup_counter = 0
                    self._cleanup_stale_entries()

            except Exception as e:
                log.error("Cycle error: %s", e, exc_info=True)

            await asyncio.sleep(30)

    # ════════════════════════════════════════════════════════════════════
    # 1. PROCESS MONITORING — All processes, all users
    # ════════════════════════════════════════════════════════════════════

    SUSPICIOUS_PATHS = [
        "\\Downloads\\", "\\Desktop\\", "\\Documents\\", "\\Pictures\\",
        "\\Videos\\", "\\Music\\", "\\Temp\\", "\\AppData\\Local\\Temp\\",
        "\\AppData\\Roaming\\", "\\AppData\\Local\\",
        "\\Users\\Public\\", "\\Windows\\Temp\\", "\\PerfLogs\\",
    ]

    async def _check_processes(self):
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-Process | Select-Object Id,ProcessName,Path,StartTime | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            processes = json.loads(output.strip())
            if isinstance(processes, dict):
                processes = [processes]

            # Batch-fetch all command lines with ONE wmic call instead of per-process
            self._cmdline_cache = self._batch_get_cmdlines()

            for proc in processes:
                pid = proc.get("Id", 0)
                name = proc.get("ProcessName", "")
                proc_path = proc.get("Path", "") or ""

                if not pid or not name:
                    continue

                key = f"process:{pid}:{name}"
                if key in self._seen_processes:
                    continue
                self._seen_processes.add(key)

                cmdline = self._get_process_cmdline(pid)
                findings = []
                risk_score = 0
                event_type = "unusual_process"
                severity = "low"

                # Check 1: Known malicious tool patterns
                if cmdline:
                    for pattern in self.CRITICAL_PATTERNS:
                        if re.search(pattern, cmdline, re.I):
                            findings.append(f"malicious_pattern:{pattern}")
                            risk_score = max(risk_score, 95)
                            severity = "critical"
                            event_type = "malicious_process"
                            break

                # Check 2: Suspicious patterns
                if cmdline and severity != "critical":
                    for pattern in self.SUSPICIOUS_PATTERNS:
                        if re.search(pattern, cmdline, re.I):
                            findings.append(f"suspicious_pattern:{pattern}")
                            risk_score = max(risk_score, 60)
                            severity = "high"
                            if event_type == "unusual_process":
                                event_type = "malicious_process"
                            break

                # Check 3: Process from user-writable dir
                if proc_path:
                    proc_lower = proc_path.lower()
                    is_system = any(p in proc_lower for p in [
                        "\\windows\\system32\\", "\\windows\\syswow64\\",
                        "\\program files\\", "\\program files (x86)\\",
                        "\\windows\\system\\",
                    ])
                    is_suspicious_path = any(p in proc_lower for p in self.SUSPICIOUS_PATHS)

                    if is_suspicious_path and not is_system:
                        findings.append(f"suspicious_path:{proc_path}")
                        risk_score = max(risk_score, 70)
                        severity = "high"
                        event_type = "malicious_process"

                # Check 4: Memory-only process (no path — process hollowing)
                if not proc_path and name.lower() not in {p.lower() for p in self.SAFE_PROCESSES}:
                    findings.append("no_path_memory_only")
                    risk_score = max(risk_score, 80)
                    severity = "critical"
                    event_type = "malicious_process"

                # Check 5: Unsigned from user dir
                if proc_path and "\\users\\" in proc_path.lower() and \
                   name.lower() not in {p.lower() for p in self.SAFE_PROCESSES}:
                    if "\\appdata\\local\\" not in proc_path.lower() and \
                       "\\appdata\\roaming\\" not in proc_path.lower():
                        findings.append(f"user_dir_execution:{proc_path}")
                        risk_score = max(risk_score, 65)
                        if severity == "low":
                            severity = "medium"

                if findings:
                    await self._send_event(SecurityEvent(
                        event_type=event_type,
                        severity=severity,
                        source="process_monitor",
                        message=f"{severity.upper()}: {name} — {'; '.join(findings)}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        user=self._get_current_user(),
                        details={
                            "pid": pid,
                            "process_name": name,
                            "process_path": proc_path,
                            "command_line": cmdline[:500] if cmdline else "",
                            "findings": findings,
                            "risk_score": risk_score,
                        }
                    ))
            # Clear cmdline cache
            self._cmdline_cache = {}
        except Exception as e:
            log.debug("Process check error: %s", e)
            self._cmdline_cache = {}

    def _batch_get_cmdlines(self) -> Dict[int, str]:
        """Get command lines for ALL processes in one WMI call."""
        result: Dict[int, str] = {}
        try:
            output = subprocess.check_output(
                'wmic process get ProcessId,CommandLine',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            lines = output.strip().split("\n")
            # First line is header, skip it
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                # Parse: command line ends with a space then PID
                # Find the last space followed by digits
                m = re.match(r'^(\d+)\s+(.+)$', line)
                if m:
                    pid = int(m.group(1))
                    cmdline = m.group(2).strip()
                    result[pid] = cmdline
        except Exception:
            pass
        return result

    def _get_process_cmdline(self, pid: int) -> str:
        """Get cmdline for a single PID. Uses batch cache if available."""
        if hasattr(self, '_cmdline_cache'):
            return self._cmdline_cache.get(pid, "")
        return ""

    # ════════════════════════════════════════════════════════════════════
    # 2. FILE MONITORING — ALL drives, ALL users, content analysis
    # ════════════════════════════════════════════════════════════════════

    async def _check_files_all_drives(self):
        """Scan ALL drives for new suspicious files — not just user folders."""
        for drive in self._get_all_drives():
            await self._scan_drive_recursive(drive)

    async def _scan_drive_recursive(self, drive: str, max_depth: int = 3):
        """
        Recursively scan a drive for new files.
        Depth-limited to avoid performance issues, but covers all user folders.
        """
        try:
            # Always scan user folders at any depth
            user_dirs = set(self._get_all_user_profiles())

            for root, dirs, files in os.walk(drive):
                rel_depth = root.replace(drive, "").count(os.sep)

                # Skip deep directories UNLESS it's a user folder
                is_user_path = any(root.startswith(ud) for ud in user_dirs)
                if rel_depth > max_depth and not is_user_path:
                    dirs.clear()
                    continue

                # Skip system restore / shadow copy
                root_lower = root.lower()
                if any(skip in root_lower for skip in [
                    "\\system volume information", "\\$recycle.bin",
                    "\\windows\\winsxs", "\\windows\\assembly",
                    "\\windows\\installer", "\\msocache",
                ]):
                    dirs.clear()
                    continue

                for fname in files:
                    try:
                        fpath = Path(root) / fname
                        path_str = str(fpath)

                        if path_str in self._seen_files:
                            continue
                        self._seen_files.add(path_str)

                        # Analyze the file
                        await self._analyze_file(fpath)

                    except Exception:
                        continue
        except Exception:
            pass

    async def _analyze_file(self, fpath: Path):
        """Analyze a single file for threats — extension, magic bytes, entropy, hash."""
        try:
            if not fpath.is_file():
                return
            fsize = fpath.stat().st_size
            if fsize == 0:
                return
            if fsize > 500 * 1024 * 1024:  # Skip files > 500MB
                return

            ext = fpath.suffix.lower()
            fname = fpath.name
            parent = str(fpath.parent)

            # Determine if this file is in a user-writable location
            locations = []
            parent_lower = parent.lower()
            # Cross-platform: Windows uses \users\, macOS/Linux use /Users/
            if "\\users\\" in parent_lower or "/users/" in parent_lower:
                locations.append("user_directory")
            if "\\temp\\" in parent_lower or "\\tmp\\" in parent_lower or "/tmp/" in parent_lower or parent_lower == "/tmp":
                locations.append("temp_directory")
            if "\\downloads\\" in parent_lower or "/downloads/" in parent_lower:
                locations.append("downloads")

            # Read file header for analysis
            header = b""
            try:
                with open(fpath, "rb") as f:
                    header = f.read(16)
            except Exception:
                pass

            real_type = self._detect_real_type(header)
            sha256 = self._calculate_hash(fpath)
            entropy = self._calculate_entropy(fpath)

            findings = []
            risk_score = 0
            event_type = "file_scanned"
            severity = "low"

            # ── Check 1: Dangerous extension ──────────────────────────
            if ext in self.DANGEROUS_EXTENSIONS:
                findings.append(f"dangerous_extension:{ext}")
                risk_score = max(risk_score, 50)
                severity = "high"
                event_type = "suspicious_file"

            # ── Check 2: Extension mismatch (disguised file) ──────────
            if ext and real_type and real_type not in ("unknown", "error", "binary", "text"):
                if ext != real_type and real_type in self.DANGEROUS_EXTENSIONS:
                    findings.append(f"extension_mismatch:{ext}->{real_type}")
                    risk_score = max(risk_score, 90)
                    severity = "critical"
                    event_type = "suspicious_file"

            # ── Check 3: Double extension (invoice.pdf.exe) ───────────
            if fname.count(".") >= 2:
                last_ext = fname.rsplit(".", 1)[-1].lower()
                if last_ext in self.DANGEROUS_EXTENSIONS:
                    findings.append(f"double_extension:{fname}")
                    risk_score = max(risk_score, 80)
                    severity = "critical"
                    event_type = "suspicious_file"

            # ── Check 4: High entropy (encoded/encrypted) ─────────────
            if fsize > 100 and entropy > 7.5:
                findings.append(f"high_entropy:{entropy:.2f}")
                risk_score = max(risk_score, 60)
                if severity == "low":
                    severity = "medium"
                if event_type == "file_scanned":
                    event_type = "suspicious_file"

            # ── Check 5: Large archive (ransomware staging) ───────────
            if ext in (".zip", ".rar", ".7z") and fsize > 10 * 1024 * 1024:
                findings.append(f"large_archive:{fsize}bytes")
                risk_score = max(risk_score, 40)
                if severity == "low":
                    severity = "medium"

            # ── Check 6: Office document from suspicious location ─────
            if ext in (".docm", ".xlsm", ".pptm", ".dotm", ".xlam") and \
               any(l in locations for l in ("temp_directory", "downloads")):
                findings.append("macro_doc_in_temp")
                risk_score = max(risk_score, 55)
                severity = "high"
                event_type = "suspicious_file"

            # ── Check 7: Executable in user-writable path (cross-platform) ──
            if ext in (".exe", ".dll", ".scr", ".msi", ".dmg") and \
               not any(p in parent_lower for p in [
                   "\\program files", "\\windows\\system32", "\\windows\\syswow64",
                   "\\windows\\system", "\\program files (x86)",
                   "/applications/", "/system/", "/usr/bin/", "/usr/local/",
               ]):
                if "\\users\\" in parent_lower or "/users/" in parent_lower or \
                   "\\temp\\" in parent_lower or "/tmp/" in parent_lower:
                    findings.append(f"executable_in_user_path:{parent}")
                    risk_score = max(risk_score, 70)
                    severity = "high"
                    event_type = "suspicious_file"

            # Skip if nothing found and it's a common system file
            if severity == "low" and not findings:
                return

            await self._send_event(SecurityEvent(
                event_type=event_type,
                severity=severity,
                source="file_monitor",
                message=f"{severity.upper()}: {fname} — {'; '.join(findings)}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=self.hostname,
                user=self._get_current_user(),
                details={
                    "file_name": fname,
                    "file_path": str(fpath),
                    "file_size": fsize,
                    "sha256": sha256,
                    "entropy": round(entropy, 4),
                    "detected_type": real_type,
                    "extension": ext,
                    "findings": findings,
                    "risk_score": risk_score,
                    "location": locations,
                }
            ))
        except Exception as e:
            log.debug("Analyze file error: %s for %s", e, fpath)

    def _detect_real_type(self, header: bytes) -> str:
        """Detect actual file type from magic bytes."""
        if not header:
            return "empty"
        for magic, ftype in self.MAGIC_BYTES.items():
            if header.startswith(magic):
                return ftype
        # Check if text
        try:
            header.decode("ascii")
            return "text"
        except Exception:
            pass
        return "binary"

    def _calculate_entropy(self, fpath: Path, max_bytes: int = 4096) -> float:
        try:
            with open(fpath, "rb") as f:
                data = f.read(max_bytes)
            if not data:
                return 0.0
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(data)
                if p > 0:
                    entropy -= p * math.log2(p)
            return round(entropy, 4)
        except Exception:
            return 0.0

    def _calculate_hash(self, fpath: Path) -> str:
        try:
            sha256 = hashlib.sha256()
            with open(fpath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return "error"

    # ════════════════════════════════════════════════════════════════════
    # 3. KERNEL DRIVER MONITORING — Rootkit detection
    # ════════════════════════════════════════════════════════════════════

    async def _check_drivers(self):
        """Enumerate all kernel drivers and check for known bad / suspicious ones."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-WmiObject Win32_SystemDriver | '
                'Select-Object Name,DisplayName,PathName,State,StartMode | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            drivers = json.loads(output.strip())
            if isinstance(drivers, dict):
                drivers = [drivers]

            for drv in drivers:
                name = drv.get("Name", "")
                path = drv.get("PathName", "") or ""

                if not name:
                    continue

                key = f"driver:{name}"
                if key in self._seen_drivers:
                    continue
                self._seen_drivers.add(key)

                findings = []

                # Check 1: Known malicious driver
                if name.lower() in self.KNOWN_BAD_DRIVERS:
                    findings.append(f"known_bad_driver:{name}")

                # Check 2: Driver from suspicious path
                if path:
                    path_lower = path.lower()
                    if any(s in path_lower for s in ["\\temp\\", "\\users\\", "\\downloads\\"]):
                        findings.append(f"suspicious_path:{path}")

                # Check 3: Driver running but not from System32 (unsigned drivers often)
                if path and "\\systemroot\\system32\\drivers\\" not in path.lower() \
                   and "\\windows\\system32\\drivers\\" not in path.lower():
                    if "\\program files\\" not in path.lower():
                        findings.append(f"non_standard_path:{path}")

                if findings:
                    await self._send_event(SecurityEvent(
                        event_type="suspicious_driver",
                        severity="high",
                        source="kernel_driver_monitor",
                        message=f"Suspicious driver: {name} — {'; '.join(findings)}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "driver_name": name,
                            "driver_path": path,
                            "state": drv.get("State"),
                            "findings": findings,
                        }
                    ))

            # Check for NEW drivers that appeared (drivers loaded since last cycle)
            # Get driver count for trend monitoring
            driver_count = len(drivers) if isinstance(drivers, list) else 1
            # Alert if anomalously many drivers (possible rootkit injection)
            if driver_count > 800:
                await self._send_event(SecurityEvent(
                    event_type="suspicious_driver",
                    severity="high",
                    source="kernel_driver_monitor",
                    message=f"Anomalous driver count: {driver_count} drivers loaded",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    hostname=self.hostname,
                    details={"driver_count": driver_count}
                ))

        except Exception as e:
            log.debug("Driver check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 4. BOOT CONFIGURATION MONITORING
    # ════════════════════════════════════════════════════════════════════

    async def _check_boot_config(self):
        """Monitor BCD for tampering (kernel-level persistence)."""
        try:
            output = subprocess.check_output(
                'bcdedit /enum',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            current_hash = hashlib.sha256(output.encode()).hexdigest()

            if not self._seen_bcd_hash:
                self._seen_bcd_hash = current_hash
                return

            if current_hash != self._seen_bcd_hash:
                old_hash = self._seen_bcd_hash
                self._seen_bcd_hash = current_hash

                # Check for dangerous settings
                dangerous = []
                if "debug" in output.lower():
                    dangerous.append("debug_enabled")
                if "testsigning" in output.lower():
                    dangerous.append("testsigning_enabled")
                if "nointegritychecks" in output.lower():
                    dangerous.append("integrity_checks_disabled")
                if "detecthal" in output.lower():
                    dangerous.append("detecthal_set")

                await self._send_event(SecurityEvent(
                    event_type="boot_config_changed",
                    severity="critical",
                    source="bcd_monitor",
                    message=f"BCD configuration changed" +
                            (f" — {'; '.join(dangerous)}" if dangerous else ""),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    hostname=self.hostname,
                    details={
                        "previous_hash": old_hash,
                        "new_hash": current_hash,
                        "dangerous_flags": dangerous,
                        "bcd_summary": output[:1000],
                    }
                ))
        except Exception as e:
            log.debug("BCD check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 5. SCHEDULED TASKS — Persistence detection
    # ════════════════════════════════════════════════════════════════════

    async def _check_scheduled_tasks(self):
        """Enumerate all scheduled tasks and flag new ones."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-ScheduledTask | '
                'Select-Object TaskName,TaskPath,State,Author,Date | ConvertTo-Json -Depth 2"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            tasks = json.loads(output.strip())
            if isinstance(tasks, dict):
                tasks = [tasks]

            for task in tasks:
                task_name = task.get("TaskName", "")
                task_path = task.get("TaskPath", "")

                if not task_name:
                    continue

                key = f"task:{task_path}\\{task_name}"
                if key in self._seen_scheduled_tasks:
                    continue
                self._seen_scheduled_tasks.add(key)

                # Flag any task in user-writable location or with suspicious name
                task_lower = task_name.lower()
                path_lower = task_path.lower()

                findings = []
                risk_score = 30

                # Suspicious task names
                suspicious_names = [
                    "update", "updater", "javaupdate", "adobe update",
                    "flash", "silverlight", "windows optimization",
                    "system restore", "security scan", "antivirus",
                    "crypto", "miner", "bitcoin",
                ]
                for sn in suspicious_names:
                    if sn in task_lower:
                        findings.append(f"suspicious_name:{task_name}")
                        risk_score = max(risk_score, 60)
                        break

                # User-level tasks (non-Microsoft)
                if "\\microsoft\\" not in path_lower and "\\windows\\" not in path_lower:
                    findings.append("non_microsoft_path")
                    risk_score = max(risk_score, 50)

                # Task runs from temp or users
                actions = self._get_task_actions(task_name)
                if actions:
                    for action in actions:
                        action_lower = action.lower()
                        if any(s in action_lower for s in ["\\temp\\", "\\users\\", "\\downloads\\"]):
                            findings.append(f"suspicious_action:{action}")
                            risk_score = max(risk_score, 70)
                            break

                if findings:
                    await self._send_event(SecurityEvent(
                        event_type="new_scheduled_task",
                        severity="high",
                        source="scheduled_task_monitor",
                        message=f"New scheduled task: {task_name} — {'; '.join(findings)}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "task_name": task_name,
                            "task_path": task_path,
                            "state": task.get("State"),
                            "author": task.get("Author", ""),
                            "findings": findings,
                            "risk_score": risk_score,
                            "actions": actions[:5] if actions else [],
                        }
                    ))
        except Exception as e:
            log.debug("Scheduled task check error: %s", e)

    def _get_task_actions(self, task_name: str) -> List[str]:
        """Get the actions for a scheduled task (to check binary paths)."""
        try:
            output = subprocess.check_output(
                f'powershell -Command "(Get-ScheduledTask -TaskName \'{task_name}\').Actions | Select-Object Execute | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5
            )
            if not output.strip():
                return []
            data = json.loads(output.strip())
            if isinstance(data, dict):
                return [data.get("Execute", "")]
            if isinstance(data, list):
                return [d.get("Execute", "") for d in data]
            return []
        except Exception:
            return []

    # ════════════════════════════════════════════════════════════════════
    # 6. SERVICE BINARY INTEGRITY
    # ════════════════════════════════════════════════════════════════════

    async def _check_services(self):
        """Monitor services for new ones, especially with suspicious binary paths."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-WmiObject Win32_Service | '
                'Select-Object Name,DisplayName,PathName,State,StartMode,ProcessId | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            services = json.loads(output.strip())
            if isinstance(services, dict):
                services = [services]

            for svc in services:
                name = svc.get("Name", "")
                path = svc.get("PathName", "") or ""

                if not name:
                    continue

                key = f"service:{name}"
                if key in self._seen_services:
                    continue
                self._seen_services.add(key)

                path_lower = path.lower()
                findings = []

                # Check 1: Binary in suspicious location
                for s in self.SUSPICIOUS_SERVICE_PATHS:
                    if s in path_lower:
                        findings.append(f"suspicious_path:{path}")
                        break

                # Check 2: Service binary not from System32/Program Files
                if path and not any(p in path_lower for p in [
                    "\\system32\\", "\\program files", "\\syswow64\\",
                ]):
                    findings.append(f"non_standard_path:{path}")

                # Check 3: Service running from Temp
                if "\\temp\\" in path_lower:
                    findings.append("running_from_temp")

                if findings:
                    await self._send_event(SecurityEvent(
                        event_type="service_binary_tampered",
                        severity="critical",
                        source="service_monitor",
                        message=f"Suspicious service: {name} — {'; '.join(findings)}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "service_name": name,
                            "display_name": svc.get("DisplayName", ""),
                            "binary_path": path,
                            "state": svc.get("State"),
                            "start_mode": svc.get("StartMode"),
                            "findings": findings,
                        }
                    ))
        except Exception as e:
            log.debug("Service check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 7. HOSTS FILE HIJACKING DETECTION
    # ════════════════════════════════════════════════════════════════════

    async def _check_hosts_file(self):
        """Monitor the hosts file for hijacking by malware."""
        hosts_path = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "drivers" / "etc" / "hosts"
        if not hosts_path.exists():
            return

        try:
            content = hosts_path.read_text()
            current_hash = hashlib.sha256(content.encode()).hexdigest()

            if not self._seen_hosts_hash:
                self._seen_hosts_hash = current_hash
                return

            if current_hash != self._seen_hosts_hash:
                old_hash = self._seen_hosts_hash
                self._seen_hosts_hash = current_hash

                # Look for hijacking patterns
                hijacked_entries = []
                for line in content.splitlines():
                    line_clean = line.strip()
                    if not line_clean or line_clean.startswith("#"):
                        continue
                    for pattern in self.HOSTS_HIJACK_PATTERNS:
                        if re.search(pattern, line_clean, re.I):
                            hijacked_entries.append(line_clean)

                # Also flag any entry redirecting localhost to external IP
                for line in content.splitlines():
                    line_clean = line.strip()
                    if line_clean.startswith("#") or not line_clean:
                        continue
                    parts = line_clean.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        if ip not in ("127.0.0.1", "::1", "0.0.0.0") and \
                           not ip.startswith("255."):
                            # Non-loopback mapping — could be legitimate or hijacking
                            pass

                if hijacked_entries:
                    await self._send_event(SecurityEvent(
                        event_type="hosts_hijacked",
                        severity="high",
                        source="hosts_file_monitor",
                        message=f"Hosts file hijacked: {len(hijacked_entries)} malicious entries",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "previous_hash": old_hash,
                            "new_hash": current_hash,
                            "hijacked_entries": hijacked_entries[:20],
                            "file_size": len(content),
                        }
                    ))
        except Exception as e:
            log.debug("Hosts file check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 8. FIREWALL RULE MONITORING
    # ════════════════════════════════════════════════════════════════════

    async def _check_firewall_rules(self):
        """Detect new/modified Windows Firewall rules (used by malware to open ports)."""
        try:
            # Non-verbose is MUCH faster on Windows Server with many rules
            output = subprocess.check_output(
                'netsh advfirewall firewall show rule name=all',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=15
            )

            # Parse out rule names
            rules = set()
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Rule Name:"):
                    name = line.split(":", 1)[1].strip()
                    if name:
                        rules.add(name)

            for rule in rules:
                if rule not in self._seen_firewall_rules:
                    self._seen_firewall_rules.add(rule)

                    # Check for suspicious rules
                    rule_lower = rule.lower()
                    suspicious = False
                    findings = []

                    if any(kw in rule_lower for kw in ["allow", "open", "permit", "inbound"]):
                        if not any(safe in rule_lower for safe in [
                            "core networking", "file and printer", "remote desktop",
                            "remote assistance", "windows update", "windows features",
                            "branchcache", "network discovery", "windows defender",
                        ]):
                            suspicious = True
                            findings.append("potentially_permissive")

                    if any(kw in rule_lower for kw in ["temp", "download", "remote", "backdoor"]):
                        suspicious = True
                        findings.append("suspicious_name")

                    if suspicious:
                        await self._send_event(SecurityEvent(
                            event_type="firewall_rule_changed",
                            severity="high",
                            source="firewall_monitor",
                            message=f"New firewall rule: {rule}" +
                                    (f" — {'; '.join(findings)}" if findings else ""),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            details={
                                "rule_name": rule,
                                "findings": findings,
                            }
                        ))
        except Exception as e:
            log.debug("Firewall check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 9. STARTUP FOLDERS — All users, current user
    # ════════════════════════════════════════════════════════════════════

    async def _check_startup_folders(self):
        """Monitor ALL startup folders (all users + all user profiles)."""
        startup_folders = [
            # All Users
            os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData") +
            "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
            os.environ.get("ProgramData", "C:\\ProgramData") +
            "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        ]
        # Add each user's startup folder
        for profile in self._get_all_user_profiles():
            startup_folders.append(
                f"{profile}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
            )

        for folder in startup_folders:
            if not os.path.isdir(folder):
                continue
            try:
                for item in Path(folder).iterdir():
                    if not item.is_file():
                        continue
                    path_str = str(item)
                    if path_str in self._seen_files:
                        continue
                    self._seen_files.add(path_str)

                    ext = item.suffix.lower()
                    if ext in (".lnk", ".url", ".exe", ".vbs", ".ps1", ".bat", ".cmd", ".js", ".hta"):
                        sha256 = self._calculate_hash(item)
                        await self._send_event(SecurityEvent(
                            event_type="startup_item",
                            severity="high",
                            source="startup_folder_monitor",
                            message=f"New startup item: {item.name} (in {Path(folder).name})",
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            user=self._get_current_user(),
                            details={
                                "file_name": item.name,
                                "file_path": path_str,
                                "sha256": sha256,
                                "startup_folder": folder,
                            }
                        ))
            except Exception:
                continue

    # ════════════════════════════════════════════════════════════════════
    # 10. REGISTRY RUN KEYS — ALL users
    # ════════════════════════════════════════════════════════════════════

    async def _check_registry_run_keys(self):
        """Monitor ALL registry Run/RunOnce keys for ALL users."""
        reg_paths = [
            # Current user
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            # Local machine (all users)
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
            # Wow6432Node (32-bit on 64-bit)
            "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            # Active Setup
            "HKLM\\Software\\Microsoft\\Active Setup\\Installed Components",
            # Startup folders via registry
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
            # Policy-based persistence
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        ]

        for reg_key in reg_paths:
            try:
                output = subprocess.check_output(
                    f'reg query "{reg_key}"',
                    shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5
                )
                for line in output.splitlines():
                    line = line.strip()
                    if not line or line.startswith("HKEY") or \
                       "REG_" not in line or "(Default)" in line:
                        continue

                    key_str = f"{reg_key}:{line}"
                    if key_str in self._seen_startup_items:
                        continue
                    self._seen_startup_items.add(key_str)

                    # Parse value name and data
                    parts = line.rsplit("REG_", 1)
                    if len(parts) < 2:
                        continue
                    value_name = parts[0].strip()
                    value_data = parts[1].strip()
                    # Remove type prefix
                    for rtype in ["SZ    ", "EXPAND_SZ    ", "MULTI_SZ    ", "DWORD    ", "BINARY    "]:
                        if value_data.startswith(rtype):
                            value_data = value_data[len(rtype):].strip()
                            break

                    value_lower = value_data.lower()

                    # Check for suspicious Run entries
                    findings = []
                    risk_score = 30

                    if any(s in value_lower for s in ["\\temp\\", "\\users\\", "\\downloads\\"]):
                        findings.append("suspicious_path")
                        risk_score = max(risk_score, 70)

                    if any(s in value_lower for s in [".ps1", ".vbs", ".js", ".hta", ".bat"]):
                        if "\\program files\\" not in value_lower:
                            findings.append("script_as_startup")
                            risk_score = max(risk_score, 65)

                    for pattern in self.CRITICAL_PATTERNS:
                        if re.search(pattern, value_lower):
                            findings.append("malicious_pattern")
                            risk_score = max(risk_score, 95)
                            break

                    if findings:
                        await self._send_event(SecurityEvent(
                            event_type="startup_item",
                            severity="high",
                            source="registry_monitor",
                            message=f"New Run key: {value_name} — {'; '.join(findings)}",
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            details={
                                "registry_key": reg_key,
                                "value_name": value_name,
                                "value_data": value_data,
                                "findings": findings,
                                "risk_score": risk_score,
                            }
                        ))
            except Exception:
                continue

    # ════════════════════════════════════════════════════════════════════
    # 11. WMI PERSISTENCE DETECTION
    # ════════════════════════════════════════════════════════════════════

    async def _check_wmi_persistence(self):
        """Check for WMI event subscriptions (common persistence mechanism)."""
        for namespace in self.WMI_PERSISTENCE_NAMESPACES:
            try:
                # Get all __EventFilter objects (WMI persistence)
                output = subprocess.check_output(
                    f'powershell -Command "Get-WmiObject -Namespace {namespace} -Class __EventFilter | '
                    f'Select-Object Name,Query,EventNameSpace | ConvertTo-Json"',
                    shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
                )
                if not output.strip():
                    continue

                filters = json.loads(output.strip())
                if isinstance(filters, dict):
                    filters = [filters]

                for flt in filters:
                    name = flt.get("Name", "")
                    query = flt.get("Query", "")
                    if not name:
                        continue

                    key = f"wmi_filter:{namespace}:{name}"
                    if key in self._seen_wmi_subscriptions:
                        continue
                    self._seen_wmi_subscriptions.add(key)

                    # Check if the filter triggers on process creation or timer
                    query_lower = query.lower()
                    findings = []

                    if "processstarttrace" in query_lower or "__instancecreationevent" in query_lower:
                        findings.append("triggers_on_process_creation")
                    if "__timerevent" in query_lower or "intervalminutes" in query_lower:
                        findings.append("timer_based")
                    if "commandlinetemplate" in query_lower or "active script event consumer" in query_lower:
                        findings.append("executes_script")

                    # Get the consumer associated with this filter
                    consumer_output = subprocess.check_output(
                        f'powershell -Command '
                        f'"Get-WmiObject -Namespace {namespace} -Class __FilterToConsumerBinding | '
                        f'Where-Object {{$_.Filter -match \'{name}\'}} | '
                        f'Select-Object Consumer | ConvertTo-Json"',
                        shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5
                    )

                    if findings or consumer_output.strip():
                        if not findings:
                            findings.append("wmi_persistence")
                        await self._send_event(SecurityEvent(
                            event_type="wmi_persistence",
                            severity="critical",
                            source="wmi_monitor",
                            message=f"WMI persistence: {name} — {'; '.join(findings)}",
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            details={
                                "filter_name": name,
                                "namespace": namespace,
                                "query": query[:500],
                                "findings": findings,
                                "consumer_info": consumer_output[:500],
                            }
                        ))
            except Exception:
                continue

    # ════════════════════════════════════════════════════════════════════
    # 12. WINDOWS DEFENDER / AV STATUS
    # ════════════════════════════════════════════════════════════════════

    async def _check_defender_status(self):
        """Check if Windows Defender is disabled or tampered with."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-MpComputerStatus | '
                'Select-Object AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,'
                'NISEnabled,FirewallEnabled,AMServiceEnabled,'
                'AntivirusSignatureLastUpdated,QuickScanLastUpdated | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            status = json.loads(output.strip())
            issues = []

            if not status.get("AntivirusEnabled"):
                issues.append("AntivirusDisabled")
            if not status.get("RealTimeProtectionEnabled"):
                issues.append("RealTimeProtectionDisabled")
            if not status.get("NISEnabled"):
                issues.append("NetworkInspectionDisabled")
            if not status.get("FirewallEnabled"):
                issues.append("FirewallDisabled")
            if not status.get("AMServiceEnabled"):
                issues.append("AntimalwareServiceDisabled")

            if issues:
                await self._send_event(SecurityEvent(
                    event_type="defender_disabled",
                    severity="critical",
                    source="defender_status_monitor",
                    message=f"Windows Defender issues: {'; '.join(issues)}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    hostname=self.hostname,
                    details={
                        "issues": issues,
                        "full_status": status,
                    }
                ))
        except Exception as e:
            log.debug("Defender check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 13. CERTIFICATE STORE ANOMALY DETECTION
    # ════════════════════════════════════════════════════════════════════

    async def _check_certificate_store(self):
        """Check certificate store for untrusted/self-signed certificates."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-ChildItem -Path Cert:\\LocalMachine\\My, '
                'Cert:\\LocalMachine\\Root, Cert:\\CurrentUser\\My | '
                'Select-Object Subject,Issuer,NotAfter,SerialNumber,Thumbprint | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=15
            )
            if not output.strip():
                return

            certs = json.loads(output.strip())
            if isinstance(certs, dict):
                certs = [certs]

            for cert in certs:
                thumbprint = cert.get("Thumbprint", "")
                if not thumbprint or thumbprint in self._seen_cert_hashes:
                    continue
                self._seen_cert_hashes.add(thumbprint)

                issuer = cert.get("Issuer", "")
                subject = cert.get("Subject", "")
                not_after = cert.get("NotAfter", "")

                findings = []

                # Check for known bad issuers
                for bad_issuer in self.KNOWN_BAD_CERT_ISSUERS:
                    if bad_issuer.lower() in issuer.lower():
                        findings.append(f"suspicious_issuer:{issuer}")

                # Check for self-signed certs (subject == issuer)
                if subject and issuer and subject == issuer:
                    # Self-signed can be legitimate, but flag for review
                    pass

                # Check for expired certs
                if not_after:
                    try:
                        expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                        if expiry < datetime.now(timezone.utc):
                            findings.append("expired_certificate")
                    except Exception:
                        pass

                if findings:
                    await self._send_event(SecurityEvent(
                        event_type="certificate_anomaly",
                        severity="high",
                        source="certificate_monitor",
                        message=f"Certificate anomaly: {subject} — {'; '.join(findings)}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "subject": subject,
                            "issuer": issuer,
                            "thumbprint": thumbprint,
                            "not_after": not_after,
                            "findings": findings,
                        }
                    ))
        except Exception as e:
            log.debug("Certificate check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 14. VOLUME SHADOW COPY MONITORING (Ransomware Detection)
    # ════════════════════════════════════════════════════════════════════

    async def _check_shadow_copies(self):
        """Monitor Volume Shadow Copies for deletion (ransomware indicator)."""
        try:
            # Check shadows on ALL drives, not just C:
            output = subprocess.check_output(
                'vssadmin list shadows',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=15
            )

            # Count shadow copies
            count = 0
            for line in output.splitlines():
                if "Shadow Copy Volume:" in line:
                    count += 1

            if self._seen_shadow_copies == -1:
                self._seen_shadow_copies = count
                log.info("Initial shadow copy count: %d", count)
                return

            if count < self._seen_shadow_copies:
                deleted = self._seen_shadow_copies - count
                self._seen_shadow_copies = count

                await self._send_event(SecurityEvent(
                    event_type="shadow_copy_deleted",
                    severity="critical",
                    source="shadow_copy_monitor",
                    message=f"{deleted} shadow copy(s) deleted — possible ransomware activity",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    hostname=self.hostname,
                    details={
                        "previous_count": self._seen_shadow_copies + deleted,
                        "current_count": count,
                        "deleted_count": deleted,
                    }
                ))

            self._seen_shadow_copies = count

        except subprocess.CalledProcessError as e:
            # vssadmin might not be available or no shadows
            if self._seen_shadow_copies == -1:
                self._seen_shadow_copies = 0
        except Exception as e:
            log.debug("Shadow copy check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 15. LISTENING PORTS
    # ════════════════════════════════════════════════════════════════════

    async def _check_listening_ports(self):
        """Monitor for new listening ports (backdoors / C2)."""
        try:
            output = subprocess.check_output(
                'netstat -ano | findstr LISTENING',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )

            for line in output.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue

                local = parts[1]
                pid = parts[-1]

                if ":" not in local:
                    continue

                # Parse port
                addr, port_str = local.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    continue

                port_key = f"listen:{addr}:{port}"
                if port_key in self._seen_listening_ports:
                    continue
                self._seen_listening_ports.add(port_key)

                # Check for high/unknown ports (common for backdoors)
                if port > 49151 and port not in (0,):
                    # Dynamic/private port range — could be legitimate
                    findings = []
                    risk_score = 20

                    # Try to get the process name
                    proc_name = ""
                    try:
                        proc_out = subprocess.check_output(
                            f'powershell -Command "(Get-Process -Id {pid}).ProcessName"',
                            shell=True, text=True, stderr=subprocess.DEVNULL, timeout=3
                        )
                        proc_name = proc_out.strip()
                    except Exception:
                        pass

                    if proc_name and proc_name.lower() not in {p.lower() for p in self.SAFE_PROCESSES}:
                        findings.append(f"unknown_process:{proc_name}")
                        risk_score = max(risk_score, 40)

                    if addr == "0.0.0.0" or addr == "::":
                        findings.append("listening_on_all_interfaces")
                        risk_score = max(risk_score, 30)

                    if findings and risk_score >= 30:
                        await self._send_event(SecurityEvent(
                            event_type="suspicious_network",
                            severity="medium",
                            source="port_monitor",
                            message=f"New listening port: {port} ({proc_name or 'unknown'})" +
                                    (f" — {'; '.join(findings)}" if findings else ""),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            details={
                                "port": port,
                                "address": addr,
                                "pid": pid,
                                "process_name": proc_name,
                                "findings": findings,
                                "risk_score": risk_score,
                            }
                        ))
        except Exception as e:
            log.debug("Port check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 16. NETWORK CONNECTIONS
    # ════════════════════════════════════════════════════════════════════

    async def _check_network(self):
        """Check for suspicious outbound connections to external IPs."""
        try:
            result = subprocess.run(
                ['netstat', '-an'], capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.split('\n')[4:]

            suspicious_count = 0
            for line in lines:
                if 'ESTABLISHED' not in line:
                    continue
                parts = line.split()
                if len(parts) < 4:
                    continue

                remote = parts[3] if ':' in parts[3] else \
                         parts[4] if len(parts) > 4 else ''
                if not remote or ':' not in remote:
                    continue

                ip = remote.rsplit(':', 1)[0]
                if not ip:
                    continue

                # Skip private IPs
                if self._is_private_ip(ip):
                    continue

                # Skip safe domains
                if ip in self.SAFE_IPS or self._is_safe_domain(ip):
                    continue

                suspicious_count += 1

                # Alert on threshold
                if suspicious_count > 5:
                    await self._send_event(SecurityEvent(
                        event_type="suspicious_network",
                        severity="medium",
                        source="network_monitor",
                        message=f"{suspicious_count} external connections established",
                        source_ip="127.0.0.1",
                        hostname=self.hostname,
                        details={"count": suspicious_count}
                    ))
                    break

        except Exception as e:
            log.debug("Network check error: %s", e)

    def _is_private_ip(self, ip: str) -> bool:
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            first, second = int(parts[0]), int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 169 and second == 254:
                return True  # Link-local
            return False
        except Exception:
            return False

    def _is_safe_domain(self, ip: str) -> bool:
        try:
            now = time.time()
            if ip in self._ptr_cache:
                cached_time, is_safe = self._ptr_cache[ip]
                if now - cached_time < self._PTR_CACHE_VALIDITY:
                    return is_safe
            hostname = socket.gethostbyaddr(ip)[0].lower()
            is_safe = any(hostname.endswith(suffix) for suffix in self.SAFE_DOMAIN_SUFFIXES)
            self._ptr_cache[ip] = (now, is_safe)
            return is_safe
        except (socket.herror, socket.gaierror):
            return False
        except Exception:
            return False

    # ════════════════════════════════════════════════════════════════════
    # 17. ARP CACHE POISONING DETECTION
    # ════════════════════════════════════════════════════════════════════

    async def _check_arp_cache(self):
        """Check ARP cache for multiple IPs mapping to same MAC (ARP poisoning)."""
        try:
            output = subprocess.check_output(
                'arp -a',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )

            mac_to_ips = defaultdict(list)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    if mac.count("-") == 5 and mac != "ff-ff-ff-ff-ff-ff":
                        if ip not in self._seen_arp_entries:
                            self._seen_arp_entries.add(ip)
                        mac_to_ips[mac].append(ip)

            # Alert on duplicate MACs (only once per MAC)
            for mac, ips in mac_to_ips.items():
                if mac in self._seen_arp_alerts:
                    continue
                if len(ips) >= 3 and len(set(ips)) >= 3:
                    self._seen_arp_alerts.add(mac)
                    await self._send_event(SecurityEvent(
                        event_type="suspicious_network",
                        severity="high",
                        source="arp_monitor",
                        message=f"Possible ARP poisoning: MAC {mac} has {len(ips)} IPs",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "mac_address": mac,
                            "ip_addresses": ips,
                            "count": len(ips),
                        }
                    ))
        except Exception as e:
            log.debug("ARP check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 18. DNS CACHE POISONING DETECTION
    # ════════════════════════════════════════════════════════════════════

    async def _check_dns_cache(self):
        """Check DNS cache for suspicious entries."""
        try:
            output = subprocess.check_output(
                'ipconfig /displaydns',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )

            suspicious_domains = []
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("    ") and "---" not in line and \
                   "." in line and not line.startswith("Record"):
                    name = line.strip()
                    # Check for domains trying to look like legitimate ones
                    for legit in ["microsft", "gooogle", "facebok", "gith ub",
                                  "goggle", "micrsoft", "mircosoft",
                                  "winodws", "update"]:
                        if legit.replace(" ", "") in name.lower().replace(" ", ""):
                            suspicious_domains.append(name)
                            break

            if suspicious_domains:
                await self._send_event(SecurityEvent(
                    event_type="suspicious_network",
                    severity="high",
                    source="dns_monitor",
                    message=f"Possible DNS poisoning: {len(suspicious_domains)} lookalike domains cached",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    hostname=self.hostname,
                    details={
                        "suspicious_domains": suspicious_domains[:20],
                        "count": len(suspicious_domains),
                    }
                ))
        except Exception as e:
            log.debug("DNS check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 19. USB DEVICE + FILE SCANNING
    # ════════════════════════════════════════════════════════════════════

    async def _check_usb(self):
        """Detect new USB devices and scan their files."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-PnpDevice -Class Usb -Status OK | '
                'Select-Object FriendlyName,ID | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            devices = json.loads(output.strip())
            if isinstance(devices, dict):
                devices = [devices]

            for dev in devices:
                name = dev.get("FriendlyName", "")
                dev_id = dev.get("ID", "")

                if name and dev_id:
                    is_new = dev_id not in self._seen_usb
                    self._seen_usb.add(dev_id)

                    if is_new:
                        await self._send_event(SecurityEvent(
                            event_type="usb_connected",
                            severity="low",
                            source="usb_monitor",
                            message=f"USB device connected: {name}",
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            details={"device_name": name, "device_id": dev_id}
                        ))

                        # Scan removable drives for suspicious files
                        await self._scan_removable_drives()

        except Exception as e:
            log.debug("USB check error: %s", e)

    async def _scan_removable_drives(self):
        """Scan all removable drives for suspicious files."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-WmiObject Win32_LogicalDisk | '
                'Where-Object {$_.DriveType -eq 2} | Select-Object DeviceID | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            drives = json.loads(output.strip())
            if isinstance(drives, dict):
                drives = [drives]

            for d in drives:
                drive = d.get("DeviceID", "")
                if not drive:
                    continue

                log.info("Scanning removable drive %s for threats...", drive)

                scanned = 0
                max_files = 500

                for root, dirs, files in os.walk(drive):
                    rel_depth = root.replace(drive, "").count(os.sep)
                    if rel_depth > 3:
                        dirs.clear()
                        continue

                    for fname in files:
                        if scanned >= max_files:
                            return
                        scanned += 1
                        try:
                            fpath = Path(root) / fname
                            ext = fpath.suffix.lower()

                            if ext not in self.DANGEROUS_EXTENSIONS:
                                continue

                            path_str = str(fpath)
                            if path_str in self._seen_files:
                                continue
                            self._seen_files.add(path_str)

                            await self._analyze_file(fpath)

                        except Exception:
                            continue
        except Exception as e:
            log.debug("Removable drive scan error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 20. SYSTEM EVENTS (Windows Event Log)
    # ════════════════════════════════════════════════════════════════════

    async def _check_system_events(self):
        """Monitor important Windows Security Event Log entries."""
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-WinEvent -LogName Security -MaxEvents 10 '
                '-ErrorAction SilentlyContinue | '
                'Select-Object Id,TimeCreated,Message | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=10
            )
            if not output.strip():
                return

            events = json.loads(output.strip())
            if isinstance(events, dict):
                events = [events]

            important = {
                4624: ("successful_logon", "info"),
                4625: ("failed_login", "medium"),
                4634: ("logoff", "info"),
                4648: ("logon_with_explicit_credentials", "medium"),
                4672: ("admin_logon", "info"),
                4688: ("process_created", "low"),
                4698: ("scheduled_task_created", "high"),
                4700: ("scheduled_task_enabled", "high"),
                4720: ("user_created", "high"),
                4722: ("user_enabled", "medium"),
                4724: ("password_reset", "high"),
                4728: ("member_added_to_security_group", "high"),
                4732: ("member_added_to_local_group", "high"),
                4740: ("account_lockout", "high"),
                4742: ("computer_account_changed", "medium"),
                4756: ("member_added_to_universal_group", "high"),
                4768: ("kerberos_ticket_requested", "info"),
                4771: ("kerberos_pre_auth_failed", "medium"),
                4776: ("credential_validation", "low"),
                4798: ("user_group_enumerated", "low"),
                4799: ("security_group_enumerated", "low"),
                5136: ("directory_service_change", "high"),
                5140: ("network_share_accessed", "medium"),
                5145: ("network_share_object_accessed", "medium"),
                5156: ("windows_filtering_platform_connection", "low"),
                5157: ("windows_filtering_platform_connection_blocked", "medium"),
                5158: ("windows_filtering_platform_bind", "medium"),
                5379: ("credential_manager_credentials_read", "high"),
                5382: ("secureboot_config_changed", "high"),
                6416: ("new_device_installed", "low"),
                6419: ("device_removed", "low"),
                6420: ("device_disabled", "medium"),
                6421: ("device_enabled", "low"),
                6422: ("device_installation_blocked", "low"),
                6423: ("device_installation_forbidden", "low"),
                6424: ("device_installation_rollback", "medium"),
            }

            for evt in events:
                event_id = evt.get("Id", 0)
                if event_id in important:
                    event_type, default_severity = important[event_id]
                    message = evt.get("Message", "")[:200]

                    # Dedup by event ID + timestamp
                    key = f"sys_event:{event_id}:{evt.get('TimeCreated', '')}"
                    if key in self._seen_system_events:
                        continue
                    self._seen_system_events.add(key)

                    await self._send_event(SecurityEvent(
                        event_type=event_type,
                        severity=default_severity,
                        source="windows_eventlog",
                        message=f"Security Event {event_id}: {message[:100]}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "event_id": event_id,
                            "time_created": evt.get("TimeCreated", ""),
                            "full_message": message,
                        }
                    ))
        except Exception as e:
            log.debug("System events check error: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # 21. FULL DRIVE ENTROPY SCAN (Hourly Deep Scan)
    # ════════════════════════════════════════════════════════════════════

    async def _check_full_drive_entropy_scan(self):
        """Deep entropy scan across all drives — detect encrypted/encoded payloads."""
        log.info("Running hourly deep entropy scan across all drives...")
        scanned = 0
        high_entropy_files = 0

        for drive in self._get_all_drives():
            try:
                for root, dirs, files in os.walk(drive):
                    root_lower = root.lower()
                    # Skip system internals
                    if any(s in root_lower for s in [
                        "\\system volume information", "\\$recycle.bin",
                        "\\windows\\winsxs", "\\windows\\assembly",
                        "\\windows\\installer", "\\windows\\system32\\drivers",
                        "\\windows\\system32\\spp\\",
                    ]):
                        dirs.clear()
                        continue

                    # Only go 2 levels deep on non-user folders
                    rel_depth = root.replace(drive, "").count(os.sep)
                    if rel_depth > 2 and "\\users\\" not in root_lower:
                        dirs.clear()
                        continue

                    for fname in files:
                        if scanned >= 2000:  # Cap per cycle
                            log.info("Deep scan: %d files scanned, %d high-entropy found",
                                     scanned, high_entropy_files)
                            return
                        scanned += 1

                        try:
                            fpath = Path(root) / fname
                            if not fpath.is_file():
                                continue
                            fsize = fpath.stat().st_size
                            if fsize < 1024 or fsize > 100 * 1024 * 1024:  # 1KB - 100MB
                                continue

                            ext = fpath.suffix.lower()
                            if ext in self.DANGEROUS_EXTENSIONS:
                                continue  # Already caught by regular scan

                            entropy = self._calculate_entropy(fpath)
                            if entropy > 7.8 and fsize > 5000:
                                high_entropy_files += 1
                                sha256 = self._calculate_hash(fpath)
                                await self._send_event(SecurityEvent(
                                    event_type="suspicious_file",
                                    severity="medium",
                                    source="deep_entropy_scanner",
                                    message=f"High entropy file: {fname} (entropy={entropy:.2f})",
                                    timestamp=datetime.now(timezone.utc).isoformat(),
                                    hostname=self.hostname,
                                    details={
                                        "file_name": fname,
                                        "file_path": str(fpath),
                                        "file_size": fsize,
                                        "sha256": sha256,
                                        "entropy": round(entropy, 4),
                                        "extension": ext,
                                        "note": "deep_scan_high_entropy",
                                    }
                                ))
                        except Exception:
                            continue
            except Exception:
                continue

        log.info("Deep scan complete: %d files, %d high-entropy", scanned, high_entropy_files)

    # ════════════════════════════════════════════════════════════════════
    # 22. HEARTBEAT
    # ════════════════════════════════════════════════════════════════════

    async def _heartbeat(self):
        now = time.time()
        if now - self._last_heartbeat < 300:  # 5 min
            return

        self._last_heartbeat = now

        try:
            # Collect stats
            stats = {
                "monitored_drives": len(self._get_all_drives()),
                "user_profiles": len(self._get_all_user_profiles()),
                "seen_processes": len(self._seen_processes),
                "seen_files": len(self._seen_files),
                "seen_services": len(self._seen_services),
                "active_drivers": len(self._seen_drivers),
                "seen_firewall_rules": len(self._seen_firewall_rules),
            }

            await self._send_event(SecurityEvent(
                event_type="agent_heartbeat",
                severity="info",
                source="agent_heartbeat",
                message=f"Enterprise Agent running on {self.hostname}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=self.hostname,
                details={
                    "uptime_seconds": int(now - self._start_time.timestamp()),
                    "os": platform.system(),
                    "os_version": platform.version(),
                    "monitoring_stats": stats,
                }
            ))
        except Exception as e:
            log.debug("Heartbeat: %s", e)

    # ════════════════════════════════════════════════════════════════════
    # CLEANUP
    # ════════════════════════════════════════════════════════════════════

    def _cleanup_stale_entries(self):
        """Periodic cleanup of rate limiter timestamps."""
        now = time.time()
        stale_cutoff = 120
        cleaned = 0
        for etype in list(self._event_type_timestamps.keys()):
            original_len = len(self._event_type_timestamps[etype])
            self._event_type_timestamps[etype] = [
                t for t in self._event_type_timestamps[etype] if now - t < stale_cutoff
            ]
            cleaned += original_len - len(self._event_type_timestamps[etype])
            if not self._event_type_timestamps[etype]:
                del self._event_type_timestamps[etype]
        dedup_cleaned = 0
        for key in list(self._dedup_cache.keys()):
            if now - self._dedup_cache[key] > stale_cutoff:
                del self._dedup_cache[key]
                dedup_cleaned += 1
        if cleaned or dedup_cleaned:
            log.debug("Cleanup: %d rate-limit + %d dedup entries", cleaned, dedup_cleaned)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

async def main():
    import argparse
    parser = argparse.ArgumentParser(description="CyberNova Enterprise Host Agent")
    parser.add_argument("--backend", default="http://localhost:8000")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin123")
    parser.add_argument("--tenant", default="default")
    args = parser.parse_args()

    agent = HostAgent(
        backend_url=args.backend,
        username=args.username,
        password=args.password,
        tenant_id=args.tenant
    )

    try:
        await agent.start()
    except KeyboardInterrupt:
        await agent.stop()


if __name__ == "__main__":
    asyncio.run(main())
