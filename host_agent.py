"""
CyberNova — HOST AGENT (Filtered)
Real-time Windows Security Agent
ALERTS ONLY ON REAL THREATS - No noise!
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import socket
import subprocess
import time
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from collections import defaultdict

import httpx

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s | %(levelname)s | %(message)s'
)
log = logging.getLogger("cybernova.agent")


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


class HostAgent:
    """
    SMART Security Agent - Only Alerts on Real Threats!
    
    Filtering principles:
    1. Only alert on NEW suspicious items (not repeat every cycle)
    2. Only alert on ACTUAL malicious patterns (not normal processes)
    3. Rate limited heartbeat (once per 5 minutes, not every 5 seconds)
    4. Threshold based - need X events in Y time to alert
    5. Whitelisted known safe IPs/domains
    """
    
    # ==================== THREAT SIGNATURES ====================
    # These ALWAYS trigger alerts - NO FILTERING
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
    ]
    
    # Suspicious but needs verification
    SUSPICIOUS_PATTERNS = [
        r"powershell.*-wmi",
        r"powershell.*-exec",
        r"net.*user.*add",
        r"new-service.*-persist",
        r"schtasks.*create",
        r"wmic.*process.*call",
    ]
    
    # Known safe IPs (whitelisted)
    SAFE_IPS = {
        "8.8.8.8", "8.8.4.4",  # Google DNS
        "1.1.1.1", "1.0.0.1",  # Cloudflare DNS
        "9.9.9.9",  # Quad9
        "127.0.0.1", "localhost",
    }
    
    # Safe domain suffixes for PTR validation (to avoid alerting on legitimate services)
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
    }
    
    # Known safe processes
    SAFE_PROCESSES = {
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
        "explorer.exe", "svchost.exe", "services.exe", 
        "lsass.exe", "winlogon.exe", "csrss.exe",
        "taskmgr.exe", "dwm.exe", "conhost.exe",
    }
    
    # Dangerous extensions
    DANGEROUS_EXTENSIONS = {".exe", ".dll", ".scr", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd"}
    
    def __init__(self, backend_url: str, username: str = "", password: str = "", tenant_id: str = "default"):
        self.backend_url = backend_url.rstrip('/')
        self.username = username or os.environ.get("AGENT_USERNAME", "")
        self.password = password or os.environ.get("AGENT_PASSWORD", "")
        if not self.username or not self.password:
            raise ValueError("Username and password are required — set AGENT_USERNAME and AGENT_PASSWORD env vars")
        self.hostname = socket.gethostname()
        self._running = False
        self._auth_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: float = 0
        self._token_refresh_buffer = 60  # Refresh 60s before expiry
        self._task: Optional[asyncio.Task] = None
        self._start_time = datetime.now(timezone.utc)
        # Historical per-IP connection counts for smart thresholding
        self._external_history = defaultdict(list)
         
        # SMART TRACKING - Only track NEW things
        self._seen_external_ips: Set[str] = set()           # IP:port -> already alerted
        self._seen_files: Set[str] = set()                 # File paths already checked
        self._seen_usb: Set[str] = set()                # USB device IDs
        self._seen_processes: Set[str] = set()             # Process names seen
        self._seen_downloads: Set[str] = set()          # Downloaded files
        self._seen_services: Set[str] = set()           # Service names
        self._seen_ports: Set[int] = set()            # Listening ports
        
        # PTR cache for domain safety checks
        self._ptr_cache = {}
        self._PTR_CACHE_VALIDITY = 300  # 5 minutes
        
        # Initialize seen files to avoid alerting on existing files
        self._initialize_seen_files()
        
        # Deduplication cache: event signature -> last emit timestamp
        self._dedup_cache: Dict[str, float] = {}
        # Per-event-type rate limiter windows (60s)
        self._event_type_timestamps: Dict[str, List[float]] = defaultdict(list)
        
        # THRESHOLD TRACKING - Count events over time
        self._event_counts: Dict[str, List[float]] = defaultdict(list)  # event_type -> [timestamps]
        
        # Periodic stale entry cleanup counter
        self._cleanup_counter = 0
        
        # Heartbeat throttle (only once per 5 min)
        self._last_heartbeat = 0
        # SOAR integration (toggleable via environment variable)
        self._soar_enabled = str(os.environ.get("CYBERNOVA_SOAR_ENABLED", "false")).lower() in {"1", "true", "yes"}
        self._soar_webhook = os.environ.get("CYBERNOVA_SOAR_WEBHOOK")
        
    def _initialize_seen_files(self):
        """Pre-populate seen files to avoid alerting on existing files"""
        user = self._get_current_user()
        watch_paths = [
            f"C:\\Users\\{user}\\Downloads",
            f"C:\\Users\\{user}\\Desktop", 
        ]
        
        for watch_path in watch_paths:
            if not os.path.exists(watch_path):
                continue
            try:
                for item in Path(watch_path).iterdir():
                    if item.is_file():
                        self._seen_files.add(str(item))
            except Exception:
                continue
        
    async def start(self):
        log.info("=" * 60)
        log.info("CYBERNOVA HOST AGENT (SMART FILTER)")
        log.info("=" * 60)
        log.info("Host: %s", self.hostname)
        log.info("Backend: %s", self.backend_url)
        log.info("Mode: ALERT ONLY ON REAL THREATS")
        
        await self._authenticate()
        if not self._auth_token:
            log.error("AUTH FAILED!")
            return
        
        self._running = True
        self._task = asyncio.create_task(self._monitoring_loop())
        
        try:
            await self._task
        except asyncio.CancelledError:
            log.info("Agent stopped")
        finally:
            self._running = False
    
    async def _ensure_valid_token(self):
        """Ensure we have a valid token, refresh if needed"""
        if self._is_token_valid():
            return
        if self._refresh_token:
            await self._refresh_token_if_needed()
        if not self._is_token_valid():
            await self._authenticate()
            
    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            
    async def _authenticate(self):
        """Authenticate using login, get access + refresh tokens"""
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
                    
                    # Calculate expiry (assuming 15 min for access token)
                    self._token_expires_at = time.time() + (15 * 60 - self._token_refresh_buffer)
                    log.info("Authenticated OK (access + refresh tokens)")
                else:
                    log.error("Auth failed: %s", resp.status_code)
        except Exception as e:
            log.error("Auth failed: %s", e)
    
    async def _refresh_token_if_needed(self):
        """Refresh token if about to expire"""
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
                        log.info("Token refreshed OK")
                    else:
                        # Refresh failed, re-authenticate
                        log.warning("Token refresh failed, re-authenticating...")
                        await self._authenticate()
            except Exception as e:
                log.error("Token refresh error: %s", e)
                await self._authenticate()
    
    def _is_token_valid(self) -> bool:
        """Check if current token is valid"""
        if not self._auth_token:
            return False
        return time.time() < self._token_expires_at
            
    async def _send_event(self, event: SecurityEvent):
        try:
            # Whitelist/internal events: skip if explicitly marked
            if event.extra.get("whitelist"):
                log.debug("Skipping whitelisted event: %s", event.event_type)
                return

            # Apply per-event deduplication (60s window)
            dedup_key = self._get_dedupe_key(event)
            now = time.time()
            last = self._dedup_cache.get(dedup_key)
            if last is not None and (now - last) < 60:
                log.debug("Deduplicated event within 60s: %s", dedup_key)
                return
            self._dedup_cache[dedup_key] = now
            # Per-event-type rate limiting (60s window)
            # ONLY rate-limit high-volume informational events — never suppress security alerts
            _HIGH_VOLUME_EVENTS = {"external_connection", "external_connection_threshold", "suspicious_network", "agent_heartbeat", "usb_connected"}
            etype = event.event_type
            if etype in _HIGH_VOLUME_EVENTS:
                self._event_type_timestamps[etype] = [t for t in self._event_type_timestamps[etype] if now - t < 60]
                if len(self._event_type_timestamps[etype]) >= 30:
                    self._event_type_timestamps[etype].append(now)
                    log.debug("Rate-limit: dropping %s (count=%d in 60s)",
                              etype, len(self._event_type_timestamps[etype]))
                    return
                self._event_type_timestamps[etype].append(now)

            # Map to a proper severity based on event type
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
                    log.info("-> ALERT: [%s] %s", event.severity.upper(), event.event_type)
                    # Trigger SOAR action if enabled
                    await self._maybeTriggerSoar(event)
        except Exception as e:
            log.error("Send failed: %s", e)

    def _get_dedupe_key(self, event: SecurityEvent) -> str:
        """Return a stable dedupe key for an event."""
        sig = str(event.extra.get("signature", ""))
        base = f"{event.event_type}:{event.dest_ip or ''}:{sig}:{event.hostname}"
        return hashlib.sha256(base.encode()).hexdigest()

    async def _maybeTriggerSoar(self, event: SecurityEvent):
        """Trigger a minimal SOAR action if configured."""
        if not self._soar_enabled or not self._soar_webhook:
            return
        try:
            payload = {
                "incident": {
                    "type": event.event_type,
                    "severity": event.severity,
                    "title": f"{event.event_type} detected on {event.hostname}",
                    "message": event.message,
                    "timestamp": event.timestamp,
                    "dest_ip": event.dest_ip,
                    "source": event.source,
                }
            }
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(self._soar_webhook, json=payload)
                log.debug("SOAR webhook response: %s", getattr(resp, 'status_code', None))
        except Exception as e:
            log.debug("SOAR action failed: %s", e)

    def _map_severity(self, event_type: str, details: Optional[Dict[str, Any]] = None, current: Optional[str] = None) -> str:
        """Map event type to a severity using a small policy table."""
        mapping = {
            # Threshold/external events
            "external_connection_threshold": "high",
            # Common malware signals
            "malicious_process": "critical",
            "malicious_script": "critical",
            "suspicious_file": "high",
            "new_download": "high",
            "startup_item": "high",
            # Heartbeat/info can stay low/informational
            "agent_heartbeat": "info",
            # Authentication/security events
            "failed_login": "medium",
            "user_created": "high",
            "account_lockout": "high",
            # Default fallback
            "default": (current or "medium"),
        }
        if event_type in mapping:
            return mapping[event_type]
        # Fallback: preserve current if provided
        return current or "medium"
            
    async def _monitoring_loop(self):
        """Smart monitoring - not too frequent"""
        cycle = 0
        while self._running:
            cycle += 1
            log.info("=== Monitoring Cycle %d ===", cycle)
            
            # Ensure token is valid before sending events
            await self._ensure_valid_token()
            
            try:
                # Run checks - but throttle each
                await self._check_network()
                await self._check_processes()
                await self._check_files()
                await self._check_downloads()
                await self._check_usb()
                await self._check_powershell()
                await self._check_registry()
                await self._check_services()
                await self._check_system_events()
                await self._heartbeat()
                
                # Periodic cleanup of stale rate limiter entries (every ~10 cycles = 5 min)
                self._cleanup_counter += 1
                if self._cleanup_counter >= 10:
                    self._cleanup_counter = 0
                    self._cleanup_stale_entries()
                
            except Exception as e:
                log.error("Monitor error: %s", e)
                
            await asyncio.sleep(30)  # Check every 30s, not 5s
            
    async def _check_network(self):
        """Check for suspicious network connections"""
        try:
            import subprocess
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')[4:]  # Skip header
            
            suspicious = 0
            for line in lines:
                if 'ESTABLISHED' in line and not any(safe in line for safe in ['192.168.', '10.', '127.']):
                    parts = line.split()
                    if len(parts) >= 4:
                        remote = parts[3] if ':' in parts[3] else parts[4] if len(parts) > 4 else ''
                        if remote and ':' in remote:
                            ip = remote.rsplit(':', 1)[0]
                            if ip and not ip.startswith(('192.168.', '10.', '127.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '224.', '239.')):
                                suspicious += 1
            
            if suspicious > 5:
                await self._send_event(SecurityEvent(
                    event_type="suspicious_network",
                    severity="medium",
                    message=f"Found {suspicious} external connections",
                    source_ip="127.0.0.1",
                    details={"count": suspicious}
                ))
        except Exception as e:
            log.debug(f"Network check error: {e}")
            
    def _is_safe_domain(self, ip: str) -> bool:
        """Check if IP resolves to a safe domain (via PTR record)"""
        try:
            # Check cache first
            now = time.time()
            if ip in self._ptr_cache:
                cached_time, is_safe = self._ptr_cache[ip]
                if now - cached_time < self._PTR_CACHE_VALIDITY:
                    return is_safe
            
            # Perform PTR lookup
            hostname = socket.gethostbyaddr(ip)[0].lower()
            
            # Check if hostname ends with any safe domain suffix
            is_safe = any(hostname.endswith(suffix) for suffix in self.SAFE_DOMAIN_SUFFIXES)
            
            # Cache the result
            self._ptr_cache[ip] = (now, is_safe)
            
            return is_safe
        except (socket.herror, socket.gaierror):
            # If PTR lookup fails, assume not safe (could be internal or no PTR)
            return False
        except Exception:
            return False
            
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
            return False
        except Exception:
            return False
            
    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
            
    # =================================================================
    # SMART PROCESSES - Only malicious/memory-only
    # =================================================================
    async def _check_processes(self):
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL
            )
            if not output.strip():
                return
                
            processes = json.loads(output.strip())
            if isinstance(processes, dict):
                processes = [processes]
                
            for proc in processes:
                pid = proc.get("Id", 0)
                name = proc.get("ProcessName", "")
                
                if not pid or not name:
                    continue
                
                # Skip safe processes
                if name.lower() in [p.lower() for p in self.SAFE_PROCESSES]:
                    continue
                
                key = f"process:{name}"
                if key in self._seen_processes:
                    continue
                self._seen_processes.add(key)
                
                # Check for CRITICAL patterns (always alert)
                cmdline = self._get_process_cmdline(pid)
                if cmdline:
                    for pattern in self.CRITICAL_PATTERNS:
                        if re.search(pattern, cmdline, re.I):
                            event = SecurityEvent(
                                event_type="malicious_process",
                                severity="critical",
                                source="process_monitor",
                                message=f"Malicious process: {name}",
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                hostname=self.hostname,
                                user=self._get_current_user(),
                                details={
                                    "pid": pid,
                                    "process_name": name,
                                    "command_line": cmdline[:500],
                                    "matched": pattern
                                }
                            )
                            await self._send_event(event)
                            return  # Found one, done for this cycle
                            
        except Exception as e:
            log.debug("Process check: %s", e)
            
    def _get_process_cmdline(self, pid: int) -> str:
        try:
            output = subprocess.check_output(
                f'wmic process where ProcessId={pid} get CommandLine',
                shell=True, text=True, stderr=subprocess.DEVNULL
            )
            lines = output.strip().split("\n")
            if len(lines) > 1:
                return lines[1].strip()
        except Exception:
            pass
        return ""

    def _get_current_user(self) -> str:
        try:
            return os.environ.get("USERNAME", "Unknown")
        except Exception:
            return "Unknown"

    # =================================================================
    # FILES - Only new suspicious files (not repeat)
    # =================================================================
    async def _check_files(self):
        user = self._get_current_user()
        watch_paths = [
            f"C:\\Users\\{user}\\Downloads",
            f"C:\\Users\\{user}\\Desktop", 
        ]
        
        for watch_path in watch_paths:
            if not os.path.exists(watch_path):
                continue
            try:
                for item in Path(watch_path).iterdir():
                    if not item.is_file():
                        continue
                    
                    path_str = str(item)
                    if path_str in self._seen_files:
                        continue
                    self._seen_files.add(path_str)
                    
                    ext = item.suffix.lower()
                    if ext in self.DANGEROUS_EXTENSIONS:
                        sha256 = self._calculate_hash(item)
                        
                        event = SecurityEvent(
                            event_type="suspicious_file",
                            severity="high",
                            source="file_monitor",
                            message=f"Suspicious file: {item.name}",
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            details={
                                "file_name": item.name,
                                "file_path": path_str,
                                "file_size": item.stat().st_size,
                                "sha256": sha256
                            }
                        )
                        await self._send_event(event)
                        
            except Exception:
                continue
                
    def _calculate_hash(self, path: Path) -> str:
        try:
            sha256 = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return "error"

    # =================================================================
    # DOWNLOADS - Only new downloads
    # =================================================================
    async def _check_downloads(self):
        user = self._get_current_user()
        downloads = Path(f"C:\\Users\\{user}\\Downloads")
        
        if not downloads.exists():
            return
            
        try:
            files = list(downloads.glob("*"))
            recent = [f for f in files if f.is_file() and 
                     time.time() - f.stat().st_mtime < 60]  # Last minute
            
            for f in recent:
                path_str = str(f)
                if path_str in self._seen_downloads:
                    continue
                self._seen_downloads.add(path_str)
                
                ext = f.suffix.lower()
                
                # Alert on dangerous types
                if ext in self.DANGEROUS_EXTENSIONS:
                    event = SecurityEvent(
                        event_type="new_download",
                        severity="high",
                        source="download_monitor",
                        message=f"Downloaded: {f.name}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={
                            "file_name": f.name,
                            "file_size": f.stat().st_size,
                            "sha256": self._calculate_hash(f)
                        }
                    )
                    await self._send_event(event)
                    
        except Exception as e:
            log.debug("Downloads: %s", e)
            
    # =================================================================
    # USB - Only new devices
    # =================================================================
    async def _check_usb(self):
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-PnpDevice -Class Usb -Status OK | Select-Object FriendlyName,ID | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL
            )
            if not output.strip():
                return
                
            devices = json.loads(output.strip())
            if isinstance(devices, dict):
                devices = [devices]
                
            for dev in devices:
                name = dev.get("FriendlyName", "")
                dev_id = dev.get("ID", "")
                
                if name and dev_id and dev_id not in self._seen_usb:
                    self._seen_usb.add(dev_id)
                    event = SecurityEvent(
                        event_type="usb_connected",
                        severity="low",
                        source="usb_monitor",
                        message=f"USB: {name}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={"device_name": name, "device_id": dev_id}
                    )
                    await self._send_event(event)
                    
        except Exception as e:
            log.debug("USB: %s", e)
            
    # =================================================================
    # POWERSHELL - Malicious scripts only
    # =================================================================
    async def _check_powershell(self):
        try:
            user = self._get_current_user()
            temp = Path(f"C:\\Users\\{user}\\AppData\\Local\\Temp")
            
            if temp.exists():
                for f in temp.glob("*.ps1"):
                    if f.stat().st_size > 1024*100:  # Skip >100KB
                        continue
                    path_str = str(f)
                    if path_str in self._seen_files:
                        continue
                    self._seen_files.add(path_str)
                    
                    try:
                        content = f.read_text()[:1000].lower()
                    except Exception:
                        continue
                    
                    # Check for CRITICAL patterns
                    for pattern in self.CRITICAL_PATTERNS:
                        if re.search(pattern, content, re.I):
                            event = SecurityEvent(
                                event_type="malicious_script",
                                severity="critical",
                                source="powershell_monitor",
                                message=f"Malicious PS script: {f.name}",
                                timestamp=datetime.now(timezone.utc).isoformat(),
                                hostname=self.hostname,
                                details={
                                    "script_name": f.name,
                                    "matched": pattern
                                }
                            )
                            await self._send_event(event)
                            break
                            
        except Exception as e:
            log.debug("PowerShell: %s", e)
            
    # =================================================================
    # REGISTRY - New startup items only
    # =================================================================
    async def _check_registry(self):
        try:
            reg_keys = [
                "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ]
            
            for key in reg_keys:
                try:
                    output = subprocess.check_output(
                        f'reg query "{key}"',
                        shell=True, text=True, stderr=subprocess.DEVNULL
                    )
                    
                    for line in output.split("\n"):
                        if "REG_" not in line:
                            continue
                        line = line.strip()
                        if not line:
                            continue
                            
                        key_str = f"{key}:{line}"
                        if key_str in self._seen_ports:  # Reuse set for startup items
                            continue
                        self._seen_ports.add(key_str)
                        
                        event = SecurityEvent(
                            event_type="startup_item",
                            severity="high",
                            source="registry_monitor",
                            message=f"New startup: {line[:80]}",
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            hostname=self.hostname,
                            details={"registry": key, "value": line}
                        )
                        await self._send_event(event)
                        
                except Exception:
                    continue
                    
        except Exception as e:
            log.debug("Registry: %s", e)
            
    # =================================================================
    # SERVICES - New services only
    # =================================================================
    async def _check_services(self):
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-Service | Select-Object Name,Status | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL
            )
            if not output.strip():
                return
                
            services = json.loads(output.strip())
            if isinstance(services, dict):
                services = [services]
                
            for svc in services:
                name = svc.get("Name", "")
                if not name or name in self._seen_services:
                    continue
                self._seen_services.add(name)
                
        except Exception as e:
            log.debug("Services: %s", e)
            
    # =================================================================
    # SYSTEM EVENTS - Important security events only
    # =================================================================
    async def _check_system_events(self):
        try:
            output = subprocess.check_output(
                'powershell -Command "Get-WinEvent -LogName Security -MaxEvents 3 -ErrorAction SilentlyContinue | Select-Object Id,Message | ConvertTo-Json"',
                shell=True, text=True, stderr=subprocess.DEVNULL, timeout=5
            )
            
            if not output.strip():
                return
                
            events = json.loads(output.strip())
            if isinstance(events, dict):
                events = [events]
                
            important = {4625: "failed_login", 4720: "user_created", 4740: "account_lockout"}
            
            for evt in events:
                event_id = evt.get("Id", 0)
                if event_id in important:
                    event_type = important[event_id]
                    key = f"event:{event_id}"
                    if key in self._seen_ports:  # Reuse set
                        continue
                    self._seen_ports.add(key)
                    
                    event = SecurityEvent(
                        event_type=event_type,
                        severity="high" if event_id != 4625 else "medium",
                        source="windows_eventlog",
                        message=f"Security Event {event_id}",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        hostname=self.hostname,
                        details={"event_id": event_id}
                    )
                    await self._send_event(event)
                    
        except Exception as e:
            log.debug("System events: %s", e)
            
    # =================================================================
    # THRESHOLD - Smart alerting
    # =================================================================
    async def _check_threshold(self, identifier: str, event_type: str, threshold: int = 3, window: int = 60):
        """Only alert if X events from same source in Y seconds"""
        now = time.time()
        
        # Add this event
        self._event_counts[identifier].append(now)
        
        # Clean old entries
        self._event_counts[identifier] = [
            t for t in self._event_counts[identifier] 
            if now - t < window
        ]
        
        # Check threshold
        count = len(self._event_counts[identifier])
        if count >= threshold:
            # Alert!
            event = SecurityEvent(
                event_type="external_connection",
                severity="high",
                source="network_monitor",
                message=f"Suspicious: {count} connections from {identifier}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=self.hostname,
                dest_ip=identifier,
                details={
                    "connection_count": count,
                    "window_seconds": window,
                    "note": "thresholdalert"
                }
            )
            await self._send_event(event)
            # Clear after alert to prevent spam
            self._event_counts[identifier] = []
            
    def _cleanup_stale_entries(self):
        """Periodic cleanup of stale rate limiter timestamps to prevent memory leak."""
        now = time.time()
        stale_cutoff = 120  # 2 minutes
        cleaned = 0
        for etype in list(self._event_type_timestamps.keys()):
            original_len = len(self._event_type_timestamps[etype])
            self._event_type_timestamps[etype] = [
                t for t in self._event_type_timestamps[etype] if now - t < stale_cutoff
            ]
            cleaned += original_len - len(self._event_type_timestamps[etype])
            if not self._event_type_timestamps[etype]:
                del self._event_type_timestamps[etype]
        # Also clean dedup cache entries older than 120s
        dedup_cleaned = 0
        for key in list(self._dedup_cache.keys()):
            if now - self._dedup_cache[key] > stale_cutoff:
                del self._dedup_cache[key]
                dedup_cleaned += 1
        if cleaned or dedup_cleaned:
            log.debug("Cleanup: %d rate-limit + %d dedup entries removed", cleaned, dedup_cleaned)

    # =================================================================
    # HEARTBEAT - Throttled (once per 5 min)
    # =================================================================
    async def _heartbeat(self):
        now = time.time()
        if now - self._last_heartbeat < 300:  # 5 min
            return
            
        self._last_heartbeat = now
        
        try:
            event = SecurityEvent(
                event_type="agent_heartbeat",
                severity="info",
                source="agent_heartbeat",
                message=f"Agent running on {self.hostname}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=self.hostname,
                details={
                    "uptime_seconds": int(now - self._start_time.timestamp()),
                    "os": platform.system(),
                    "mode": "smart_filter"
                }
            )
            await self._send_event(event)
        except Exception as e:
            log.debug("Heartbeat: %s", e)


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="CyberNova Host Agent (SMART)")
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
