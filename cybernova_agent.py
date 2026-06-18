"""
CyberNova endpoint agent. Sends logs, alerts, and heartbeats to the backend.
"""
import os
import sys
import json
import time
import uuid
import socket
import platform
import logging
import threading
import collections
import httpx
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("cybernova_agent")


class CyberNovaAgent:
    def __init__(self, config_path: str = None):
        self.config_path = config_path or self._default_config_path()
        self.config = self._load_config()
        
        self.device_id: Optional[str] = None
        self.device_token: Optional[str] = None
        self.tenant_id: Optional[str] = None
        self.is_registered = False
        
        self._client = httpx.Client(
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"CyberNova-Agent/{self._get_agent_version()}"
            },
            timeout=30.0,
        )
        
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._running = False
    
    def _default_config_path(self) -> str:
        base = os.environ.get("PROGRAMDATA") or os.environ.get("PROGRAMFILES")
        if base:
            return os.path.join(base, "CyberNova", "agent_config.json")
        return "cybernova_agent_config.json"
    
    def _load_config(self) -> dict:
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                return json.load(f)
        return {}
    
    def _save_config(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump(self.config, f, indent=2)
    
    def _get_agent_version(self) -> str:
        return "1.0.0"
    
    def _get_system_info(self) -> dict:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            
            os_type = platform.system()
            os_version = platform.release()
            
            if os_type == "Windows":
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    os_version = winreg.QueryValueEx(key, "ProductName")[0]
                    winreg.CloseKey(key)
                except Exception:
                    pass
            
            return {
                "hostname": hostname,
                "ip": ip,
                "os": os_type,
                "os_version": os_version,
                "agent_version": self._get_agent_version(),
            }
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {"hostname": "unknown", "ip": "0.0.0.0", "os": "unknown", "os_version": ""}
    
    def _get_api_url(self) -> str:
        base_url = self.config.get("api_url", "http://localhost:8000")
        return base_url.rstrip("/")
    
    # registration
    
    def register(self, token: str) -> bool:
        """Register this device with the backend.
        
        Detects mode automatically:
        - If token looks like an org key (starts with 'ORG-'), use org_key mode
        - Otherwise, treat as tenant_id (individual mode)
        """
        system_info = self._get_system_info()
        
        # Auto-detect mode: org keys always start with 'ORG-', tenant IDs are UUIDs
        is_org_key = token.startswith("ORG-")
        
        payload = {
            "device_name": system_info["hostname"],
            "system_info": system_info,
        }
        if is_org_key:
            payload["org_key"] = token
        else:
            payload["tenant_id"] = token
        
        try:
            url = f"{self._get_api_url()}/api/v1/devices/register"
            response = self._client.post(url, json=payload)
            response.raise_for_status()
            
            data = response.json()
            self.device_id = data["device_id"]
            self.device_token = data["device_token"]
            self.tenant_id = data["tenant_id"]
            
            self.config.update({
                "device_id": self.device_id,
                "device_token": self.device_token,
                "tenant_id": self.tenant_id,
                "org_key": token if is_org_key else None,
            })
            self._save_config()
            
            self.is_registered = True
            logger.info(f"Device registered: {self.device_id}")
            return True
            
        except httpx.HTTPError as e:
            logger.error(f"Registration failed: {e}")
            return False
    
    def auto_register(self) -> bool:
        """Try auto-registration using stored config."""
        if self.config.get("device_token"):
            self.device_id = self.config.get("device_id")
            self.device_token = self.config.get("device_token")
            self.tenant_id = self.config.get("tenant_id")
            
            if self._test_connection():
                self.is_registered = True
                logger.info(f"Device auto-registered: {self.device_id}")
                return True
        
        return False
    
    def _test_connection(self) -> bool:
        try:
            url = f"{self._get_api_url()}/api/v1/devices/me"
            response = self._client.get(
                url, 
                headers=self._auth_headers(),
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.device_token}"}
    
    # heartbeat
    
    def start_heartbeat(self, interval: int = 30):
        """Start sending heartbeats."""
        self._running = True
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(interval,),
            daemon=True
        )
        self._heartbeat_thread.start()
        logger.info(f"Heartbeat started (interval: {interval}s)")
    
    def stop_heartbeat(self):
        """Stop heartbeats."""
        self._running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)
    
    def _heartbeat_loop(self, interval: int):
        while self._running:
            try:
                self.send_heartbeat()
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
            time.sleep(interval)
    
    def send_heartbeat(self) -> bool:
        """Send heartbeat to backend."""
        if not self.is_registered:
            return False
        
        payload = {
            "device_id": self.device_id,
            "status": "online"
        }
        
        try:
            url = f"{self._get_api_url()}/api/v1/devices/heartbeat"
            response = self._client.post(
                url,
                json=payload,
                headers=self._auth_headers(),
            )
            response.raise_for_status()
            return True
        except httpx.HTTPError as e:
            logger.error(f"Heartbeat failed: {e}")
            return False
    
    # logs
    
    def send_logs(self, logs: List[Dict[str, Any]]) -> bool:
        """Send logs to backend."""
        if not self.is_registered:
            logger.warning("Device not registered, cannot send logs")
            return False
        
        payload = {
            "device_id": self.device_id,
            "logs": logs
        }
        
        try:
            url = f"{self._get_api_url()}/api/v1/devices/logs"
            response = self._client.post(
                url,
                json=payload,
                headers=self._auth_headers(),
            )
            response.raise_for_status()
            logger.info(f"Sent {len(logs)} logs")
            return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to send logs: {e}")
            return False
    
    # alerts
    
    def send_alerts(self, alerts: List[Dict[str, Any]]) -> bool:
        """Send alerts to backend."""
        if not self.is_registered:
            logger.warning("Device not registered, cannot send alerts")
            return False
        
        payload = {
            "device_id": self.device_id,
            "alerts": alerts
        }
        
        try:
            url = f"{self._get_api_url()}/api/v1/devices/alerts"
            response = self._client.post(
                url,
                json=payload,
                headers=self._auth_headers(),
            )
            response.raise_for_status()
            logger.info(f"Sent {len(alerts)} alerts")
            return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to send alerts: {e}")
            return False
    
    # event collection
    
    def collect_and_send(self, log_sources: List[str] = None):
        """Collect and send logs from various sources."""
        all_logs = []
        
        log_sources = log_sources or ["security", "system", "application"]
        
        if "security" in log_sources:
            all_logs.extend(self._collect_security_logs())
        
        if "system" in log_sources:
            all_logs.extend(self._collect_system_logs())
        
        if all_logs:
            self.send_logs(all_logs)
    
    def _collect_security_logs(self) -> List[dict]:
        logs = []
        
        if platform.system() == "Windows":
            logs.extend(self._collect_windows_security_events())
        
        return logs
    
    def _collect_system_logs(self) -> List[dict]:
        logs = []
        
        if platform.system() == "Windows":
            logs.extend(self._collect_windows_system_events())
        else:
            logs.extend(self._collect_linux_system_logs())
        
        return logs
    
    def _collect_windows_security_events(self) -> List[dict]:
        try:
            import win32evtlog
            import win32evtlogutil
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = []
            batch = win32evtlog.ReadEventLog(hand, flags, 0)
            for e in batch[:50]:
                try:
                    msg = win32evtlogutil.SafeFormatMessage(e, "Security")
                except Exception:
                    msg = str(e.StringInserts) if e.StringInserts else "No message"
                events.append({
                    "level": "info",
                    "source": "Windows_Security_Event",
                    "event_id": e.EventID,
                    "message": msg[:500],
                    "timestamp": e.TimeGenerated.Format() if hasattr(e.TimeGenerated, 'Format') else str(e.TimeGenerated),
                })
            win32evtlog.CloseEventLog(hand)
            return events
        except ImportError:
            # pywin32 not installed — fallback to wevtutil CLI
            return self._collect_windows_events_cli("Security")
        except Exception:
            return []
    
    def _collect_windows_system_events(self) -> List[dict]:
        try:
            import win32evtlog
            import win32evtlogutil
            hand = win32evtlog.OpenEventLog(None, "System")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = []
            batch = win32evtlog.ReadEventLog(hand, flags, 0)
            for e in batch[:20]:
                try:
                    msg = win32evtlogutil.SafeFormatMessage(e, "System")
                except Exception:
                    msg = str(e.StringInserts) if e.StringInserts else "No message"
                events.append({
                    "level": "info",
                    "source": "Windows_System_Event",
                    "event_id": e.EventID,
                    "message": msg[:500],
                    "timestamp": e.TimeGenerated.Format() if hasattr(e.TimeGenerated, 'Format') else str(e.TimeGenerated),
                })
            win32evtlog.CloseEventLog(hand)
            return events
        except ImportError:
            return self._collect_windows_events_cli("System")
        except Exception:
            return []
    
    def _collect_windows_events_cli(self, log_name: str) -> List[dict]:
        """Fallback: collect Windows events via wevtutil CLI when pywin32 is unavailable."""
        import subprocess
        try:
            result = subprocess.run(
                ["wevtutil", "qe", log_name, "/c:20", "/rd:true", "/f:text"],
                capture_output=True, text=True, timeout=15, creationflags=0x08000000 if os.name == 'nt' else 0
            )
            if result.returncode != 0:
                return []
            events = []
            now = datetime.now(timezone.utc).isoformat()
            for block in result.stdout.strip().split("\n\n"):
                block = block.strip()
                if not block:
                    continue
                lines = block.split("\n")
                event_id = 0
                message = block[:500]
                for line in lines:
                    if line.startswith("EventId:"):
                        try:
                            event_id = int(line.split(":", 1)[1].strip())
                        except (ValueError, IndexError):
                            pass
                events.append({
                    "level": "info",
                    "source": f"Windows_{log_name}_Event",
                    "event_id": event_id,
                    "message": message,
                    "timestamp": now,
                })
            return events
        except Exception:
            return []
    
    def _collect_linux_system_logs(self) -> List[dict]:
        logs = []
        
        log_files = [
            ("/var/log/auth.log", "auth.log"),
            ("/var/log/syslog", "syslog"),
            ("/var/log/secure", "secure"),
        ]
        
        for log_path, source_name in log_files:
            if os.path.exists(log_path):
                try:
                    # Read only the last 20 lines using deque (memory-efficient)
                    with open(log_path, "r", errors="replace") as f:
                        tail_lines = collections.deque(f, maxlen=20)
                    for line in tail_lines:
                        stripped = line.strip()
                        if stripped:
                            logs.append({
                                "level": "info",
                                "source": source_name,
                                "message": stripped,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            })
                except Exception:
                    pass
        
        return logs
    
    # main loop
    
    def run(self, token: str = None):
        """Run the agent.
        
        Args:
            token: Either an org_key (for org users) or a tenant_id (for individual users).
                   The agent detects which by trying org_key registration first, then
                   falling back to individual mode.
        """
        token = token or os.environ.get("CYBERNOVA_ORG_KEY") or os.environ.get("CYBERNOVA_TENANT_ID")
        
        if not token:
            logger.error("No token provided. Pass org_key/tenant_id as argument or set CYBERNOVA_ORG_KEY / CYBERNOVA_TENANT_ID")
            sys.exit(1)
        
        logger.info("CyberNova Agent starting...")
        logger.info("  Mode: %s", "Organization" if len(token) > 20 else "Individual")
        
        if not self.auto_register():
            logger.info("Registering with backend...")
            if not self.register(token):
                logger.error("Registration failed — check that the backend is running and the token is valid")
                sys.exit(1)
        
        self.start_heartbeat(interval=30)
        
        logger.info("CyberNova Agent running (device=%s, tenant=%s)", self.device_id, self.tenant_id)
        
        try:
            while True:
                self.collect_and_send()
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.stop_heartbeat()
            logger.info("CyberNova Agent stopped")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="CyberNova Endpoint Agent",
        epilog="""
Examples:
  python cybernova_agent.py <org_key>          # Organization mode (boss/staff)
  python cybernova_agent.py <tenant_id>        # Individual mode
  python cybernova_agent.py --api-url http://server:8000 <org_key>
        """
    )
    parser.add_argument("token", nargs="?", help="Organization key or tenant ID")
    parser.add_argument("--api-url", default="http://localhost:8000", help="Backend API URL (default: http://localhost:8000)")
    
    args = parser.parse_args()
    
    agent = CyberNovaAgent()
    
    if args.api_url:
        agent.config["api_url"] = args.api_url
        agent._save_config()
    
    agent.run(args.token)


if __name__ == "__main__":
    main()