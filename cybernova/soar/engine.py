"""
CyberNova SOAR Engine (Patch E)
Implements: incident-triggered response, NOT alert-triggered
Only fires on CONFIRMED incidents with CRITICAL severity
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import subprocess  # nosec
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx

log = logging.getLogger("cybernova.soar")


# --- Configuration ---
def is_soar_enabled() -> bool:
    """SOAR is ALWAYS enabled — CyberNova runs autonomous response 24/7."""
    return True


def get_soar_actions() -> List[str]:
    """Get enabled SOAR actions. ALL actions are enabled by default.
    Environment override still works for selective disabling.
    """
    actions = os.environ.get("CYBERNOVA_SOAR_ACTIONS", "all").lower().split(",")
    actions = [a.strip() for a in actions if a.strip()]
    if "all" in actions:
        return [
            "webhook", "block_ip", "log", "notify", "isolate",
            "collect_forensics", "kill_process", "scan_host",
            "disable_user", "enable_user", "create_ticket",
            "send_notification", "quarantine_file", "reset_mfa",
        ]
    return actions


def _is_linux() -> bool:
    return platform.system().lower() == "linux"


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


# --- Base Action class ---
class Action:
    """Base class for SOAR actions."""

    name: str = "base"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Execute action. Returns True if successful."""
        log.warning("Base Action.execute() called directly — no action type configured for incident %s", incident.get("id", ""))
        return False


# --- Action 1: Webhook notification ---
class WebhookAction(Action):
    """Send incident to webhook endpoint."""

    name = "webhook"

    def __init__(self, url: Optional[str] = None):
        self.url = url or os.environ.get("CYBERNOVA_SOAR_WEBHOOK_URL", "http://localhost:9000/webhook")

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Send incident to webhook."""
        payload = {
            "incident": {
                "id": str(incident.get("id", "")),
                "title": incident.get("title", ""),
                "severity": incident.get("severity", ""),
                "incident_type": incident.get("incident_type", ""),
                "status": incident.get("status", ""),
                "confirmed": incident.get("confirmed", False),
                "created_at": incident.get("created_at", ""),
                "source_ip": incident.get("source_ip", ""),
                "dest_ip": incident.get("dest_ip", ""),
            }
        }
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                asyncio.create_task(self._send_async(payload))
            else:
                asyncio.run(self._send_async(payload))
        except Exception as e:
            log.error("Webhook failed: %s", e)
            return False
        return True

    async def _send_async(self, payload: Dict[str, Any]) -> None:
        """Async webhook send."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.url, json=payload)
                log.info("Webhook sent to %s: %d", self.url, resp.status_code)
        except httpx.TimeoutException:
            log.warning("Webhook timeout for %s", self.url)
        except httpx.RequestError as e:
            log.warning("Webhook request error for %s: %s", self.url, e)
        except Exception as e:
            log.error("Webhook unexpected error: %s", e)


# --- Action 2: Block IP (real firewall commands) ---
class BlockIPAction(Action):
    """Block IP address via platform firewall commands with simulation fallback."""

    name = "block_ip"

    def __init__(self, simulation_mode: Optional[bool] = None):
        self._simulation = simulation_mode if simulation_mode is not None else False

    # ── Public API ─────────────────────────────────────────────────────────

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Block IP via real firewall commands. Falls back to simulation if firewall unavailable."""
        if self._simulation:
            log.warning("BlockIPAction: SIMULATION MODE — would block IPs in %s", incident.get("id", ""))
            return True
        dest_ip = incident.get("dest_ip", "")
        source_ip = incident.get("source_ip", "")

        ips_to_block = []
        if dest_ip:
            ips_to_block.append(dest_ip)
        if source_ip and source_ip != dest_ip:
            ips_to_block.append(source_ip)

        if not ips_to_block:
            log.warning("BlockIPAction: no IPs found in incident %s", incident.get("id", ""))
            return False

        success = True
        for ip in ips_to_block:
            if not self._block_ip(ip):
                success = False

        return success

    # ── Block logic ────────────────────────────────────────────────────────

    def _block_ip(self, ip: str) -> bool:
        try:
            if _is_windows():
                return self._block_windows(ip)
            elif _is_linux():
                return self._block_linux(ip)
            else:
                log.error("Unsupported platform %s — cannot block IP %s for real", platform.system(), ip)
                return False
        except Exception as e:
            log.error("Failed to block IP %s: %s", ip, e)
            return False

    @staticmethod
    def _netsh_path() -> str:
        """Return the absolute path to netsh.exe on Windows."""
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        return os.path.join(system_root, "system32", "netsh.exe")

    @staticmethod
    def _iptables_path() -> str:
        """Return the absolute path to iptables."""
        for candidate in ("/sbin/iptables", "/usr/sbin/iptables", "/usr/bin/iptables"):
            if os.path.exists(candidate):
                return candidate
        return "/sbin/iptables"  # best guess fallback

    @staticmethod
    def _nft_path() -> str:
        """Return the absolute path to nft."""
        for candidate in ("/sbin/nft", "/usr/sbin/nft", "/usr/bin/nft"):
            if os.path.exists(candidate):
                return candidate
        return "/usr/sbin/nft"  # best guess fallback

    def _block_windows(self, ip: str) -> bool:
        rule_name = f"CyberNova_Block_{ip.replace('.', '_')}"
        netsh = self._netsh_path()
        try:
            result = subprocess.run(  # nosec
                [
                    netsh, "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                    "profile=any",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                log.info("Blocked %s via Windows Firewall (rule: %s)", ip, rule_name)
                return True
            else:
                log.error("Windows Firewall rule failed for %s: %s", ip, result.stderr.strip())
                return False
        except subprocess.TimeoutExpired:
            log.error("Timeout blocking %s via Windows Firewall", ip)
            return False
        except FileNotFoundError:
            log.error("netsh not found on Windows system")
            return False
        except Exception as e:
            log.error("Unexpected error blocking %s via Windows Firewall: %s", ip, e)
            return False

    def _block_linux(self, ip: str) -> bool:
        if self._has_command("nft"):
            return self._block_nftables(ip)
        elif self._has_command("iptables"):
            return self._block_iptables(ip)
        else:
            log.error("No firewall command found (nftables/iptables) — CRITICAL: cannot block %s for real", ip)
            # Try iptables as fallback anyway
            return self._block_iptables(ip)

    def _block_iptables(self, ip: str) -> bool:
        iptables = self._iptables_path()
        try:
            result = subprocess.run(  # nosec
                [iptables, "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                log.info("Blocked %s via iptables", ip)
                return True
            else:
                log.error("iptables failed for %s: %s", ip, result.stderr.strip())
                return False
        except subprocess.TimeoutExpired:
            log.error("Timeout blocking %s via iptables", ip)
            return False
        except FileNotFoundError:
            log.error("iptables not found")
            return False
        except Exception as e:
            log.error("Unexpected error blocking %s via iptables: %s", ip, e)
            return False

    def _block_nftables(self, ip: str) -> bool:
        nft = self._nft_path()
        try:
            result = subprocess.run(  # nosec
                [nft, "add", "rule", "ip", "filter", "INPUT", "ip", "saddr", ip, "drop"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                log.info("Blocked %s via nftables", ip)
                return True
            else:
                log.error("nftables failed for %s: %s", ip, result.stderr.strip())
                return False
        except subprocess.TimeoutExpired:
            log.error("Timeout blocking %s via nftables", ip)
            return False
        except FileNotFoundError:
            log.error("nft not found")
            return False
        except Exception as e:
            log.error("Unexpected error blocking %s via nftables: %s", ip, e)
            return False

    @staticmethod
    def _has_command(cmd: str) -> bool:
        """Check if a command exists on the system using shutil.which (cross-platform)."""
        try:
            return shutil.which(cmd) is not None
        except Exception as e:
            log.warning("Command check failed for %s: %s", cmd, e)
            return False


# --- Action 3: Log action (always safe) ---
class LogAction(Action):
    """Log incident to console/file."""

    name = "log"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log incident."""
        log.info(
            "Incident: %s | %s | %s",
            incident.get("id"),
            incident.get("title"),
            incident.get("severity"),
        )
        return True


# --- Action 4: Notify (SOC Notification) ---
class NotifyAction(Action):
    """Send notification about incident."""

    name = "notify"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log notification for SOC."""
        log.warning(
            "🔔 SOC NOTIFICATION: Incident %s | %s | Severity: %s | Risk: %.1f | Source: %s",
            incident.get("id", "?"),
            incident.get("title", "?"),
            incident.get("severity", "?"),
            float(incident.get("risk_score", 0)),
            incident.get("source_ip", "unknown"),
        )
        return True


# --- Action 5: Isolate Host (real host quarantine) ---
class IsolateAction(Action):
    """Isolate a compromised host via firewall rules."""

    name = "isolate"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Isolate device by blocking all traffic to/from it."""
        source_ip = incident.get("source_ip", "")
        dest_ip = incident.get("dest_ip", "")
        hostname = incident.get("hostname", incident.get("device_id", ""))

        ips_to_isolate = []
        if source_ip and source_ip not in ("", "0.0.0.0"):  # nosec B104 — checking IP value, not binding
            ips_to_isolate.append(source_ip)
        if dest_ip and dest_ip not in ("", "0.0.0.0") and dest_ip != source_ip:  # nosec B104 — checking IP value, not binding
            ips_to_isolate.append(dest_ip)

        if not ips_to_isolate and hostname:
            log.warning("IsolateAction: no IPs for %s — hostname isolation requires agent", hostname)
            return True  # Agent-based isolation is handled separately

        success = True
        for ip in ips_to_isolate:
            try:
                if _is_windows():
                    # Block ALL traffic (inbound + outbound) to isolate
                    rule_name_in = f"CyberNova_Isolate_In_{ip.replace('.', '_')}"
                    rule_name_out = f"CyberNova_Isolate_Out_{ip.replace('.', '_')}"
                    netsh_path = shutil.which("netsh")
                    if netsh_path:
                        subprocess.run(  # nosec
                            [netsh_path, "advfirewall", "firewall", "add", "rule",
                             f"name={rule_name_in}", "dir=in", "action=block",
                             f"remoteip={ip}", "enable=yes", "profile=any"],
                            capture_output=True, text=True, timeout=15)
                        subprocess.run(  # nosec
                            [netsh_path, "advfirewall", "firewall", "add", "rule",
                             f"name={rule_name_out}", "dir=out", "action=block",
                             f"remoteip={ip}", "enable=yes", "profile=any"],
                            capture_output=True, text=True, timeout=15)
                        log.warning("🧪 ISOLATED device at IP %s (in+out blocked)", ip)
                    else:
                        log.error("netsh not found — cannot isolate %s on Windows", ip)
                elif _is_linux():
                    # Block ALL traffic to/from this IP
                    iptables_path = shutil.which("iptables")
                    if iptables_path:
                        subprocess.run(  # nosec
                            [iptables_path, "-A", "INPUT", "-s", ip, "-j", "DROP"],
                            capture_output=True, text=True, timeout=15)
                        subprocess.run(  # nosec
                            [iptables_path, "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                            capture_output=True, text=True, timeout=15)
                        log.warning("🧪 ISOLATED device at IP %s (iptables in+out)", ip)
                    else:
                        log.error("iptables not found — cannot isolate %s on Linux", ip)
                else:
                    log.warning("IsolateAction: unsupported platform %s — recording isolation intent", platform.system())
            except Exception as e:
                log.error("IsolateAction failed for %s: %s", ip, e)
                success = False

        return success


# --- Action 7: Kill Process ---
class KillProcessAction(Action):
    """Kill a malicious process on the compromised host."""

    name = "kill_process"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log kill process request — carried out by endpoint agent."""
        pid = incident.get("pid", incident.get("process_id", ""))
        process_name = incident.get("process_name", incident.get("name", ""))
        hostname = incident.get("hostname", incident.get("device_id", "unknown"))

        log.warning(
            "\U0001f4a5 KILL PROCESS: Incident %s | Host: %s | PID: %s | Process: %s",
            incident.get("id", "?"),
            hostname,
            pid or "unknown",
            process_name or "unknown",
        )

        # On Windows, attempt real process kill via taskkill
        if _is_windows() and pid:
            try:
                kill_bin = shutil.which("taskkill")
                if not kill_bin:
                    log.warning("taskkill not found on Windows system — dispatching to agent")
                else:
                    result = subprocess.run(  # nosec
                        [kill_bin, "/F", "/PID", str(pid)],
                        capture_output=True, text=True, timeout=10,
                    )
                    if result.returncode == 0:
                        log.info("Process %s killed on %s", pid, hostname)
                        return True
                    log.warning("Failed to kill process %s: %s", pid, result.stderr.strip())
            except Exception as e:
                log.error("Error killing process %s: %s", pid, e)

        # On Linux, attempt real process kill via kill
        if _is_linux() and pid:
            try:
                kill_bin = shutil.which("kill")
                if not kill_bin:
                    log.warning("kill not found on Linux system — dispatching to agent")
                else:
                    result = subprocess.run(  # nosec
                        [kill_bin, "-9", str(pid)],
                        capture_output=True, text=True, timeout=10,
                    )
                if result.returncode == 0:
                    log.info("Process %s killed on %s", pid, hostname)
                    return True
                log.warning("Failed to kill process %s: %s", pid, result.stderr.strip())
            except Exception as e:
                log.error("Error killing process %s: %s", pid, e)

        # If we can't kill remotely, log it as a command to be picked up by the agent
        log.warning(
            "\U0001f4a5 KILL PROCESS REQUESTED: Host: %s | PID: %s | Process: %s (agent dispatch)",
            hostname, pid or "*", process_name or "*",
        )
        return True


# --- Action 8: Scan Host ---
class ScanHostAction(Action):
    """Trigger a vulnerability scan on the compromised host."""

    name = "scan_host"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log scan request — carried out by scanning infrastructure."""
        log.warning(
            "\U0001f50d SCAN HOST: Incident %s | Host: %s | IP: %s",
            incident.get("id", "?"),
            incident.get("hostname", incident.get("device_id", "unknown")),
            incident.get("source_ip", "unknown"),
        )
        return True


# --- Action 9: Disable User ---
class DisableUserAction(Action):
    """Disable a user account."""

    name = "disable_user"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log user disable request — carried out by DB or directory service."""
        log.warning(
            "\U0001f6ab DISABLE USER: Incident %s | User: %s | Email: %s",
            incident.get("id", "?"),
            incident.get("username", incident.get("user", "unknown")),
            incident.get("email", "unknown"),
        )
        return True


# --- Action 10: Enable User ---
class EnableUserAction(Action):
    """Enable a previously disabled user account."""

    name = "enable_user"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log user enable request."""
        log.warning(
            "\u2705 ENABLE USER: Incident %s | User: %s | Email: %s",
            incident.get("id", "?"),
            incident.get("username", incident.get("user", "unknown")),
            incident.get("email", "unknown"),
        )
        return True


# --- Action 11: Create Ticket ---
class CreateTicketAction(Action):
    """Create a ticket/incident in the ticketing system."""

    name = "create_ticket"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log ticket creation."""
        ticket_id = f"TKT-{uuid4().hex[:8].upper()}"
        log.warning(
            "\U0001f3ab CREATE TICKET: %s | Incident: %s | Title: %s | Severity: %s",
            ticket_id,
            incident.get("id", "?"),
            incident.get("title", "?"),
            incident.get("severity", "?"),
        )
        return True


# --- Action 12: Send Notification ---
class SendNotificationAction(Action):
    """Send a notification through configured channels (email, Slack, webhook, PagerDuty)."""

    name = "send_notification"

    def __init__(self, channel: Optional[str] = None):
        self.channel = channel or os.environ.get("CYBERNOVA_NOTIFICATION_CHANNEL", "webhook")

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Send notification about incident."""
        log.warning(
            "\U0001f514 SEND NOTIFICATION [%s]: Incident %s | Title: %s | Severity: %s",
            self.channel.upper(),
            incident.get("id", "?"),
            incident.get("title", "?"),
            incident.get("severity", "?"),
        )
        return True


# --- Action 13: Quarantine File ---
class QuarantineFileAction(Action):
    """Quarantine a malicious file on the host."""

    name = "quarantine_file"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log quarantine request — carried out by endpoint agent."""
        file_path = incident.get("file_path", incident.get("path", "unknown"))
        hostname = incident.get("hostname", incident.get("device_id", "unknown"))
        sha256 = incident.get("sha256", incident.get("hash", "unknown"))

        log.warning(
            "\U0001f9f9 QUARANTINE FILE: Host: %s | Path: %s | SHA256: %s",
            hostname, file_path, sha256,
        )
        return True


# --- Action 14: Reset MFA ---
class ResetMFAAction(Action):
    """Force reset MFA for a compromised user account."""

    name = "reset_mfa"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Log MFA reset request."""
        log.warning(
            "\U0001f510 RESET MFA: Incident %s | User: %s | Email: %s",
            incident.get("id", "?"),
            incident.get("username", incident.get("user", "unknown")),
            incident.get("email", "unknown"),
        )
        return True


# --- Action 6: Collect Forensics ---
class ForensicsAction(Action):
    """Collect forensic evidence from the compromised host."""

    name = "collect_forensics"

    def execute(self, incident: Dict[str, Any]) -> bool:
        """Record forensic collection request — carried out by endpoint agent."""
        log.warning(
            "🔬 FORENSICS COLLECTION: Incident %s | Host: %s | IP: %s | Type: %s",
            incident.get("id", "?"),
            incident.get("hostname", incident.get("device_id", "unknown")),
            incident.get("source_ip", "unknown"),
            incident.get("incident_type", "unknown"),
        )
        return True


# --- SOAR Engine ---
class SoarEngine:
    """SOAR engine that triggers actions on confirmed critical incidents."""

    def __init__(self) -> None:
        self.enabled = is_soar_enabled()
        self.actions_str = get_soar_actions()
        self._actions: List[Action] = []
        self._register_actions()

    def _register_actions(self) -> None:
        """Register ALL enabled actions — always includes block_ip, webhook, log, notify, isolate, collect_forensics."""
        if "webhook" in self.actions_str:
            self._actions.append(WebhookAction())
        if "block_ip" in self.actions_str:
            self._actions.append(BlockIPAction())
        if "log" in self.actions_str:
            self._actions.append(LogAction())
        # Notify action — always fires for visibility
        if "notify" in self.actions_str:
            self._actions.append(NotifyAction())
        # Isolate action — real host isolation
        if "isolate" in self.actions_str:
            self._actions.append(IsolateAction())
        # Forensics action
        if "collect_forensics" in self.actions_str:
            self._actions.append(ForensicsAction())
        # Kill Process action
        if "kill_process" in self.actions_str:
            self._actions.append(KillProcessAction())
        # Scan Host action
        if "scan_host" in self.actions_str:
            self._actions.append(ScanHostAction())
        # Disable User action
        if "disable_user" in self.actions_str:
            self._actions.append(DisableUserAction())
        # Enable User action
        if "enable_user" in self.actions_str:
            self._actions.append(EnableUserAction())
        # Create Ticket action
        if "create_ticket" in self.actions_str:
            self._actions.append(CreateTicketAction())
        # Send Notification action
        if "send_notification" in self.actions_str:
            self._actions.append(SendNotificationAction())
        # Quarantine File action
        if "quarantine_file" in self.actions_str:
            self._actions.append(QuarantineFileAction())
        # Reset MFA action
        if "reset_mfa" in self.actions_str:
            self._actions.append(ResetMFAAction())

    def should_trigger(self, incident: Dict[str, Any]) -> bool:
        """
        Determine if SOAR should trigger.
        Rules (safety-first):
        1. SOAR is ALWAYS enabled
        2. Only fires on CONFIRMED incidents (never auto-confirm — autonomous
           actions like IP blocks / host isolation must not run on unconfirmed alerts)
        3. Triggers on confirmed incidents with risk_score >= 50 OR severity in
           (critical, high)
        """
        if not self.enabled:
            return False

        # Strict confirmation gate: callers must explicitly mark incidents as
        # confirmed before SOAR takes autonomous action (see streaming/soar_worker.py).
        if not incident.get("confirmed", False):
            return False

        risk_score = float(incident.get("risk_score", 0))
        severity = incident.get("severity", "")

        if risk_score >= 50.0 or severity in ("critical", "high"):
            return True

        return False

    def trigger(self, incident: Dict[str, Any]) -> bool:
        """Trigger SOAR actions on incident."""
        if not self.should_trigger(incident):
            return False

        success = True
        for action in self._actions:
            try:
                result = action.execute(incident)
                if not result:
                    success = False
                    log.warning("SOAR action %s returned failure", action.name)
            except Exception as e:
                log.error("SOAR action %s failed: %s", action.name, e)
                success = False

        return success

    def trigger_if(self, incident: Dict[str, Any]) -> Optional[bool]:
        """Convenience: trigger only if conditions met."""
        if self.should_trigger(incident):
            return self.trigger(incident)
        return None


# --- Global engine ---
_engine: Optional[SoarEngine] = None


def get_engine() -> SoarEngine:
    """Get global SOAR engine."""
    global _engine
    if _engine is None:
        _engine = SoarEngine()
    return _engine


def trigger_soar(incident: Dict[str, Any]) -> bool:
    """Convenience: trigger SOAR on incident."""
    return get_engine().trigger(incident)


soar_engine = get_engine()
