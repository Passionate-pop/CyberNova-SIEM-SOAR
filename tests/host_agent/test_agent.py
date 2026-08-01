"""
CyberNova — Host Agent Unit Tests
Tests for SecurityEvent, HostAgent init, monitoring functions.
"""
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, PropertyMock, call, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import re

import pytest

from host_agent import SecurityEvent, HostAgent, RealTimeFileWatcher


# ═════════════════════════════════════════════════════════════════════════════
# SecurityEvent Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestSecurityEvent:
    def test_basic_event(self):
        """A SecurityEvent with all required fields should serialize correctly."""
        event = SecurityEvent(
            event_type="malicious_process",
            severity="critical",
            source="process_monitor",
            message="CRITICAL: mimikatz.exe detected",
            timestamp="2026-01-01T00:00:00Z",
            hostname="SRV-001",
        )
        d = event.to_dict()
        assert d["event_type"] == "malicious_process"
        assert d["severity"] == "critical"
        assert d["message"] == "CRITICAL: mimikatz.exe detected"
        assert d["hostname"] == "SRV-001"

    def test_event_with_optional_fields(self):
        """Optional fields (source_ip, dest_ip, user) should be included when set."""
        event = SecurityEvent(
            event_type="suspicious_network",
            severity="high",
            source="network_monitor",
            message="Connection to 203.0.113.5",
            timestamp="2026-01-01T00:00:00Z",
            source_ip="10.0.0.5",
            dest_ip="203.0.113.5",
            user="jsmith",
            hostname="SRV-001",
        )
        d = event.to_dict()
        assert d["source_ip"] == "10.0.0.5"
        assert d["dest_ip"] == "203.0.113.5"
        assert d["user"] == "jsmith"

    def test_event_extra_fields(self):
        """Extra kwargs should be merged into the serialized output."""
        event = SecurityEvent(
            event_type="suspicious_file",
            severity="high",
            source="file_monitor",
            message="Suspicious file: evil.exe",
            timestamp="2026-01-01T00:00:00Z",
            hostname="SRV-001",
            details={"sha256": "abc123", "risk_score": 85},
        )
        d = event.to_dict()
        assert d["details"]["sha256"] == "abc123"
        assert d["details"]["risk_score"] == 85

    def test_event_empty_fields_omitted(self):
        """Empty or None optional fields should be excluded from serialized output."""
        event = SecurityEvent(
            event_type="agent_heartbeat",
            severity="info",
            source="agent_heartbeat",
            message="Heartbeat",
            timestamp="2026-01-01T00:00:00Z",
            hostname="SRV-001",
            source_ip="",
            dest_ip="",
            user="",
        )
        d = event.to_dict()
        assert "source_ip" not in d
        assert "dest_ip" not in d
        assert "user" not in d


# ═════════════════════════════════════════════════════════════════════════════
# HostAgent Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestHostAgentInit:
    def _make_agent(self):
        """Create a HostAgent with file indexing mocked to avoid slow filesystem walk."""
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    def test_init_with_credentials(self):
        """HostAgent should initialize with explicit username/password."""
        agent = self._make_agent()
        assert agent.backend_url == "http://localhost:8888"
        assert agent.username == "admin"
        assert agent.password == "secret"
        assert agent.hostname  # not empty

    def test_init_raises_without_credentials(self):
        """HostAgent should raise ValueError when no credentials given."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="Username and password required"):
                with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
                    HostAgent(backend_url="http://localhost:8888")

    def test_init_tracking_sets_exist(self):
        """All deduplication tracking sets should be initialized."""
        agent = self._make_agent()
        assert hasattr(agent, "_seen_files")
        assert hasattr(agent, "_seen_processes")
        assert hasattr(agent, "_seen_services")
        assert hasattr(agent, "_seen_drivers")
        assert hasattr(agent, "_seen_firewall_rules")
        assert hasattr(agent, "_seen_external_ips")

    def test_init_safe_ips_exists(self):
        """SAFE_IPS class attribute should be defined."""
        agent = self._make_agent()
        assert hasattr(HostAgent, "SAFE_IPS")
        assert "8.8.8.8" in HostAgent.SAFE_IPS
        assert "1.1.1.1" in HostAgent.SAFE_IPS


class TestHostAgentSecurityEvent:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    @pytest.mark.asyncio
    async def test_map_severity_known_types(self):
        """_map_severity should return correct severity for known event types."""
        agent = self._make_agent()
        assert agent._map_severity("malicious_process") == "critical"
        assert agent._map_severity("boot_config_changed") == "critical"
        assert agent._map_severity("defender_disabled") == "critical"
        assert agent._map_severity("shadow_copy_deleted") == "critical"
        assert agent._map_severity("wmi_persistence") == "critical"
        assert agent._map_severity("hosts_hijacked") == "high"
        assert agent._map_severity("suspicious_network") == "medium"
        assert agent._map_severity("failed_login") == "medium"
        assert agent._map_severity("usb_connected") == "low"
        assert agent._map_severity("agent_heartbeat") == "info"

    @pytest.mark.asyncio
    async def test_map_severity_unknown_type(self):
        """_map_severity should return passed severity for unknown types."""
        agent = HostAgent(
            backend_url="http://localhost:8888",
            username="admin",
            password="secret",
        )
        assert agent._map_severity("unknown_event", current="medium") == "medium"


class TestHostAgentPrivateIP:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    def test_private_ips(self):
        """_is_private_ip should correctly identify RFC1918 addresses."""
        agent = self._make_agent()
        assert agent._is_private_ip("10.0.0.1") is True
        assert agent._is_private_ip("172.16.0.1") is True
        assert agent._is_private_ip("192.168.1.1") is True
        assert agent._is_private_ip("127.0.0.1") is True
        assert agent._is_private_ip("169.254.1.1") is True

    def test_public_ips(self):
        """_is_private_ip should return False for public IPs."""
        agent = HostAgent(
            backend_url="http://localhost:8888",
            username="admin",
            password="secret",
        )
        assert agent._is_private_ip("8.8.8.8") is False
        assert agent._is_private_ip("203.0.113.5") is False
        assert agent._is_private_ip("1.1.1.1") is False

    def test_invalid_ip(self):
        """_is_private_ip should handle invalid IPs without crashing."""
        agent = HostAgent(
            backend_url="http://localhost:8888",
            username="admin",
            password="secret",
        )
        assert agent._is_private_ip("not-an-ip") is False
        assert agent._is_private_ip("") is False
        assert agent._is_private_ip("::1") is False


class TestHostAgentDangerousExtensions:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    def test_dangerous_extensions_set(self):
        """DANGEROUS_EXTENSIONS should cover major attack vectors."""
        agent = self._make_agent()
        exts = agent.DANGEROUS_EXTENSIONS
        # Executables
        assert ".exe" in exts
        assert ".dll" in exts
        assert ".scr" in exts
        # Scripts
        assert ".ps1" in exts
        assert ".vbs" in exts
        assert ".py" in exts
        # Office macros
        assert ".docm" in exts
        assert ".xlsm" in exts
        # Archives (used for staging)
        assert ".zip" in exts
        assert ".rar" in exts
        # Disk images (bypass MOTW)
        assert ".iso" in exts
        assert ".vhd" in exts

    def test_magic_bytes_detection(self):
        """_detect_real_type should correctly identify file types from magic bytes."""
        agent = HostAgent(
            backend_url="http://localhost:8888",
            username="admin",
            password="secret",
        )
        assert agent._detect_real_type(b"MZ") == ".exe"
        assert agent._detect_real_type(b"\x89PNG") == ".png"
        assert agent._detect_real_type(b"%PDF") == ".pdf"
        assert agent._detect_real_type(b"GIF8") == ".gif"
        assert agent._detect_real_type(b"PK\x03\x04") == ".zip"
        assert agent._detect_real_type(b"hello world") == "text"
        assert agent._detect_real_type(b"") == "empty"


class TestHostAgentCriticalPatterns:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    def test_critical_patterns_detect_known_tools(self):
        """CRITICAL_PATTERNS should detect common malicious tool references."""
        agent = self._make_agent()
        for pattern in [r"mimikatz", r"invoke-mimikatz", r"lsass", r"cobaltstrike",
                         r"powersploit", r"beacon", r"metasploit"]:
            matched = any(re.search(p, f"process {pattern} -arg", re.I)
                          for p in agent.CRITICAL_PATTERNS)
            assert matched, f"Pattern '{pattern}' should match CRITICAL_PATTERNS"

    def test_suspicious_patterns_detect_attacks(self):
        """SUSPICIOUS_PATTERNS should detect common attack commands."""
        agent = HostAgent(
            backend_url="http://localhost:8888",
            username="admin",
            password="secret",
        )
        test_cases = [
            "net user hacker Password123! /add",
            "net localgroup Administrators hacker /add",
            "schtasks /create /tn evil",
            "vssadmin delete shadows /all",
            "bcdedit /delete",
            "wevtutil cl security",
            "wmic process call create calc.exe",
            "reg delete HKLM\\...\\Run /f",
        ]
        for cmd in test_cases:
            matched = any(re.search(p, cmd, re.I) for p in agent.SUSPICIOUS_PATTERNS)
            assert matched, f"Command '{cmd}' should match SUSPICIOUS_PATTERNS"


class TestHostAgentDeduplication:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    @pytest.mark.asyncio
    async def test_dedup_same_event_within_window(self):
        """Same event sent twice within 60s should be deduplicated."""
        agent = self._make_agent()

        event1 = SecurityEvent(
            event_type="suspicious_file",
            severity="high",
            source="file_monitor",
            message="Suspicious file: evil.exe",
            timestamp="2026-01-01T00:00:00Z",
            hostname="SRV-001",
            details={"sha256": "abc123"},
        )
        event2 = SecurityEvent(
            event_type="suspicious_file",
            severity="high",
            source="file_monitor",
            message="Suspicious file: evil.exe",
            timestamp="2026-01-01T00:00:01Z",
            hostname="SRV-001",
            details={"sha256": "abc123"},
        )

        # Calculate dedup keys — they should be equal for identical events
        key1 = agent._get_dedupe_key(event1)
        key2 = agent._get_dedupe_key(event2)
        assert key1 == key2


class TestHostAgentCleanup:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    @pytest.mark.asyncio
    async def test_cleanup_stale_entries_removes_old_dedup(self):
        """_cleanup_stale_entries should remove expired dedup cache entries."""
        agent = self._make_agent()
        # Add old entries
        old_time = time.time() - 300  # 5 min old
        agent._dedup_cache["stale_key"] = old_time
        agent._event_type_timestamps["test_type"] = [old_time]

        agent._cleanup_stale_entries()

        assert "stale_key" not in agent._dedup_cache
        assert "test_type" not in agent._event_type_timestamps

    @pytest.mark.asyncio
    async def test_cleanup_trims_large_tracking_sets(self):
        """_cleanup_stale_entries should cap oversized tracking sets."""
        agent = HostAgent(
            backend_url="http://localhost:8888",
            username="admin",
            password="secret",
        )
        # Fill _seen_processes with more items than the limit
        for i in range(50100):
            agent._seen_processes.add(f"process:{i}")
        assert len(agent._seen_processes) > 50000

        agent._cleanup_stale_entries()

        assert len(agent._seen_processes) <= 50000


class TestHostAgentSafeProcesses:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    def test_safe_processes_covered(self):
        """SAFE_PROCESSES should include all critical Windows system processes."""
        agent = self._make_agent()
        safe = agent.SAFE_PROCESSES
        assert "svchost.exe" in safe
        assert "lsass.exe" in safe
        assert "explorer.exe" in safe
        assert "services.exe" in safe
        assert "winlogon.exe" in safe
        assert "csrss.exe" in safe


class TestHostAgentMagicBytes:
    def _make_agent(self):
        with patch.object(HostAgent, '_initialize_all_drives_file_index', return_value=None):
            return HostAgent(
                backend_url="http://localhost:8888",
                username="admin",
                password="secret",
            )

    def test_magic_bytes_coverage(self):
        """MAGIC_BYTES should detect all common file types."""
        agent = self._make_agent()
        assert b"MZ" in agent.MAGIC_BYTES
        assert b"\x7fELF" in agent.MAGIC_BYTES
        assert b"\x89PNG" in agent.MAGIC_BYTES
        assert b"\xff\xd8\xff" in agent.MAGIC_BYTES
        assert b"%PDF" in agent.MAGIC_BYTES


# ═════════════════════════════════════════════════════════════════════════════
# SecurityEvent Integration Tests
# ═════════════════════════════════════════════════════════════════════════════

class TestSecurityEventSerialization:
    def test_extra_fields_merged_correctly(self):
        """Extra fields should merge at top level, not nest under 'extra'."""
        event = SecurityEvent(
            event_type="test",
            severity="low",
            source="test",
            message="test event",
            timestamp="2026-01-01T00:00:00Z",
            hostname="TEST",
            signature="sig123",
            pid=1234,
        )
        d = event.to_dict()
        assert d["signature"] == "sig123"
        assert d["pid"] == 1234
        assert "extra" not in d

    def test_multiple_events_unique(self):
        """Different events should have different serialized forms."""
        e1 = SecurityEvent(
            event_type="alert_a", severity="high", source="src",
            message="Alert A", timestamp="t1", hostname="h1",
        )
        e2 = SecurityEvent(
            event_type="alert_b", severity="low", source="src",
            message="Alert B", timestamp="t2", hostname="h2",
        )
        assert e1.to_dict() != e2.to_dict()



