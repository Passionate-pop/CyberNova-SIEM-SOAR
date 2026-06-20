"""Unit tests for _enforce_firewall_unblock and _enforce_firewall_block — prevents
regressions in the firewall enforcement logic across Docker, Windows, iptables,
nftables, and ipfw.

Covers:
- Docker detection (returns False, skips host firewall)
- Windows netsh firewall add/delete rules
- Linux iptables INPUT+FORWARD rule add/remove
- Linux nftables handle-based rule deletion
- BSD/macOS ipfw rule listing and deletion by rule number
- No firewall binary found (returns False)
- Exception handling (returns False on unexpected errors)
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path


# ---------------------------------------------------------------------------
# Import the functions under test
# ---------------------------------------------------------------------------
from cybernova.response.routes.soar_actions import (
    _enforce_firewall_block,
    _enforce_firewall_unblock,
    _is_running_in_docker,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _completed(returncode=0, stdout="", stderr=""):
    """Build a fake CompletedProcess."""
    cp = MagicMock()
    cp.returncode = returncode
    cp.stdout = stdout
    cp.stderr = stderr
    return cp


def _make_path_side_effect(exists: set[str]):
    """Return a callable to replace Path so specific binaries appear to exist.
    *exists* is a set like {"/sbin/iptables"}."""
    def _factory(path_str):
        obj = MagicMock(spec=Path)
        obj.exists.return_value = path_str in exists
        return obj
    return _factory


def _nth_command(mock_thread, n=0):
    """Extract the command list from the nth call to asyncio.to_thread.

    asyncio.to_thread(subprocess.run, [cmd...], ...) stores subprocess.run
    as positional arg 0 and the command list as positional arg 1.
    """
    return mock_thread.call_args_list[n][0][1]


# ######################################################################
# A. _enforce_firewall_unblock tests
# ######################################################################

# ===================================================================
# A1. Docker detection (unblock)
# ===================================================================
class TestUnblockDockerDetection:
    """When running inside a Docker container, unblock should be a no-op."""

    @pytest.mark.asyncio
    @patch(
        "cybernova.response.routes.soar_actions._is_running_in_docker",
        return_value=True,
    )
    async def test_docker_returns_false(self, mock_docker):
        result = await _enforce_firewall_unblock("10.0.0.1")
        assert result is False

    @pytest.mark.asyncio
    @patch(
        "cybernova.response.routes.soar_actions._is_running_in_docker",
        return_value=True,
    )
    async def test_docker_does_not_call_subprocess(self, mock_docker):
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            await _enforce_firewall_unblock("10.0.0.1")
            mock_thread.assert_not_called()


# ===================================================================
# A2. Windows firewall unblock
# ===================================================================
class TestUnblockWindowsFirewall:
    """Windows: netsh advfirewall firewall delete rule name=..."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_windows_delete_rule_success(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Windows"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_unblock("192.168.1.100")

        assert result is True
        cmd = _nth_command(mock_thread, 0)
        assert cmd == [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            "name=CyberNova_Block_192_168_1_100",
        ]

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_windows_delete_rule_failure(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=1, stderr="Access denied")

        with patch("platform.system", return_value="Windows"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_unblock("10.0.0.5")

        assert result is False


# ===================================================================
# A3. Linux iptables unblock
# ===================================================================
class TestUnblockIptablesFirewall:
    """Linux: iptables -D INPUT/FORWARD -s ip -j DROP"""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_iptables_unblock_success(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/iptables"})):
            result = await _enforce_firewall_unblock("10.0.0.99")

        assert result is True
        assert mock_thread.call_count == 2
        assert _nth_command(mock_thread, 0) == ["iptables", "-D", "INPUT", "-s", "10.0.0.99", "-j", "DROP"]
        assert _nth_command(mock_thread, 1) == ["iptables", "-D", "FORWARD", "-s", "10.0.0.99", "-j", "DROP"]

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_iptables_uses_usr_sbin(self, mock_thread, mock_docker):
        """iptables in /usr/sbin should also be detected."""
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/usr/sbin/iptables"})):
            result = await _enforce_firewall_unblock("172.16.0.1")

        assert result is True
        assert mock_thread.call_count == 2


# ===================================================================
# A4. Linux nftables handle-based deletion
# ===================================================================
class TestUnblockNftablesFirewall:
    """Linux nftables: list ruleset, find handle, delete by handle."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_nftables_handle_deletion(self, mock_thread, mock_docker):
        """nftables: find matching drop rule and delete by handle."""
        nft_list_output = (
            "table inet filter {\n"
            "  chain INPUT {\n"
            "    type filter hook input priority filter; policy accept;\n"
            "    drop ip saddr 10.0.0.50 # handle 42\n"
            "  }\n"
            "}\n"
        )
        mock_thread.side_effect = [
            _completed(returncode=0, stdout=nft_list_output),
            _completed(returncode=0),
        ]

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/nft"})):
            result = await _enforce_firewall_unblock("10.0.0.50")

        assert result is True
        assert _nth_command(mock_thread, 0) == ["nft", "-a", "list", "ruleset"]
        assert _nth_command(mock_thread, 1) == [
            "nft", "delete", "rule", "inet", "filter", "INPUT", "handle", "42",
        ]

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_nftables_no_matching_rule(self, mock_thread, mock_docker):
        """nftables: no matching rule found — returns True (already unblocked)."""
        nft_list_output = (
            "table inet filter {\n"
            "  chain INPUT {\n"
            "    type filter hook input priority filter; policy accept;\n"
            "  }\n"
            "}\n"
        )
        mock_thread.return_value = _completed(returncode=0, stdout=nft_list_output)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/nft"})):
            result = await _enforce_firewall_unblock("10.0.0.99")

        assert result is True

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_nftables_delete_handle_fails(self, mock_thread, mock_docker):
        """nftables: list succeeds but delete by handle fails → returns False."""
        nft_list_output = "drop ip saddr 10.0.0.5 # handle 7\n"
        mock_thread.side_effect = [
            _completed(returncode=0, stdout=nft_list_output),
            _completed(returncode=1, stderr="Could not process rule"),
        ]

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/nft"})):
            result = await _enforce_firewall_unblock("10.0.0.5")

        assert result is False

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_nftables_list_fails(self, mock_thread, mock_docker):
        """nftables: listing ruleset fails → returns False."""
        mock_thread.return_value = _completed(returncode=1, stderr="Permission denied")

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/nft"})):
            result = await _enforce_firewall_unblock("10.0.0.5")

        assert result is False

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_nftables_multiple_rules_deletes_first(self, mock_thread, mock_docker):
        """nftables: multiple rules match — should delete the first matching handle."""
        nft_list_output = (
            "drop ip saddr 10.0.0.1 # handle 10\n"
            "drop ip saddr 10.0.0.1 # handle 20\n"
        )
        mock_thread.side_effect = [
            _completed(returncode=0, stdout=nft_list_output),
            _completed(returncode=0),
        ]

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/nft"})):
            result = await _enforce_firewall_unblock("10.0.0.1")

        assert result is True
        assert _nth_command(mock_thread, 1) == [
            "nft", "delete", "rule", "inet", "filter", "INPUT", "handle", "10",
        ]


# ===================================================================
# A5. BSD/macOS ipfw unblock
# ===================================================================
class TestUnblockIpfwFirewall:
    """BSD/macOS: ipfw list → find deny rule → ipfw delete <rule_num>."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_ipfw_delete_matching_rule(self, mock_thread, mock_docker):
        """ipfw: find matching deny rule and delete by rule number."""
        ipfw_list_output = (
            "100 deny ip from 10.0.0.7 to any\n"
            "200 allow ip from any to any\n"
        )
        mock_thread.side_effect = [
            _completed(returncode=0, stdout=ipfw_list_output),
            _completed(returncode=0),
        ]

        with patch("platform.system", return_value="Darwin"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/ipfw"})):
            result = await _enforce_firewall_unblock("10.0.0.7")

        assert result is True
        assert _nth_command(mock_thread, 0) == ["ipfw", "list"]
        assert _nth_command(mock_thread, 1) == ["ipfw", "delete", "100"]

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_ipfw_no_matching_rule(self, mock_thread, mock_docker):
        """ipfw: no matching deny rule — returns True (already unblocked)."""
        ipfw_list_output = "200 allow ip from any to any\n"
        mock_thread.return_value = _completed(returncode=0, stdout=ipfw_list_output)

        with patch("platform.system", return_value="Darwin"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/ipfw"})):
            result = await _enforce_firewall_unblock("10.0.0.7")

        assert result is True

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_ipfw_list_fails(self, mock_thread, mock_docker):
        """ipfw: listing fails → returns False."""
        mock_thread.return_value = _completed(returncode=1, stderr="ipfw not found")

        with patch("platform.system", return_value="Darwin"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/ipfw"})):
            result = await _enforce_firewall_unblock("10.0.0.7")

        assert result is False


# ===================================================================
# A6. No firewall binary found (unblock)
# ===================================================================
class TestUnblockNoFirewallBinary:
    """When no supported firewall binary exists, return False (DB-only)."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    async def test_no_binary_returns_false(self, mock_docker):
        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_unblock("10.0.0.1")
        assert result is False


# ===================================================================
# A7. Exception handling (unblock)
# ===================================================================
class TestUnblockExceptionHandling:
    """Unexpected exceptions should be caught and return False."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch(
        "cybernova.response.routes.soar_actions.asyncio.to_thread",
        new_callable=AsyncMock,
        side_effect=OSError("subprocess fork failed"),
    )
    async def test_os_error_returns_false(self, mock_thread, mock_docker):
        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/iptables"})):
            result = await _enforce_firewall_unblock("10.0.0.1")
        assert result is False


# ===================================================================
# A8. Edge cases (unblock)
# ===================================================================
class TestUnblockEdgeCases:
    """Various edge cases for IP address handling."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    async def test_ipv6_address_no_binary(self, mock_docker):
        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_unblock("::1")
        assert result is False

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    async def test_empty_ip_no_binary(self, mock_docker):
        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_unblock("")
        assert result is False

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_special_chars_ip_iptables(self, mock_thread, mock_docker):
        """IP with special chars should not cause injection — verify exact command."""
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/iptables"})):
            result = await _enforce_firewall_unblock("10.0.0.1; rm -rf /")

        assert result is True
        cmd = _nth_command(mock_thread, 0)
        assert cmd == ["iptables", "-D", "INPUT", "-s", "10.0.0.1; rm -rf /", "-j", "DROP"]


# ######################################################################
# B. _enforce_firewall_block tests
# ######################################################################

# ===================================================================
# B1. Docker detection (block)
# ===================================================================
class TestBlockDockerDetection:
    """When running inside a Docker container, block should be a no-op."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=True)
    async def test_docker_returns_false(self, mock_docker):
        result = await _enforce_firewall_block("10.0.0.1")
        assert result is False

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=True)
    async def test_docker_does_not_call_subprocess(self, mock_docker):
        with patch("asyncio.to_thread", new_callable=AsyncMock) as mock_thread:
            await _enforce_firewall_block("10.0.0.1")
            mock_thread.assert_not_called()


# ===================================================================
# B2. Windows firewall block
# ===================================================================
class TestBlockWindowsFirewall:
    """Windows: netsh advfirewall firewall add rule ..."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_windows_add_rule_success(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Windows"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_block("192.168.1.100")

        assert result is True
        cmd = _nth_command(mock_thread, 0)
        assert cmd[0:3] == ["netsh", "advfirewall", "firewall"]
        assert "name=CyberNova_Block_192_168_1_100" in cmd
        assert "remoteip=192.168.1.100" in cmd

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_windows_add_rule_failure(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=1, stderr="Access denied")

        with patch("platform.system", return_value="Windows"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_block("10.0.0.5")

        assert result is False


# ===================================================================
# B3. Linux iptables block
# ===================================================================
class TestBlockIptablesFirewall:
    """Linux: iptables -A INPUT/FORWARD -s ip -j DROP"""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_iptables_block_success(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/iptables"})):
            result = await _enforce_firewall_block("10.0.0.99")

        assert result is True
        assert mock_thread.call_count == 2
        assert _nth_command(mock_thread, 0) == ["iptables", "-A", "INPUT", "-s", "10.0.0.99", "-j", "DROP"]
        assert _nth_command(mock_thread, 1) == ["iptables", "-A", "FORWARD", "-s", "10.0.0.99", "-j", "DROP"]

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_iptables_block_failure(self, mock_thread, mock_docker):
        """iptables block fails if either INPUT or FORWARD fails."""
        mock_thread.side_effect = [
            _completed(returncode=0),  # INPUT succeeds
            _completed(returncode=1, stderr="Permission denied"),  # FORWARD fails
        ]

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/iptables"})):
            result = await _enforce_firewall_block("10.0.0.99")

        assert result is False

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_iptables_uses_usr_sbin(self, mock_thread, mock_docker):
        """iptables in /usr/sbin should also be detected."""
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/usr/sbin/iptables"})):
            result = await _enforce_firewall_block("172.16.0.1")

        assert result is True
        assert mock_thread.call_count == 2


# ===================================================================
# B4. Linux nftables block
# ===================================================================
class TestBlockNftablesFirewall:
    """Linux nftables: nft add rule inet filter INPUT ip saddr ip drop"""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_nftables_block_success(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/nft"})):
            result = await _enforce_firewall_block("10.0.0.50")

        assert result is True
        cmd = _nth_command(mock_thread, 0)
        assert cmd == ["nft", "add", "rule", "inet", "filter", "INPUT", "ip", "saddr", "10.0.0.50", "drop"]

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_nftables_block_failure(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=1, stderr="nft error")

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/nft"})):
            result = await _enforce_firewall_block("10.0.0.5")

        assert result is False


# ===================================================================
# B5. BSD/macOS ipfw block
# ===================================================================
class TestBlockIpfwFirewall:
    """BSD/macOS: ipfw add deny ip from ip to any"""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_ipfw_block_success(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Darwin"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/ipfw"})):
            result = await _enforce_firewall_block("10.0.0.7")

        assert result is True
        cmd = _nth_command(mock_thread, 0)
        assert cmd == ["ipfw", "add", "deny", "ip", "from", "10.0.0.7", "to", "any"]

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_ipfw_block_failure(self, mock_thread, mock_docker):
        mock_thread.return_value = _completed(returncode=1, stderr="ipfw error")

        with patch("platform.system", return_value="Darwin"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/ipfw"})):
            result = await _enforce_firewall_block("10.0.0.7")

        assert result is False


# ===================================================================
# B6. No firewall binary found (block)
# ===================================================================
class TestBlockNoFirewallBinary:
    """When no supported firewall binary exists, return False (DB-only)."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    async def test_no_binary_returns_false(self, mock_docker):
        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_block("10.0.0.1")
        assert result is False


# ===================================================================
# B7. Exception handling (block)
# ===================================================================
class TestBlockExceptionHandling:
    """Unexpected exceptions should be caught and return False."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch(
        "cybernova.response.routes.soar_actions.asyncio.to_thread",
        new_callable=AsyncMock,
        side_effect=OSError("subprocess fork failed"),
    )
    async def test_os_error_returns_false(self, mock_thread, mock_docker):
        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/iptables"})):
            result = await _enforce_firewall_block("10.0.0.1")
        assert result is False


# ===================================================================
# B8. Edge cases (block)
# ===================================================================
class TestBlockEdgeCases:
    """Various edge cases for IP address handling."""

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    async def test_ipv6_address_no_binary(self, mock_docker):
        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect(set())):
            result = await _enforce_firewall_block("::1")
        assert result is False

    @pytest.mark.asyncio
    @patch("cybernova.response.routes.soar_actions._is_running_in_docker", return_value=False)
    @patch("cybernova.response.routes.soar_actions.asyncio.to_thread", new_callable=AsyncMock)
    async def test_special_chars_ip_iptables(self, mock_thread, mock_docker):
        """IP with special chars should not cause injection — verify exact command."""
        mock_thread.return_value = _completed(returncode=0)

        with patch("platform.system", return_value="Linux"), \
             patch("cybernova.response.routes.soar_actions.Path", side_effect=_make_path_side_effect({"/sbin/iptables"})):
            result = await _enforce_firewall_block("10.0.0.1; rm -rf /")

        assert result is True
        cmd = _nth_command(mock_thread, 0)
        assert cmd == ["iptables", "-A", "INPUT", "-s", "10.0.0.1; rm -rf /", "-j", "DROP"]
