"""
CyberNova — Syslog Receiver
Listens for syslog events over UDP/TCP.
Primary ingestion source for firewalls, routers, Linux servers.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, Optional, Callable

from cybernova.config.settings import get_settings

log = logging.getLogger("cybernova.ingestion.syslog")


class SyslogReceiver:
    """
    Async syslog server supporting both UDP and TCP.
    
    Usage:
        receiver = SyslogReceiver(on_event=my_handler)
        await receiver.start(host="0.0.0.0", port=5140)  # nosec - required for syslog network service
    """

    def __init__(
        self,
        on_event: Optional[Callable] = None,
        buffer_size: int = 4096,
    ):
        self.on_event = on_event
        self.buffer_size = buffer_size
        self._udp_socket: Optional[socket.socket] = None
        self._tcp_server: Optional[asyncio.Server] = None
        self._running = False
        self._tasks: set = set()

    async def start(
        self,
        host: str = "0.0.0.0",  # nosec - required for syslog network listener binding
        udp_port: int = 5140,
        tcp_port: int = 5141,
    ) -> None:
        """Start both UDP and TCP syslog listeners."""
        self._running = True
        settings = get_settings()

        udp_host = getattr(settings, 'syslog_udp_host', host)
        udp_port_cfg = getattr(settings, 'syslog_udp_port', udp_port)
        tcp_host = getattr(settings, 'syslog_tcp_host', host)
        tcp_port_cfg = getattr(settings, 'syslog_tcp_port', tcp_port)

        if getattr(settings, 'syslog_enabled', True):
            udp_task = asyncio.create_task(self._udp_listener(udp_host, udp_port_cfg))
            tcp_task = asyncio.create_task(self._tcp_listener(tcp_host, tcp_port_cfg))
            self._tasks.add(udp_task)
            self._tasks.add(tcp_task)
            log.info("Syslog receiver started: UDP=%s:%d TCP=%s:%d",
                     udp_host, udp_port_cfg, tcp_host, tcp_port_cfg)
        else:
            log.warning("Syslog receiver disabled in configuration")

    async def stop(self) -> None:
        """Stop the syslog receiver."""
        self._running = False
        if self._udp_socket:
            self._udp_socket.close()
        if self._tcp_server:
            self._tcp_server.close()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        log.info("Syslog receiver stopped")

    async def _udp_listener(self, host: str, port: int) -> None:
        """Listen for syslog messages over UDP."""
        try:
            self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp_socket.setblocking(False)
            self._udp_socket.bind((host, port))
            log.info("UDP syslog listener bound to %s:%d", host, port)
        except Exception as e:
            log.error("UDP syslog bind failed on %s:%d: %s", host, port, e)
            return

        loop = asyncio.get_event_loop()
        consecutive_errors = 0
        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self._udp_socket, self.buffer_size)
                consecutive_errors = 0
                if data:
                    message = self._parse_syslog_packet(data, addr)
                    await self._handle_message(message)
            except asyncio.CancelledError:
                break
            except Exception as e:
                consecutive_errors += 1
                if self._running:
                    if consecutive_errors <= 3:
                        log.warning("UDP syslog error (attempt %d): %s", consecutive_errors, e)
                    elif consecutive_errors == 4:
                        log.warning("UDP syslog: suppressing further error messages (still receiving)")
                    await asyncio.sleep(min(consecutive_errors, 30))

    async def _tcp_listener(self, host: str, port: int) -> None:
        """Listen for syslog messages over TCP with framing."""
        server = await asyncio.start_server(
            self._tcp_client_handler, host, port
        )
        self._tcp_server = server
        async with server:
            await server.serve_forever()

    async def _tcp_client_handler(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        log.debug("TCP syslog client connected: %s", addr)
        try:
            while self._running:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                    if not line:
                        break
                    message = self._parse_syslog_packet(line.strip(), addr)
                    await self._handle_message(message)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    log.error("TCP client error %s: %s", addr, e)
                    break
        finally:
            writer.close()
            await writer.wait_closed()

    def _parse_syslog_packet(self, data: bytes, addr: tuple) -> Dict[str, Any]:
        """Parse a syslog packet into structured event data."""
        try:
            raw = data.decode("utf-8", errors="replace").strip()
        except (UnicodeDecodeError, ValueError):
            raw = data.decode("latin-1", errors="replace").strip()

        result: Dict[str, Any] = {
            "source": "syslog",
            "source_type": "syslog",
            "raw": raw,
            "source_ip": str(addr[0]) if addr else "unknown",
            "message": raw,
            "event_type": "syslog",
            "severity": "info",
        }

        if raw.startswith("<"):
            end = raw.find(">")
            if end > 0:
                try:
                    pri = int(raw[1:end])
                    facility = pri >> 3
                    severity = pri & 0x07

                    sev_map = {
                        0: "critical", 1: "critical", 2: "critical",
                        3: "high", 4: "medium", 5: "low",
                        6: "info", 7: "debug",
                    }
                    result["severity"] = sev_map.get(severity, "info")
                    result["syslog_facility"] = facility
                    result["syslog_severity_code"] = severity
                    raw = raw[end + 1:].strip()
                except ValueError:
                    pass

        result["message"] = raw

        import re
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
        if len(ips) >= 1:
            result["source_ip"] = ips[0]
        if len(ips) >= 2:
            result["dest_ip"] = ips[1]

        auth_keywords = ["failed", "failure", "invalid", "denied", "refused",
                          "incorrect", "bad credentials", "authentication"]
        if any(kw in raw.lower() for kw in auth_keywords):
            result["event_type"] = "authentication_failure"
            if result.get("severity") in ("info", "debug"):
                result["severity"] = "high"

        ssh_match = re.search(r"sshd?[\[\d+\]]?:.*", raw, re.IGNORECASE)
        if ssh_match:
            result["event_type"] = "ssh_auth"
            if "failed" in raw.lower():
                result["event_type"] = "authentication_failure"

        if any(kw in raw.lower() for kw in ["malware", "virus", "trojan", "ransomware"]):
            result["event_type"] = "malware_detection"
            result["severity"] = "critical"

        return result

    async def _handle_message(self, message: Dict[str, Any]) -> None:
        """Process a parsed syslog message."""
        if self.on_event:
            try:
                result = self.on_event(message)
                if asyncio.iscoroutine(result):
                    await result
                log.debug("Syslog event processed: %s", message.get("event_type"))
            except Exception as e:
                log.error("Syslog event handler error: %s", e)
        else:
            log.debug("Syslog event received (no handler): %s", message.get("message", "")[:100])


# Global syslog receiver instance
syslog_receiver = SyslogReceiver()
