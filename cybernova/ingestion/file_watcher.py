"""
CyberNova — Log File Watcher
Tails log files in real-time and sends events to the ingestion pipeline.
Supports: /var/log/auth.log, /var/log/syslog, Windows Event Log exports, JSON logs.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Callable

log = logging.getLogger("cybernova.ingestion.filewatcher")


class LogFileWatcher:
    """
    Real-time log file tailer using inotify/FSEvents/win32file.
    Detects new lines appended to log files and emits structured events.
    
    Usage:
        watcher = LogFileWatcher(on_events=my_pipeline.ingest_events)
        await watcher.add_file("/var/log/auth.log", source="linux_auth")
        await watcher.add_file("/var/log/syslog", source="linux_syslog")
        await watcher.start()
    """

    def __init__(self, on_events: Optional[Callable] = None):
        self.on_events = on_events
        self._files: Dict[str, Dict[str, Any]] = {}
        self._running = False
        self._tasks: set = set()
        self._is_windows = os.name == "nt"

    async def start(self) -> None:
        """Start watching all registered files."""
        self._running = True
        for file_path, config in self._files.items():
            task = asyncio.create_task(self._tail_file(file_path, config))
            self._tasks.add(task)
        log.info("Log file watcher started: watching %d files", len(self._files))

    async def stop(self) -> None:
        """Stop all file watchers."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        log.info("Log file watcher stopped")

    def add_file(self, path: str, source: str = "log_file",
                 source_type: str = "log", parser: str = "auto") -> None:
        """Register a file to watch."""
        if not os.path.exists(path):
            log.warning("Log file does not exist (will retry): %s", path)
        self._files[path] = {
            "source": source,
            "source_type": source_type,
            "parser": parser,
            "position": 0,
            "last_modified": 0,
        }
        log.info("Registered log file: %s (source=%s)", path, source)

    async def _tail_file(self, path: str, config: Dict[str, Any]) -> None:
        """Tail a single file, watching for new lines."""
        source = config["source"]
        source_type = config["source_type"]
        parser = config["parser"]
        position = config["position"]
        last_modified = config["last_modified"]

        while self._running:
            try:
                if not os.path.exists(path):
                    await asyncio.sleep(5)
                    continue

                stat = os.stat(path)
                current_mtime = stat.st_mtime

                if current_mtime != last_modified:
                    if current_mtime < last_modified:
                        position = 0

                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(position)
                        new_lines = f.readlines()
                        position = f.tell()
                        last_modified = current_mtime

                    config["position"] = position
                    config["last_modified"] = last_modified

                    if new_lines:
                        events = self._parse_lines(new_lines, source, source_type, parser)
                        if events and self.on_events:
                            for event in events:
                                try:
                                    await self.on_events(
                                        source=source,
                                        source_type=source_type,
                                        events=[event],
                                        tenant_id="default",
                                    )
                                except Exception as e:
                                    log.error("File watcher event dispatch failed: %s", e)

                await asyncio.sleep(0.5)

            except FileNotFoundError:
                await asyncio.sleep(5)
            except Exception as e:
                log.error("File tail error for %s: %s", path, e)
                await asyncio.sleep(1)

    def _parse_lines(
        self, lines: List[str], source: str, source_type: str, parser: str
    ) -> List[Dict[str, Any]]:
        """Parse raw log lines into structured events."""
        events = []
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if parser == "json" or line.startswith("{"):
                event = self._parse_json_line(line)
            elif parser == "syslog" or self._is_syslog_line(line):
                event = self._parse_syslog_line(line, source)
            else:
                event = self._parse_generic_line(line, source)

            if event:
                events.append(event)

        return events

    def _is_syslog_line(self, line: str) -> bool:
        """Heuristic: syslog lines start with timestamp or priority."""
        return bool(
            re.match(r"^<\d+>|^\w{3}\s+\d+\s+\d+:\d+:\d+", line)
        )

    def _parse_syslog_line(self, line: str, source: str) -> Dict[str, Any]:
        """Parse a syslog-formatted line."""
        severity = "info"
        event_type = "syslog"

        if "failed" in line.lower() or "failure" in line.lower():
            severity = "high"
            event_type = "authentication_failure"
        if "error" in line.lower() or "crit" in line.lower():
            severity = "critical"
        if "warning" in line.lower() or "warn" in line.lower():
            severity = "medium"

        if "ssh" in line.lower():
            event_type = "ssh_auth"
        if "sudo" in line.lower():
            event_type = "privilege_change"
        if "malware" in line.lower() or "virus" in line.lower():
            event_type = "malware_detection"
            severity = "critical"

        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        source_ip = ips[0] if ips else ""
        dest_ip = ips[1] if len(ips) > 1 else ""

        return {
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "source_type": "syslog",
            "message": line,
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _parse_json_line(self, line: str) -> Dict[str, Any]:
        """Parse a JSON-formatted log line."""
        import json
        try:
            data = json.loads(line)
            return {
                "event_type": data.get("event_type") or data.get("type") or "log",
                "severity": data.get("severity") or data.get("level") or "info",
                "source_ip": data.get("source_ip") or data.get("src_ip") or "",
                "dest_ip": data.get("dest_ip") or data.get("dst_ip") or "",
                "user": data.get("user") or data.get("username") or "",
                "message": data.get("message") or data.get("msg") or line,
                "timestamp": data.get("timestamp") or data.get("time") or "",
                "metadata": {k: v for k, v in data.items()
                             if k not in ("event_type", "severity", "source_ip",
                                          "dest_ip", "message", "timestamp")},
            }
        except json.JSONDecodeError:
            return self._parse_generic_line(line, "json_log")

    def _parse_generic_line(self, line: str, source: str) -> Dict[str, Any]:
        """Parse a generic log line using heuristics."""
        severity = "info"
        event_type = "log"

        keywords = {
            "critical": ["critical", "fatal", "panic"],
            "high": ["error", "fail", "denied", "refused", "unauthorized"],
            "medium": ["warning", "warn"],
        }
        for sev, kws in keywords.items():
            if any(kw in line.lower() for kw in kws):
                severity = sev
                break

        auth_keywords = ["login", "auth", "password", "credential", "session"]
        if any(kw in line.lower() for kw in auth_keywords):
            event_type = "authentication"

        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        return {
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "source_type": "log",
            "message": line,
            "source_ip": ips[0] if ips else "",
            "dest_ip": ips[1] if len(ips) > 1 else "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Global log file watcher
file_watcher = LogFileWatcher()
