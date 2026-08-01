from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SystemInfo(BaseModel):
    hostname: str
    os_type: str
    os_version: str
    ip_addresses: List[str] = Field(default_factory=list)
    mac_addresses: List[str] = Field(default_factory=list)
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    boot_time: Optional[str] = None
    kernel_version: str = ""
    agent_version: str = "1.0.0"

    model_config = {"extra": "allow"}


class ProcessEvent(BaseModel):
    pid: int
    name: str
    command_line: str = ""
    user: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    connections: int = 0
    parent_pid: Optional[int] = None
    parent_name: str = ""
    md5_hash: str = ""
    sha256_hash: str = ""
    path: str = ""
    start_time: Optional[str] = None
    event_type: str = "process_running"

    model_config = {"extra": "allow"}


class NetworkConnection(BaseModel):
    pid: Optional[int] = None
    process_name: str = ""
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    protocol: str = "tcp"
    state: str = "established"
    bytes_sent: int = 0
    bytes_received: int = 0
    domain_name: str = ""
    created_at: str = ""

    model_config = {"extra": "allow"}


class FileEvent(BaseModel):
    path: str
    name: str = ""
    action: str
    size: int = 0
    md5_hash: str = ""
    sha256_hash: str = ""
    permissions: str = ""
    owner: str = ""
    previous_hash: str = ""
    process_pid: Optional[int] = None
    process_name: str = ""

    model_config = {"extra": "allow"}


class SecurityEvent(BaseModel):
    event_type: str
    message: str
    severity: str = "medium"
    source: str = "agent"
    timestamp: str = ""
    process_pid: Optional[int] = None
    process_name: str = ""
    registry_key: str = ""
    registry_value: str = ""
    rule_name: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    raw_data: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class TelemetryBatch(BaseModel):
    system: Optional[SystemInfo] = None
    processes: List[ProcessEvent] = Field(default_factory=list)
    connections: List[NetworkConnection] = Field(default_factory=list)
    file_events: List[FileEvent] = Field(default_factory=list)
    security_events: List[SecurityEvent] = Field(default_factory=list)
    heartbeat_interval: int = 30
    sequence_number: int = 0
    timestamp: str = ""

    model_config = {"extra": "allow"}


class AgentConfiguration(BaseModel):
    heartbeat_interval: int = 30
    collect_processes: bool = True
    collect_connections: bool = True
    collect_file_events: bool = True
    collect_security_events: bool = True
    process_whitelist: List[str] = Field(default_factory=list)
    connection_whitelist: List[str] = Field(default_factory=list)
    file_watch_paths: List[str] = Field(default_factory=list)
    log_level: str = "info"
    block_actions_enabled: bool = False
    agent_version: str = "1.0.0"
    config_version: int = 1
    updated_at: str = ""

    model_config = {"extra": "allow"}
