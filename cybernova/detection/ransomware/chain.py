from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from cybernova.detection.ransomware.indicators import (
    HIGH_RISK_COMMANDS,
    RANSOMWARE_EXTENSIONS, RANSOMWARE_FILES,
    RANSOMWARE_PROCESS_INDICATORS,
)
from cybernova.detection.ransomware.stages import chain_manager

log = logging.getLogger("cybernova.detection.ransomware.chain")


class RansomwareDetectionChain:
    def analyze_event(self, event: Dict[str, Any], tenant_id: str) -> Optional[Dict[str, Any]]:
        entity_id = event.get("source_ip") or event.get("device_id") or event.get("hostname", "unknown")
        chain = chain_manager.get_or_create_chain(entity_id, tenant_id)

        indicator_names: List[str] = []
        evidence: Dict[str, Any] = {}
        etype = event.get("event_type", "")
        extra = event.get("extra_data", {}) or event.get("extra", {}) or {}
        event.get("message", "")
        file_path = extra.get("file", extra.get("path", ""))
        process_name = extra.get("process_name", extra.get("process", event.get("process_name", "")))
        command_line = extra.get("command_line", extra.get("cmd", ""))

        if etype == "process_created":
            proc_name_lower = process_name.lower()
            cmd_lower = command_line.lower()

            if proc_name_lower in RANSOMWARE_PROCESS_INDICATORS:
                for risk_cmd in HIGH_RISK_COMMANDS:
                    if risk_cmd in cmd_lower:
                        if "shadow" in cmd_lower or "vss" in cmd_lower:
                            indicator_names.append("shadow_copy_deletion")
                        elif "firewall" in cmd_lower:
                            indicator_names.append("firewall_disabled")
                        elif "windefend" in cmd_lower or "stop" in cmd_lower:
                            indicator_names.append("defense_disabled")
                        else:
                            indicator_names.append("suspicious_process")
                        evidence["process"] = proc_name_lower
                        evidence["command"] = cmd_lower[:200]
                        break

            if "powershell" in proc_name_lower and "-enc" in cmd_lower or "encodedcommand" in cmd_lower:
                indicator_names.append("encoded_powershell")
                evidence["encoded_cmd"] = True

        if etype == "file_changed" or etype == "file_create":
            path_lower = file_path.lower()
            ext = _get_extension(path_lower)
            name = _get_filename_stem(path_lower)

            if ext in RANSOMWARE_EXTENSIONS:
                indicator_names.append("ransomware_extension")
                evidence["extension"] = ext
                evidence["file"] = file_path

            for rw_file in RANSOMWARE_FILES:
                if rw_file in name:
                    indicator_names.append("ransomware_note")
                    evidence["note_file"] = file_path
                    break

        if etype == "file_deleted" or etype == "mass_deletion":
            indicator_names.append("backup_deletion")
            evidence["deletion_type"] = etype
            evidence["file"] = file_path

        if etype == "mass_file_change" or etype == "ransomware_encryption":
            indicator_names.append("mass_file_modification")
            evidence["change_count"] = extra.get("count", extra.get("change_count", 0))

        if etype == "c2_connection" or etype == "network_connection":
            indicator_names.append("c2_communication")
            evidence["dest_ip"] = extra.get("dest_ip", extra.get("remote_ip", ""))

        if etype == "data_exfil" or etype == "bulk_transfer":
            indicator_names.append("data_exfiltration")
            evidence["bytes"] = extra.get("bytes", 0)

        if etype == "lateral_movement":
            indicator_names.append("lateral_movement")
            evidence["target"] = extra.get("target", "")

        if etype == "file_rename":
            indicator_names.append("mass_file_rename")
            evidence["file"] = file_path

        if indicator_names:
            chain.fire_indicators(indicator_names)
            verdict = chain.get_verdict()
            log.info("Ransomware chain updated: %d indicators for %s, confidence=%.2f",
                     len(chain.all_indicators), entity_id, verdict["chain_result"]["confidence"])

            if verdict["chain_result"]["confidence"] >= 0.6:
                log.warning("Ransomware alert: %s — %s (confidence=%.2f)",
                            entity_id, verdict["chain_result"]["label"],
                            verdict["chain_result"]["confidence"])

            return verdict

        return None

    def get_active_chains(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return chain_manager.get_active_chains(tenant_id)

    def get_concluded_chains(self, tenant_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        return chain_manager.get_concluded_chains(tenant_id, limit)

    def get_chain(self, entity_id: str) -> Optional[Dict[str, Any]]:
        chain = chain_manager.get_chain(entity_id)
        return chain.get_verdict() if chain else None

    def conclude_chain(self, entity_id: str) -> Optional[Dict[str, Any]]:
        return chain_manager.conclude_chain(entity_id)

    def get_stats(self) -> Dict[str, Any]:
        return chain_manager.get_stats()


def _get_extension(path: str) -> str:
    idx = path.rfind(".")
    if idx >= 0:
        ext = path[idx:].lower()
        return ext
    return ""


def _get_filename_stem(path: str) -> str:
    path = path.replace("\\", "/")
    idx = path.rfind("/")
    if idx >= 0:
        filename = path[idx + 1:]
    else:
        filename = path
    dot_idx = filename.rfind(".")
    if dot_idx >= 0:
        return filename[:dot_idx].lower()
    return filename.lower()


ransomware_chain = RansomwareDetectionChain()
