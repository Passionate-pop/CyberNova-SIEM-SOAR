from __future__ import annotations

import logging
from typing import Any, Dict

from cybernova.protection.network_shield import network_shield
from cybernova.protection.app_shield import app_shield
from cybernova.protection.process_shield import process_shield
from cybernova.protection.system_shield import system_shield
from cybernova.protection.user_shield import user_shield
from cybernova.protection.data_shield import data_shield
from cybernova.protection.resource_shield import resource_shield
from cybernova.protection.self_heal import self_heal
from cybernova.protection.waf import waf_engine
from cybernova.protection.webshell_hunter import webshell_hunter
from cybernova.protection.rootkit_detector import rootkit_detector
from cybernova.protection.tamper_guard import tamper_guard
from cybernova.protection.cryptojacking import cryptojacking_detector
from cybernova.protection.dlp import dlp_engine, scan_event as dlp_scan_event
from cybernova.protection.config_sentinel import config_sentinel
from cybernova.protection.brute_force_mesh import brute_force_mesh, analyze_event as bf_analyze_event
from cybernova.protection.phishing_trap import phishing_trap

log = logging.getLogger("cybernova.protection.engine")

SHIELD_MODULES = [
    "network_shield", "app_shield", "process_shield", "system_shield",
    "user_shield", "data_shield", "resource_shield", "self_heal",
    "waf", "webshell", "rootkit", "tamper", "cryptojacking",
    "dlp", "config_audit", "brute_force", "phishing",
]

EVENT_TYPE_MAP: Dict[str, str] = {
    "network_shield": "network_attack_detected",
    "app_shield": "application_attack_detected",
    "process_shield": "process_attack_detected",
    "system_shield": "system_misconfiguration_detected",
    "user_shield": "social_engineering_detected",
    "data_shield": "data_threat_detected",
    "resource_shield": "resource_abuse_detected",
    "self_heal": "self_heal_action",
    "waf": "waf_block",
    "webshell": "webshell_detected",
    "rootkit": "rootkit_detected",
    "tamper": "tamper_detected",
    "cryptojacking": "cryptominer_detected",
    "dlp": "dlp_leak_detected",
    "config_audit": "misconfiguration_found",
    "brute_force": "brute_force_detected",
    "phishing": "phishing_detected",
}

MODULE_RISK_MAP: Dict[str, float] = {
    "process_shield": 5, "data_shield": 5, "self_heal": 5,
    "waf": 5, "webshell": 5, "rootkit": 5, "tamper": 5,
    "cryptojacking": 10, "dlp": 10, "config_audit": 0,
    "brute_force": 10, "phishing": 15, "network_shield": 5,
    "app_shield": 10, "system_shield": 0, "user_shield": 15,
    "resource_shield": 10,
}


class PreventionEngine:
    def __init__(self):
        self.enabled_modules: set = set(SHIELD_MODULES)
        self._shield_modules = {
            "network_shield": network_shield,
            "app_shield": app_shield,
            "process_shield": process_shield,
            "system_shield": system_shield,
            "user_shield": user_shield,
            "data_shield": data_shield,
            "resource_shield": resource_shield,
            "self_heal": self_heal,
        }
        self._legacy_modules = {
            "waf": waf_engine,
            "webshell": webshell_hunter,
            "rootkit": rootkit_detector,
            "tamper": tamper_guard,
            "cryptojacking": cryptojacking_detector,
            "dlp": dlp_engine,
            "config_audit": config_sentinel,
            "brute_force": brute_force_mesh,
            "phishing": phishing_trap,
        }

    def enable(self, *modules: str):
        for m in modules:
            if m in SHIELD_MODULES:
                self.enabled_modules.add(m)

    def disable(self, *modules: str):
        for m in modules:
            self.enabled_modules.discard(m)

    async def analyze_event(self, event: dict) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "threat_detected": False,
            "threats": [],
            "max_risk_score": 0.0,
            "modules_run": [],
        }

        for name, module in self._shield_modules.items():
            if name not in self.enabled_modules:
                continue
            etype = event.get("event_type", "")
            shield_triggers = {
                "network_shield": ("suricata_alert", "dns_query", "dns_request", "flow", "netflow", "connection"),
                "app_shield": ("http_request", "suricata_alert", "web_request", "api_request"),
                "process_shield": ("new_process", "agent_telemetry", "system_check", "process_telemetry", "memory_alert"),
                "system_shield": ("system_check", "agent_heartbeat", "config_audit_request", "new_process", "selinux_event"),
                "user_shield": ("http_request", "web_request", "email_event", "email_received", "failed_login", "login_failure", "authentication_failure"),
                "data_shield": ("file_changed", "file_deleted", "file_remove", "file_rename", "dlp_leak_detected", "data_transfer", "large_upload", "bulk_transfer", "registry_changed", "shadow_copy_event"),
                "resource_shield": ("system_check", "process_event", "process_telemetry", "http_request"),
                "self_heal": ("agent_heartbeat", "system_check", "tamper_detected", "rootkit_detected", "platform_compromised"),
            }
            triggers = shield_triggers.get(name, ())
            if not triggers or etype in triggers:
                try:
                    result = module.analyze_event(event)
                    if result and result.get("threat_detected"):
                        mapped = EVENT_TYPE_MAP.get(name, f"{name}_alert")
                        for finding in result.get("findings", []):
                            risk = finding.get("risk_score", 60)
                            results["threats"].append({
                                "module": name, "event_type": mapped,
                                "risk_score": risk,
                                "message": finding.get("message", f"{name} detected threat"),
                                "finding": finding,
                            })
                            results["max_risk_score"] = max(results["max_risk_score"], risk)
                            results["threat_detected"] = True
                    results["modules_run"].append(name)
                except Exception as e:
                    log.warning("Shield module %s error: %s", name, e)

        for name, module_fn in self._legacy_modules.items():
            if name not in self.enabled_modules:
                continue
            try:
                if name == "waf":
                    result = waf_engine.analyze_event(event)
                elif name == "dlp":
                    result = dlp_scan_event(event)
                elif name == "brute_force":
                    result = bf_analyze_event(event)
                elif name == "rootkit":
                    if event.get("event_type") in ("agent_telemetry", "system_check"):
                        result = module_fn()
                    else:
                        continue
                elif name == "tamper":
                    if event.get("event_type") in ("agent_heartbeat", "system_check"):
                        result = module_fn()
                    else:
                        continue
                elif name == "cryptojacking":
                    if event.get("event_type") in ("system_check", "process_event"):
                        result = module_fn()
                    else:
                        continue
                elif name == "phishing":
                    extra = event.get("extra_data") or event.get("extra", {})
                    url = extra.get("url", extra.get("hostname", ""))
                    result = module_fn(url) if url else None
                elif name == "config_audit":
                    if event.get("event_type") == "config_audit_request":
                        result = module_fn()
                    else:
                        continue
                elif name == "webshell":
                    if event.get("event_type") in ("file_scanned", "suspicious_file"):
                        result = module_fn(event)
                    else:
                        continue
                else:
                    continue
                if isinstance(result, dict) and result.get("threat_detected" if name != "rootkit" else "rootkit_detected"):
                    mapped = EVENT_TYPE_MAP.get(name, f"{name}_alert")
                    risk = result.get("max_risk_score", 70)
                    results["threats"].append({
                        "module": name, "event_type": mapped,
                        "risk_score": risk,
                        "message": result.get("findings", [{}])[0].get("message", f"{name} detected") if result.get("findings") else f"{name} detected",
                        "finding": result,
                    })
                    results["max_risk_score"] = max(results["max_risk_score"], risk)
                    results["threat_detected"] = True
                results["modules_run"].append(name)
            except Exception as e:
                log.warning("Legacy module %s error: %s", name, e)

        return results

    async def full_system_scan(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {"scan_complete": True, "modules": {}}
        from cybernova.protection.rootkit_detector import rootkit_detector as rk_fn
        from cybernova.protection.tamper_guard import tamper_guard as tg_fn
        from cybernova.protection.cryptojacking import cryptojacking_detector as cj_fn
        from cybernova.protection.config_sentinel import config_sentinel as cs_fn
        results["modules"]["rootkit"] = rk_fn()
        results["modules"]["tamper"] = tg_fn()
        results["modules"]["cryptojacking"] = cj_fn()
        results["modules"]["config_audit"] = cs_fn()
        results["threat_detected"] = any(
            m.get("rootkit_detected") or m.get("tamper_detected") or
            m.get("cryptominer_detected") or m.get("failed", 0) > 0
            for m in results["modules"].values()
        )
        return results


prevention_engine = PreventionEngine()
