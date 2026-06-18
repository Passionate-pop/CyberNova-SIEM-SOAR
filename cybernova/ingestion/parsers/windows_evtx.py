"""
CyberNova — Windows Event Log Parser (EVTX)
Parses Windows Security Event Log events from XML or structured JSON.
Maps Event IDs to standardized event_type strings for detection rules.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

log = logging.getLogger("cybernova.ingestion.parsers.windows_evtx")

SECURITY_EVENT_IDS = {
    4624: "successful_login",
    4625: "failed_login",
    4634: "logoff",
    4647: "logoff",
    4648: "explicit_credential",
    4672: "special_privilege",
    4688: "new_process",
    4698: "scheduled_task",
    4700: "scheduled_task",
    4702: "scheduled_task",
    4720: "user_created",
    4722: "user_enabled",
    4723: "password_change",
    4724: "password_reset",
    4725: "user_disabled",
    4726: "user_deleted",
    4728: "member_added",
    4729: "member_removed",
    4732: "member_added",
    4733: "member_removed",
    4740: "account_lockout",
    4768: "kerberos_ticket",
    4769: "kerberos_service",
    4771: "kerberos_failed",
    4776: "credential_validation",
    4798: "user_group_enum",
    4799: "user_group_enum",
    4800: "lock_screen",
    4801: "unlock_screen",
    5140: "share_access",
    5145: "share_access",
    5156: "connection_made",
    5157: "connection_blocked",
    7045: "service_installed",
}

LOGON_TYPE_MAP = {
    "2": "interactive", "3": "network", "4": "batch", "5": "service",
    "7": "unlock", "8": "network_cleartext", "9": "new_credentials",
    "10": "remote_interactive", "11": "cached_interactive",
}

EVENT_TYPE_TO_MITRE = {
    "successful_login": {"tactic": "TA0006", "technique": "T1078"},
    "failed_login": {"tactic": "TA0006", "technique": "T1110"},
    "explicit_credential": {"tactic": "TA0006", "technique": "T1552"},
    "special_privilege": {"tactic": "TA0004", "technique": "T1068"},
    "new_process": {"tactic": "TA0002", "technique": "T1059"},
    "scheduled_task": {"tactic": "TA0003", "technique": "T1053.005"},
    "user_created": {"tactic": "TA0003", "technique": "T1136"},
    "user_disabled": {"tactic": "TA0040", "technique": "T1531"},
    "member_added": {"tactic": "TA0003", "technique": "T1098"},
    "account_lockout": {"tactic": "TA0006", "technique": "T1110"},
    "service_installed": {"tactic": "TA0003", "technique": "T1543.003"},
    "kerberos_ticket": {"tactic": "TA0006", "technique": "T1558"},
    "kerberos_failed": {"tactic": "TA0006", "technique": "T1558"},
    "connection_made": {"tactic": "TA0009", "technique": "T1071"},
    "connection_blocked": {"tactic": "TA0040", "technique": "T1562"},
}


def parse_event_xml(xml_str: str) -> Optional[Dict[str, Any]]:
    try:
        import defusedxml.ElementTree as ET
        root = ET.fromstring(xml_str)

        ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
        system = root.find("ns:System", ns) or root.find("System")
        event_data = root.find("ns:EventData", ns) or root.find("EventData")
        user_data = root.find("ns:UserData", ns) or root.find("UserData")

        result: Dict[str, Any] = {"event_type": "unknown", "severity": "info"}

        if system is not None:
            _extract_system_xml(system, result)

        if event_data is not None:
            _extract_event_data_xml(event_data, result)
        elif user_data is not None:
            _extract_event_data_xml(user_data, result)

        return result
    except Exception as e:
        log.debug("XML parse failed: %s — trying regex", e)
        return None


def _extract_system_xml(system, result: Dict[str, Any]) -> None:
    for child in system:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if tag == "EventID":
            try:
                eid = int((child.text or "").strip())
                result["event_id"] = eid
                result["event_type"] = SECURITY_EVENT_IDS.get(eid, f"windows_{eid}")
                if eid in (4624, 4625, 4648, 4776):
                    result["severity"] = "medium" if eid == 4625 else "low"
                elif eid in (4672, 4720, 4725, 4726, 4740, 7045):
                    result["severity"] = "high"
                elif eid in (4688, 4698):
                    result["severity"] = "low"
                qualifiers = child.get("Qualifiers", "")
                if qualifiers:
                    result["metadata"]["event_id_qualifiers"] = qualifiers
            except (ValueError, TypeError):
                pass
        elif tag in ("Computer", "ComputerName"):
            result["hostname"] = (child.text or "").strip()
        elif tag == "TimeCreated":
            ts = child.get("SystemTime", "")
            if ts:
                result["timestamp"] = ts
        elif tag == "Keywords":
            result["keywords"] = child.text
        elif tag == "Channel":
            channel = (child.text or "").strip()
            result["channel"] = channel
            if channel == "ForwardedEvents":
                result["event_source"] = "wef_forwarded"
                result["metadata"]["channel"] = channel
            elif channel:
                result["metadata"]["channel"] = channel
        elif tag == "EventRecordID":
            try:
                result["event_record_id"] = int((child.text or "").strip())
            except (ValueError, TypeError):
                pass
        elif tag == "Level":
            try:
                result["metadata"]["level"] = int((child.text or "").strip())
            except (ValueError, TypeError):
                pass
        elif tag == "Task":
            try:
                result["metadata"]["task"] = int((child.text or "").strip())
            except (ValueError, TypeError):
                pass
        elif tag == "Opcode":
            val = (child.text or "").strip()
            if val:
                result["metadata"]["opcode"] = val
        elif tag == "Version":
            val = (child.text or "").strip()
            if val:
                try:
                    result["metadata"]["event_version"] = int(val)
                except (ValueError, TypeError):
                    result["metadata"]["event_version"] = val
        elif tag == "Execution":
            proc_id = child.get("ProcessID", "")
            thread_id = child.get("ThreadID", "")
            if proc_id:
                result["metadata"]["process_id"] = proc_id
            if thread_id:
                result["metadata"]["thread_id"] = thread_id


def _extract_event_data_xml(data_elem, result: Dict[str, Any]) -> None:
    result["metadata"] = {}
    for child in data_elem:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        if tag == "Data":
            name = child.get("Name", "")
            text = (child.text or "").strip()
            if not name:
                continue
            result["metadata"][name] = text
            _map_data_field(name, text, result)
        elif tag == "Attribute":
            name = child.get("name", "") or child.get("Name", "")
            text = (child.text or "").strip()
            if name:
                result["metadata"][name] = text
                _map_data_field(name, text, result)


def _map_data_field(name: str, value: str, result: Dict[str, Any]) -> None:
    lower = name.lower()
    if lower in ("targetusername", "accountname", "user", "subjectusername"):
        result["user"] = value
    elif lower in ("targetdomainname", "domainname", "subjectdomainname"):
        result["domain"] = value
    elif lower in ("ipaddress", "sourceipaddress", "clientip"):
        result["source_ip"] = value
    elif lower in ("workstationname", "workstation", "clientname"):
        result.get("metadata", {})["workstation"] = value
    elif lower in ("processid", "newprocessid"):
        try:
            result["metadata"]["process_id"] = int(value)
        except ValueError:
            pass
    elif lower in ("processname", "newprocessname", "imagepath"):
        result["metadata"]["process_name"] = value
        if "\\" in value:
            exe = value.rsplit("\\", 1)[-1]
            if exe.lower() in ("powershell.exe", "cmd.exe", "wscript.exe",
                                "cscript.exe", "rundll32.exe", "regsvr32.exe",
                                "mshta.exe", "certutil.exe", "bitsadmin.exe"):
                result["severity"] = "medium"
    elif lower in ("servicename", "service"):
        result["metadata"]["service_name"] = value
    elif lower in ("servicetype",):
        # Service type logged in metadata but doesn't need special mapping
        pass
    elif lower in ("logontype",):
        result["metadata"]["logon_type"] = value
        result["logon_type"] = LOGON_TYPE_MAP.get(value, value)
    elif lower in ("targetlogonid", "logonid"):
        result["metadata"]["logon_id"] = value
    elif lower in ("objectname",):
        # Object name stored in metadata for auditing — no special mapping needed
        pass
    elif value.startswith("S-1-"):
        result["metadata"]["sid"] = value
        if value.endswith("-500"):
            result["severity"] = "high"
    elif lower == "targetsid":
        result["metadata"]["target_sid"] = value


def parse_event_json(json_data: Dict[str, Any]) -> Dict[str, Any]:
    eid_raw = json_data.get("EventID") or json_data.get("event_id") or json_data.get("Id", 0)
    try:
        eid = int(eid_raw)
    except (ValueError, TypeError):
        eid = 0

    result: Dict[str, Any] = {
        "event_id": eid,
        "event_type": SECURITY_EVENT_IDS.get(eid, f"windows_{eid}"),
        "severity": "info",
        "metadata": {},
    }

    if eid in (4624, 4625, 4648, 4776):
        result["severity"] = "medium" if eid == 4625 else "low"
    elif eid in (4672, 4720, 4725, 4726, 4740, 7045):
        result["severity"] = "high"
    elif eid in (4688, 4698):
        result["severity"] = "low"

    provider = json_data.get("Provider", {})
    if isinstance(provider, dict):
        result["provider"] = provider.get("Name", "")

    system = json_data.get("System", {})
    if isinstance(system, dict):
        result["hostname"] = system.get("Computer", "")
        ts = system.get("TimeCreated", "")
        if ts:
            result["timestamp"] = ts
        keywords = system.get("Keywords", "")
        if keywords:
            result["keywords"] = keywords

    event_data = json_data.get("EventData", {}) or json_data.get("UserData", {})
    if isinstance(event_data, dict):
        for key, value in event_data.items():
            if isinstance(value, str):
                _map_data_field(key, value, result)
            elif isinstance(value, dict) and "#text" in value:
                _map_data_field(key, value["#text"], result)
        if event_data.get("Data") and isinstance(event_data.get("Data"), list):
            for item in event_data["Data"]:
                if isinstance(item, dict):
                    _map_data_field(
                        item.get("Name", "") or item.get("name", ""),
                        item.get("#text", "") or str(item.get("value", "")),
                        result,
                    )

    _extract_logon_type(result)

    mitre = EVENT_TYPE_TO_MITRE.get(result.get("event_type", ""))
    if mitre:
        result["mitre_tactic"] = mitre["tactic"]
        result["mitre_technique"] = mitre["technique"]

    return result


def _extract_logon_type(result: Dict[str, Any]) -> None:
    logon_type_val = result.get("metadata", {}).get("logon_type", "")
    if logon_type_val and logon_type_val in LOGON_TYPE_MAP:
        result["logon_type"] = LOGON_TYPE_MAP[logon_type_val]


def _parse_xml_via_regex(raw: str) -> Optional[Dict[str, Any]]:
    result: Dict[str, Any] = {"event_type": "unknown", "severity": "info", "metadata": {}}

    eid_m = re.search(r"<EventID[^>]*>(\d+)</EventID>", raw)
    if eid_m:
        eid = int(eid_m.group(1))
        result["event_id"] = eid
        result["event_type"] = SECURITY_EVENT_IDS.get(eid, f"windows_{eid}")
        if eid == 4625:
            result["severity"] = "medium"
        elif eid in (4672, 4720, 4725, 4726, 4740, 7045):
            result["severity"] = "high"

    comp_m = re.search(r"<Computer[^>]*>(.*?)</Computer>", raw)
    if comp_m:
        result["hostname"] = comp_m.group(1).strip()

    ts_m = re.search(r'SystemTime=["\']([^"\']+)["\']', raw)
    if ts_m:
        result["timestamp"] = ts_m.group(1)

    data_pairs = re.findall(r'<Data\s+Name=["\']([^"\']+)["\']>([^<]*)</Data>', raw)
    for name, value in data_pairs:
        result["metadata"][name] = value
        _map_data_field(name, value.strip(), result)

    _extract_logon_type(result)

    mitre = EVENT_TYPE_TO_MITRE.get(result.get("event_type", ""))
    if mitre:
        result["mitre_tactic"] = mitre["tactic"]
        result["mitre_technique"] = mitre["technique"]

    return result


def _parse_wef_batch_xml(xml_str: str) -> Optional[Dict[str, Any]]:
    """Parse WEF batched XML (<Events> wrapping multiple <Event>)."""
    try:
        import defusedxml.ElementTree as ET
        root = ET.fromstring(xml_str)
    except Exception as exc:
        log.debug("WEF batch XML parse failed: %s", exc)
        return None

    tag = root.tag.split("}")[-1] if "}" in root.tag else root.tag
    if tag != "Events":
        return None

    ns = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}
    result_list = []
    for event_elem in root:
        etag = event_elem.tag.split("}")[-1] if "}" in event_elem.tag else event_elem.tag
        if etag != "Event":
            continue
        system = event_elem.find("ns:System", ns) or event_elem.find("System")
        event_data = event_elem.find("ns:EventData", ns) or event_elem.find("EventData")
        user_data = event_elem.find("ns:UserData", ns) or event_elem.find("UserData")

        result: Dict[str, Any] = {"event_type": "unknown", "severity": "info"}
        if system is not None:
            _extract_system_xml(system, result)
        if event_data is not None:
            _extract_event_data_xml(event_data, result)
        elif user_data is not None:
            _extract_event_data_xml(user_data, result)
        if result.get("event_id"):
            result["event_source"] = "wef_batch"
            result_list.append(result)

    if len(result_list) == 1:
        return result_list[0]
    if len(result_list) > 1:
        return {
            "event_type": "windows_event_batch",
            "severity": "info",
            "batch_count": len(result_list),
            "events": result_list,
            "message": f"WEF batch with {len(result_list)} forwarded events",
        }
    return None


def _parse_wef_json(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Parse WEF JSON format that embeds EventXml as a string."""
    event_xml = raw.get("EventXml", raw.get("event_xml", raw.get("ForwardedEvent", "")))
    if not event_xml or not isinstance(event_xml, str) or not event_xml.strip().startswith("<"):
        return None

    result = parse_event_xml(event_xml.strip())
    if result is None:
        result = _parse_xml_via_regex(event_xml.strip())
    if not result or not result.get("event_id"):
        return None

    result["event_source"] = "wef_forwarded"

    collector = raw.get("EventCollectorName", raw.get("event_collector_name", raw.get("CollectorName", "")))
    if collector:
        result["wef_collector"] = collector

    delivery = raw.get("EventDeliveryTime", raw.get("event_delivery_time", raw.get("DeliveryTime", "")))
    if delivery:
        result["wef_delivery_time"] = delivery

    schema = raw.get("EventSchema", raw.get("event_schema", ""))
    if schema:
        result["wef_schema"] = schema

    result["message"] = f"WEF forwarded event {result.get('event_id', 'unknown')} from {result.get('hostname', 'unknown')} via {collector or 'unknown'}"
    return result


def _detect_wef_format(raw: Dict[str, Any]) -> bool:
    """Check if a JSON dict is a WEF forwarded event wrapper."""
    set(raw.keys())
    has_event_xml = bool(raw.get("EventXml") or raw.get("event_xml") or raw.get("ForwardedEvent"))
    has_collector = bool(raw.get("EventCollectorName") or raw.get("event_collector_name") or raw.get("CollectorName"))
    has_delivery = bool(raw.get("EventDeliveryTime") or raw.get("event_delivery_time") or raw.get("DeliveryTime"))
    return has_event_xml or (has_collector and has_delivery)


def parse_windows_event(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        if _detect_wef_format(raw):
            wef_result = _parse_wef_json(raw)
            if wef_result is not None:
                return wef_result
        return parse_event_json(raw)

    if isinstance(raw, str):
        raw = raw.strip()

        if raw.startswith("<") and raw.endswith(">"):
            wef_batch = _parse_wef_batch_xml(raw)
            if wef_batch is not None:
                return wef_batch
            result = parse_event_xml(raw)
            if result is not None:
                return result
            result = _parse_xml_via_regex(raw)
            if result.get("event_id"):
                return result

        import json as _json
        try:
            parsed = _json.loads(raw)
            return parse_windows_event(parsed)
        except (ValueError, _json.JSONDecodeError):
            pass

    return {
        "event_type": "windows_event",
        "severity": "info",
        "message": str(raw),
        "metadata": {"raw": raw} if isinstance(raw, str) else {},
    }


PARSER_REGISTRY_KEY = "windows_evtx"
