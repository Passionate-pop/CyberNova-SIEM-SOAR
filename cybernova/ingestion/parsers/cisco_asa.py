"""
CyberNova — Cisco ASA Firewall Log Parser
Parses ASA syslog messages by message ID.
Handles 106100/106101 (ACL hits), 302013/302014 (conn build/teardown),
304001 (URL access), 305011/305012 (NAT), 419002 (failover), 733100 (VPN).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

log = logging.getLogger("cybernova.ingestion.parsers.cisco_asa")

ASA_MSG_RE = re.compile(
    r'%ASA-(?P<severity>\d)-(?P<msg_id>\d{6}):\s*(?P<message>.*)'
)

SEVERITY_MAP = {
    "0": "emergency", "1": "alert", "2": "critical",
    "3": "error", "4": "warning", "5": "notice",
    "6": "informational", "7": "debug",
}

# 106100: permit/deny with access-list hit
# %ASA-4-106100: access-list INSIDE_OUT permitted tcp inside/10.0.0.1(12345) -> outside/1.2.3.4(80) hit-cnt 1
MSG_106100_RE = re.compile(
    r'access-list\s+(?P<acl_name>\S+)\s+(?P<action>permitted|denied|deny)\s+'
    r'(?P<protocol>\w+)\s+'
    r'(?P<src_iface>\S+)/(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?:\((?P<src_port>\d+)\))?\s+->\s+'
    r'(?P<dst_iface>\S+)/(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?:\((?P<dst_port>\d+)\))?'
    r'(?:\s+hit-cnt\s+(?P<hit_count>\d+))?'
)

# 106101: deny (without access-list name sometimes)
# %ASA-4-106101: access-list inside_acl denied tcp inside/10.0.0.1(49152) -> outside/1.2.3.4(443)
MSG_106101_RE = re.compile(
    r'access-list\s+(?P<acl_name>\S+)\s+(?:permitted|denied|deny)\s+'
    r'(?P<protocol>\w+)\s+'
    r'(?P<src_iface>\S+)/(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?:\((?P<src_port>\d+)\))?\s+->\s+'
    r'(?P<dst_iface>\S+)/(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?:\((?P<dst_port>\d+)\))?'
)

# 302013: Built connection
# %ASA-6-302013: Built inbound TCP connection 12345 for outside:1.2.3.4/80 (1.2.3.4/80) to inside:10.0.0.1/12345 (10.0.0.1/12345)
MSG_302013_RE = re.compile(
    r'Built\s+(?P<direction>inbound|outbound)\s+'
    r'(?P<protocol>\w+)\s+'
    r'connection\s+(?P<conn_id>\d+)\s+'
    r'for\s+(?P<src_iface>\S+):(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'/(?P<src_port>\d+)\s*(?:\([^)]+\))?\s+'
    r'to\s+(?P<dst_iface>\S+):(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'/(?P<dst_port>\d+)\s*(?:\([^)]+\))?'
)

# 302014: Teardown connection
# %ASA-6-302014: Teardown TCP connection 12345 for outside:1.2.3.4/80 to inside:10.0.0.1/12345 duration 0:00:30 bytes 500
MSG_302014_RE = re.compile(
    r'Teardown\s+(?P<protocol>\w+)\s+'
    r'connection\s+(?P<conn_id>\d+)\s+'
    r'for\s+(?P<src_iface>\S+):(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'/(?P<src_port>\d+)\s+'
    r'to\s+(?P<dst_iface>\S+):(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'/(?P<dst_port>\d+)'
    r'(?:\s+duration\s+(?P<duration_str>\S+))?'
    r'(?:\s+bytes\s+(?P<bytes>\d+))?'
    r'(?:\s+reason\s+(?P<reason>\S+))?'
)

# 304001: URL access
# %ASA-4-304001: User 10.0.0.1 accessed URL https://example.com/path
# %ASA-4-304001: 10.0.0.1 Accessed URL http://example.com
MSG_304001_RE = re.compile(
    r'(?:User\s+)?(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+(?:Accessed|accessed)\s+'
    r'URL\s+(?P<url>\S+)'
)

# 305011: NAT translation creation
# %ASA-4-305011: Built dynamic NAT translation from inside:10.0.0.1/12345 to outside:1.2.3.4/54321
# %ASA-4-305011: Built static NAT translation from inside:10.0.0.1 to outside:1.2.3.4
# %ASA-4-305012: Teardown NAT translation from inside:10.0.0.1/12345 to outside:1.2.3.4/54321
MSG_305011_RE = re.compile(
    r'(?P<nat_action>Built|Teardown)\s+'
    r'(?P<nat_type>dynamic|static)\s+'
    r'NAT translation\s+'
    r'from\s+(?P<src_iface>\S+):(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?:/(?P<src_port>\d+))?\s+'
    r'to\s+(?P<dst_iface>\S+):(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'(?:/(?P<dst_port>\d+))?'
)

# 419002: Failover
# %ASA-4-419002: Dual active pair A is detected. Switching to ACTIVE/STANDBY
# %ASA-2-419002: Duplicate active unit detected - switching to STANDBY
MSG_419002_RE = re.compile(
    r'(?P<failover_event>.*?)'
    r'(?:- switching to\s+(?P<failover_state>ACTIVE|STANDBY|ACTIVE/STANDBY))?'
    r'\.?$'
)

# 733100: VPN session
# %ASA-4-733100: User <user> IP <ip> Group <group> Session <type> started/ended
MSG_733100_RE = re.compile(
    r'User\s+<(?P<vpn_user>[^>]+)>\s+'
    r'IP\s+<(?P<vpn_ip>\d{1,3}(?:\.\d{1,3}){3})>\s+'
    r'(?:Group\s+<(?P<vpn_group>[^>]+)>\s+)?'
    r'Session\s+<(?P<vpn_session_type>[^>]+)>\s+'
    r'(?P<vpn_action>started|ended|created|deleted|established|terminated)'
)

CUSTOM_PATTERNS: dict[str, re.Pattern] = {
    "106100": MSG_106100_RE,
    "106101": MSG_106101_RE,
    "302013": MSG_302013_RE,
    "302014": MSG_302014_RE,
    "304001": MSG_304001_RE,
    "305011": MSG_305011_RE,
    "305012": MSG_305011_RE,
    "419002": MSG_419002_RE,
    "733100": MSG_733100_RE,
}

MSG_ACTION_MAP = {
    "106001": "deny",
    "106002": "deny",
    "106006": "deny",
    "106007": "deny",
    "106010": "deny",
    "106014": "deny",
    "106015": "deny",
    "106016": "deny",
    "106021": "deny",
    "106023": "deny",
    "106100": "permit_acl",
    "106101": "deny_acl",
    "302013": "connection_built",
    "302014": "connection_torn_down",
    "302015": "connection_built",
    "302016": "connection_torn_down",
    "304001": "url_access",
    "305011": "nat_built",
    "305012": "nat_torn_down",
    "402117": "crypto",
    "419001": "failover",
    "419002": "failover",
    "710001": "auth",
    "710002": "auth",
    "710003": "auth",
    "733100": "vpn_session",
    "111001": "dhcp",
    "113004": "aaa",
    "113005": "aaa",
    "113009": "aaa",
    "113012": "aaa",
    "113013": "aaa",
    "113015": "aaa",
    "114001": "dhcp",
    "114004": "dhcp",
    "114005": "dhcp",
    "114006": "dhcp",
    "114009": "dhcp",
    "209004": "transform",
    "209005": "transform",
    "209006": "transform",
}

MSG_EVENT_TYPE = {
    "106100": "asa_acl_permit",
    "106101": "asa_acl_deny",
    "302013": "asa_conn_built",
    "302014": "asa_conn_torn_down",
    "302015": "asa_conn_built",
    "302016": "asa_conn_torn_down",
    "304001": "asa_url_access",
    "305011": "asa_nat_built",
    "305012": "asa_nat_torn_down",
    "419001": "asa_failover",
    "419002": "asa_failover",
    "733100": "asa_vpn_session",
    "710001": "asa_auth",
    "710002": "asa_auth",
    "710003": "asa_auth",
}


def _parse_106100(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_106100_RE.match(msg_text)
    if not m:
        return False
    result["event_type"] = "asa_acl_permit" if m.group("action") == "permitted" else "asa_acl_deny"
    result["metadata"]["acl_name"] = m.group("acl_name")
    result["metadata"]["acl_action"] = m.group("action")
    result["source_ip"] = m.group("src_ip")
    result["dest_ip"] = m.group("dst_ip")
    result["protocol"] = m.group("protocol")
    result["metadata"]["src_interface"] = m.group("src_iface")
    result["metadata"]["dst_interface"] = m.group("dst_iface")
    if m.group("src_port"):
        try:
            result["source_port"] = int(m.group("src_port"))
        except ValueError:
            pass
    if m.group("dst_port"):
        try:
            result["dest_port"] = int(m.group("dst_port"))
        except ValueError:
            pass
    if m.group("hit_count"):
        result["metadata"]["hit_count"] = int(m.group("hit_count"))
    return True


def _parse_106101(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_106101_RE.match(msg_text)
    if not m:
        return False
    result["event_type"] = "asa_acl_deny"
    result["metadata"]["acl_name"] = m.group("acl_name")
    result["source_ip"] = m.group("src_ip")
    result["dest_ip"] = m.group("dst_ip")
    result["protocol"] = m.group("protocol")
    result["metadata"]["src_interface"] = m.group("src_iface")
    result["metadata"]["dst_interface"] = m.group("dst_iface")
    if m.group("src_port"):
        try:
            result["source_port"] = int(m.group("src_port"))
        except ValueError:
            pass
    if m.group("dst_port"):
        try:
            result["dest_port"] = int(m.group("dst_port"))
        except ValueError:
            pass
    return True


def _parse_302013(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_302013_RE.match(msg_text)
    if not m:
        return False
    result["event_type"] = "asa_conn_built"
    result["metadata"]["direction"] = m.group("direction")
    result["metadata"]["conn_id"] = m.group("conn_id")
    result["protocol"] = m.group("protocol")
    result["source_ip"] = m.group("src_ip")
    result["dest_ip"] = m.group("dst_ip")
    result["source_port"] = int(m.group("src_port"))
    result["dest_port"] = int(m.group("dst_port"))
    result["metadata"]["src_interface"] = m.group("src_iface")
    result["metadata"]["dst_interface"] = m.group("dst_iface")
    return True


def _parse_302014(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_302014_RE.match(msg_text)
    if not m:
        return False
    result["event_type"] = "asa_conn_torn_down"
    result["protocol"] = m.group("protocol")
    result["metadata"]["conn_id"] = m.group("conn_id")
    result["source_ip"] = m.group("src_ip")
    result["dest_ip"] = m.group("dst_ip")
    result["source_port"] = int(m.group("src_port"))
    result["dest_port"] = int(m.group("dst_port"))
    result["metadata"]["src_interface"] = m.group("src_iface")
    result["metadata"]["dst_interface"] = m.group("dst_iface")
    if m.group("duration_str"):
        result["metadata"]["duration"] = m.group("duration_str")
    if m.group("bytes"):
        result["metadata"]["bytes"] = int(m.group("bytes"))
    if m.group("reason"):
        result["metadata"]["teardown_reason"] = m.group("reason")
    return True


def _parse_304001(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_304001_RE.match(msg_text)
    if not m:
        return False
    result["event_type"] = "asa_url_access"
    result["source_ip"] = m.group("src_ip")
    url = m.group("url")
    result["metadata"]["url"] = url
    if url.startswith("https"):
        result["dest_port"] = 443
    elif url.startswith("http"):
        result["dest_port"] = 80
    result["message"] = f"Cisco ASA URL access: {url} from {result['source_ip']}"
    return True


def _parse_305011(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_305011_RE.match(msg_text)
    if not m:
        return False
    action = m.group("nat_action")
    result["event_type"] = "asa_nat_built" if action == "Built" else "asa_nat_torn_down"
    result["metadata"]["nat_type"] = m.group("nat_type")
    result["source_ip"] = m.group("src_ip")
    result["dest_ip"] = m.group("dst_ip")
    result["metadata"]["src_interface"] = m.group("src_iface")
    result["metadata"]["dst_interface"] = m.group("dst_iface")
    if m.group("src_port"):
        try:
            result["source_port"] = int(m.group("src_port"))
        except ValueError:
            pass
    if m.group("dst_port"):
        try:
            result["dest_port"] = int(m.group("dst_port"))
        except ValueError:
            pass
    return True


def _parse_419002(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_419002_RE.match(msg_text)
    if not m:
        return False
    result["event_type"] = "asa_failover"
    result["metadata"]["failover_event"] = m.group("failover_event").strip()
    if m.group("failover_state"):
        result["metadata"]["failover_state"] = m.group("failover_state")
    result["severity"] = "high"
    return True


def _parse_733100(msg_text: str, result: Dict[str, Any]) -> bool:
    m = MSG_733100_RE.match(msg_text)
    if not m:
        return False
    result["event_type"] = "asa_vpn_session"
    result["user"] = m.group("vpn_user")
    result["source_ip"] = m.group("vpn_ip")
    result["metadata"]["vpn_group"] = m.group("vpn_group") or ""
    result["metadata"]["vpn_session_type"] = m.group("vpn_session_type")
    result["metadata"]["vpn_action"] = m.group("vpn_action")
    if m.group("vpn_action") in ("started", "established", "created"):
        result["severity"] = "low"
    else:
        result["severity"] = "medium"
    return True


MSG_PARSERS = {
    "106100": _parse_106100,
    "106101": _parse_106101,
    "302013": _parse_302013,
    "302014": _parse_302014,
    "304001": _parse_304001,
    "305011": _parse_305011,
    "305012": _parse_305011,
    "419002": _parse_419002,
    "733100": _parse_733100,
}

IP_PORT_PATTERN = re.compile(
    r'(?:from\s+)?(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<src_port>\d+))?'
    r'\s+(?:to|->)\s+'
    r'(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<dst_port>\d+))?'
)

INTERFACE_PATTERN = re.compile(r'on\s+interface\s+(\S+)')
USER_PATTERN = re.compile(r'user\s+(\S+)')
PROTOCOL_PATTERN = re.compile(r'(?:proto|protocol)\s+(\S+)', re.IGNORECASE)
ICMP_PATTERN = re.compile(r'icmp\s+type\s+(\d+)', re.IGNORECASE)
ACL_PATTERN = re.compile(r'(?:acl|access-list)\s+(\S+)', re.IGNORECASE)

GENERIC_TCP_PORTS = {22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017}


def parse_cisco_asa_log(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        msg = raw.get("message", raw.get("raw", str(raw)))
    elif isinstance(raw, str):
        msg = raw
    else:
        return {"event_type": "cisco_asa", "severity": "info", "message": str(raw)}

    result: Dict[str, Any] = {
        "event_type": "cisco_asa",
        "severity": "info",
        "source_ip": "",
        "dest_ip": "",
        "source_port": 0,
        "dest_port": 0,
        "protocol": "",
        "user": "",
        "message": msg,
        "metadata": {},
    }

    m = ASA_MSG_RE.match(msg)
    if not m:
        return result

    sev_code = m.group("severity")
    msg_id = m.group("msg_id")
    msg_text = m.group("message")

    result["severity"] = SEVERITY_MAP.get(sev_code, "info")
    result["metadata"]["msg_id"] = msg_id
    result["metadata"]["msg_action"] = MSG_ACTION_MAP.get(msg_id, "")

    if msg_id in MSG_EVENT_TYPE:
        result["event_type"] = MSG_EVENT_TYPE[msg_id]

    handler = MSG_PARSERS.get(msg_id)
    if handler:
        if handler(msg_text, result):
            result["message"] = f"Cisco ASA [{msg_id}]: {msg_text}"
            return result

    ip_m = IP_PORT_PATTERN.search(msg_text)
    if ip_m:
        result["source_ip"] = ip_m.group("src_ip")
        result["dest_ip"] = ip_m.group("dst_ip")
        if ip_m.group("src_port"):
            try:
                result["source_port"] = int(ip_m.group("src_port"))
            except ValueError:
                pass
        if ip_m.group("dest_port"):
            try:
                result["dest_port"] = int(ip_m.group("dest_port"))
            except ValueError:
                pass

    iface_m = INTERFACE_PATTERN.search(msg_text)
    if iface_m:
        result["metadata"]["interface"] = iface_m.group(1)

    user_m = USER_PATTERN.search(msg_text)
    if user_m:
        result["user"] = user_m.group(1)

    proto_m = PROTOCOL_PATTERN.search(msg_text)
    if proto_m:
        result["protocol"] = proto_m.group(1)

    icmp_m = ICMP_PATTERN.search(msg_text)
    if icmp_m:
        result["metadata"]["icmp_type"] = icmp_m.group(1)
        result["protocol"] = "icmp"

    acl_m = ACL_PATTERN.search(msg_text)
    if acl_m:
        result["metadata"]["acl_name"] = acl_m.group(1)

    if "denied" in msg_text.lower() or "deny" in msg_text.lower():
        if result["severity"] in ("informational", "notice", "info", "low"):
            result["severity"] = "medium"

    result["message"] = f"Cisco ASA [{msg_id}]: {msg_text}"

    return result


PARSER_REGISTRY_KEY = "cisco_asa"
