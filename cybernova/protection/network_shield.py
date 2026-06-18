from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("cybernova.protection.network_shield")

SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".loan",
    ".click", ".work", ".date", ".men", ".win", ".bid", ".trade",
    ".webcam", ".science", ".party", ".review", ".country", ".stream",
}

DNS_TUNNEL_PATTERNS: List[re.Pattern] = [
    re.compile(r"^[a-z0-9]{50,}\.", re.I),
    re.compile(r"(?:[a-z0-9]{20,}\.){3,}", re.I),
    re.compile(r"^[a-z0-9]{8,}\.[a-z0-9]{8,}\.[a-z0-9]{8,}\.", re.I),
    re.compile(r"\.(tk|ml|ga|cf|gq|xyz|top|loan|click)\.[a-z]{2,3}$", re.I),
]

KNOWN_P2P_PORTS: Set[int] = {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6890, 51413, 1337, 4444, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669}
KNOWN_MINING_PORTS: Set[int] = {3333, 3334, 3335, 3336, 3337, 3338, 3339, 4444, 4445, 5555, 7777, 8888, 14444, 20535, 33433}
KNOWN_C2_PORTS: Set[int] = {8080, 8443, 4443, 10080, 10443, 447, 6669, 1337, 31337, 12345, 12346, 2000, 2001, 2002}
SUSPICIOUS_EGRESS_PORTS: Set[int] = {22, 23, 53, 80, 443, 3389, 5900, 5901, 8443}

TOR_EXIT_NODES_CIDR: List[str] = [
    "185.220.101.", "185.220.102.", "185.220.103.",
    "154.127.48.", "154.127.49.", "154.127.50.",
    "45.61.184.", "45.61.185.", "45.61.186.",
    "199.249.223.", "199.249.224.", "199.249.225.",
    "109.70.100.", "107.189.1.", "107.189.2.",
]

BLACKLISTED_IPS: Set[str] = set()
EGRESS_WHITELIST_CIDR: List[str] = []


class NetworkShield:
    def __init__(self):
        self._recent_flows: Dict[str, List[float]] = defaultdict(list)
        self._dns_queries: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        self._syn_flood: Dict[str, List[float]] = defaultdict(list)
        self._port_scans: Dict[str, Set[int]] = defaultdict(set)
        self._scan_times: Dict[str, float] = {}
        self._egress_bytes: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._arp_cache: Dict[str, str] = {}
        self._mac_flux: Dict[str, Set[str]] = defaultdict(set)
        self._promisc_check_time: float = 0
        self._cached_promisc: bool = False

    FLOW_WINDOW = 60
    DNS_TUNNEL_THRESHOLD = 50
    SYN_FLOOD_THRESHOLD = 100
    SCAN_THRESHOLD = 15
    EGRESS_THRESHOLD_BYTES = 50_000_000
    EGRESS_WINDOW = 300

    def analyze_event(self, event: dict) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "threat_detected": False, "threats": [],
            "max_risk_score": 0.0, "findings": [],
        }
        etype = event.get("event_type", "")
        extra = event.get("extra_data") or event.get("extra", {})
        src_ip = event.get("source_ip", extra.get("src_ip", ""))
        dst_ip = event.get("dest_ip", extra.get("dst_ip", ""))
        dst_port = event.get("dest_port", extra.get("dest_port", 0))
        protocol = event.get("protocol", extra.get("protocol", ""))

        if etype == "suricata_alert":
            sig = (extra.get("signature") or extra.get("alert", {}).get("signature", "")).lower()
            cat = (extra.get("category") or extra.get("alert", {}).get("category", "")).lower()
            self._analyze_suricata(sig, cat, src_ip, dst_ip, dst_port, results)

        if etype in ("dns_query", "dns_request"):
            qname = extra.get("query", extra.get("qname", ""))
            self._analyze_dns(src_ip, qname, results)

        if etype in ("flow", "netflow", "connection"):
            proto = extra.get("proto", protocol)
            self._analyze_flow(src_ip, dst_ip, dst_port, proto, extra.get("bytes", 0), results)

        if src_ip:
            self._detect_scan(src_ip, dst_port, results)
            self._detect_syn_flood(src_ip, etype, extra, results)
            self._detect_egress_anomaly(src_ip, dst_ip, dst_port, extra.get("bytes", 0), results)

        self._detect_promiscuous(results)
        return results

    def _analyze_suricata(self, sig: str, cat: str, src: str, dst: str, port: int, res: dict):
        attack_keywords = {
            "et trojan": ("c2_traffic", 92), "c2": ("c2_traffic", 90),
            "malware": ("malware_traffic", 88), "botnet": ("botnet_traffic", 90),
            "exploit": ("exploit_attempt", 88), "shellcode": ("shellcode_detected", 95),
            "buffer overflow": ("buffer_overflow", 92),
            "sql injection": ("sqli_attempt", 92), "sqli": ("sqli_attempt", 92),
            "xss": ("xss_attempt", 82), "cross site": ("xss_attempt", 82),
            "command injection": ("cmd_injection_attempt", 94),
            "path traversal": ("path_traversal_attempt", 78),
            "port scan": ("port_scan", 60), "scanning": ("port_scan", 60),
            "ddos": ("ddos_attempt", 92), "amplification": ("ddos_amplification", 94),
            "dns tunnel": ("dns_tunnel", 88),
            "data exfil": ("data_exfiltration_network", 88),
            "ransomware": ("ransomware_c2", 95),
            "cryptominer": ("cryptominer_network", 88),
        }
        for kw, (t, r) in attack_keywords.items():
            if kw in sig or kw in cat:
                self._add_finding(res, t, f"Suricata: {sig[:120]}", r, {"signature": sig[:200], "src": src, "dst": dst})
                break
        if port in KNOWN_C2_PORTS:
            self._add_finding(res, "suspicious_port", f"C2 port {port} traffic {src}->{dst}", 75, {"port": port})
        if port in KNOWN_MINING_PORTS:
            self._add_finding(res, "mining_pool_traffic", f"Mining pool port {port}", 85, {"port": port})

    def _analyze_dns(self, src: str, qname: str, res: dict):
        if not qname:
            return
        now = time.time()
        domain = qname.strip().rstrip(".")
        self._dns_queries[src].append((domain, now))
        self._dns_queries[src] = [(d, t) for d, t in self._dns_queries[src] if t > now - 60]
        parts = domain.split(".")
        sub = parts[0] if len(parts) > 1 else ""
        for pat in DNS_TUNNEL_PATTERNS:
            if pat.search(domain):
                self._add_finding(res, "dns_tunneling", f"DNS tunnel pattern: {domain[:80]}", 88, {"domain": domain[:120]})
                break
        if len(sub) > 40 and re.match(r"^[a-zA-Z0-9]+$", sub):
            entropy = self._shannon(sub)
            if entropy > 4.0:
                self._add_finding(res, "dns_tunneling_high_entropy", f"High-entropy subdomain ({entropy:.1f}): {domain[:80]}", 85, {"entropy": entropy})
        if domain.endswith(".tk") or domain.endswith(".ml") or domain.endswith(".ga"):
            self._add_finding(res, "dns_suspicious_tld", f"Suspicious TLD in DNS: {domain}", 55, {"domain": domain})
        if len(self._dns_queries[src]) >= self.DNS_TUNNEL_THRESHOLD:
            self._add_finding(res, "dns_flood", f"DNS flood from {src}: {len(self._dns_queries[src])} in 60s", 75, {"count": len(self._dns_queries[src])})

    def _analyze_flow(self, src: str, dst: str, port: int, proto: str, byte_count: int, res: dict):
        now = time.time()
        flow_key = f"{src}:{dst}:{port}"
        self._recent_flows[flow_key].append(now)
        self._recent_flows[flow_key] = [t for t in self._recent_flows[flow_key] if t > now - self.FLOW_WINDOW]
        if len(self._recent_flows[flow_key]) > 50:
            self._add_finding(res, "flow_flood", f"Flow flood: {src}->{dst}:{port} ({len(self._recent_flows[flow_key])} in 60s)", 70, {"flow_key": flow_key})
        if port == 53 and proto.upper() == "UDP" and byte_count > 512:
            self._add_finding(res, "dns_amplification", f"Large DNS response {byte_count}B — possible amplification", 85, {"bytes": byte_count})
        if proto.upper() == "ICMP" and byte_count > 1000:
            self._add_finding(res, "icmp_large_packet", f"Large ICMP packet {byte_count}B — possible covert channel", 75, {"bytes": byte_count})

    def _detect_scan(self, src: str, port: int, res: dict):
        if not port or port <= 0:
            return
        now = time.time()
        if src not in self._scan_times:
            self._scan_times[src] = now
            self._port_scans[src] = set()
        if now - self._scan_times[src] > 120:
            self._port_scans[src] = set()
            self._scan_times[src] = now
        self._port_scans[src].add(port)
        if len(self._port_scans[src]) >= self.SCAN_THRESHOLD:
            self._add_finding(res, "port_scan_detected", f"Port scan: {len(self._port_scans[src])} ports from {src}", 65, {"ports_scanned": len(self._port_scans[src]), "source": src})

    def _detect_syn_flood(self, src: str, etype: str, extra: dict, res: dict):
        if etype not in ("syn_packet", "tcp_syn"):
            return
        now = time.time()
        self._syn_flood[src].append(now)
        self._syn_flood[src] = [t for t in self._syn_flood[src] if t > now - 10]
        if len(self._syn_flood[src]) >= self.SYN_FLOOD_THRESHOLD:
            self._add_finding(res, "syn_flood", f"SYN flood from {src}: {len(self._syn_flood[src])} in 10s", 92, {"count": len(self._syn_flood[src])})

    def _detect_egress_anomaly(self, src: str, dst: str, port: int, byte_count: int, res: dict):
        if not dst or not byte_count:
            return
        now = time.time()
        key = f"{src}->{dst}"
        self._egress_bytes[key].append((now, byte_count))
        self._egress_bytes[key] = [(t, b) for t, b in self._egress_bytes[key] if t > now - self.EGRESS_WINDOW]
        total = sum(b for _, b in self._egress_bytes[key])
        if total > self.EGRESS_THRESHOLD_BYTES:
            self._add_finding(res, "data_exfiltration_network", f"High egress {total // 1024 // 1024}MB {src}->{dst} in 5min", 88, {"bytes": total, "dst": dst})
        if port in SUSPICIOUS_EGRESS_PORTS and byte_count > 10_000_000:
            self._add_finding(res, "suspicious_egress", f"Large transfer on port {port}: {byte_count // 1024 // 1024}MB", 80, {"port": port, "bytes": byte_count})

    def _detect_promiscuous(self, res: dict):
        now = time.time()
        if now - self._promisc_check_time < 60:
            return
        self._promisc_check_time = now
        try:
            if Path("/proc/net/dev").exists():
                text = Path("/proc/net/dev").read_text()
                for line in text.split("\n")[2:]:
                    if line.strip() and ":" in line:
                        parts = line.split(":")
                        iface = parts[0].strip()
                        stats = parts[1].split()
                        if len(stats) > 8:
                            errs = int(stats[2])
                            drop = int(stats[3])
                            if errs > 1000 or drop > 10000:
                                self._add_finding(res, "nic_errors_excessive", f"Excessive NIC errors on {iface}: {errs} errs, {drop} drops", 60, {"interface": iface})
            for p in Path("/sys/class/net").iterdir():
                flags_path = p / "flags"
                if flags_path.exists():
                    flags = int(flags_path.read_text().strip(), 16)
                    if flags & 0x100:
                        self._add_finding(res, "promiscuous_mode", f"Promiscuous mode detected on {p.name}", 85, {"interface": p.name, "flags": hex(flags)})
        except (OSError, PermissionError, ValueError) as e:
            log.warning("NetworkShield promiscuous mode check failed: %s", e)

    def detect_mac_flood(self, mac: str, ip: str, interface: str) -> Optional[Dict[str, Any]]:
        key = f"{interface}:{ip}"
        self._mac_flux[key].add(mac)
        if len(self._mac_flux[key]) > 5:
            return {"type": "mac_flooding", "risk": 90, "message": f"MAC flooding on {interface}: {len(self._mac_flux[key])} MACs for {ip}", "macs": list(self._mac_flux[key])[:10]}
        return None

    def detect_arp_spoof(self, ip: str, mac: str) -> Optional[Dict[str, Any]]:
        if ip in self._arp_cache:
            if self._arp_cache[ip] != mac:
                return {"type": "arp_spoofing", "risk": 95, "message": f"ARP spoof: {ip} changed from {self._arp_cache[ip]} to {mac}", "previous_mac": self._arp_cache[ip], "current_mac": mac}
        self._arp_cache[ip] = mac
        return None

    def _add_finding(self, res: dict, ftype: str, msg: str, risk: float, details: dict):
        res["findings"].append({"type": ftype, "risk_score": risk, "message": msg, **details})
        res["max_risk_score"] = max(res["max_risk_score"], risk)
        res["threat_detected"] = True

    def _shannon(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        for count in freq.values():
            p = count / length
            if p > 0:
                import math
                entropy -= p * math.log2(p)
        return entropy


network_shield = NetworkShield()
