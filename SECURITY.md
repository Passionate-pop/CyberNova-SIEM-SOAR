# 🛡️ CyberNova — Security & Attack Coverage

## Overview

CyberNova is a production-grade SIEM/SOAR platform that detects, correlates, and automatically responds to cyberattacks in real-time. This document details every attack category, detection method, and defense mechanism built into the platform.

**Total Detection Rules:** 630+  
**Total Protection Modules:** 17  
**Docker Services:** 10 (backend, frontend, nginx, postgres, redis, pipeline-worker, prometheus, alertmanager, grafana, suricata)

---

## 📊 Detection Rule Breakdown

| Layer | Rules | Description |
|---|---|---|
| **WAF (Web Application Firewall)** | 189 | Inline HTTP request inspection — blocks attacks before they reach the API |
| **Sigma Detection Rules** | 441 | Host/network event detection — maps to MITRE ATT&CK framework |
| **Correlation Rules** | 6+ | Multi-stage attack chain detection across sliding time windows |
| **DLP Patterns** | 22 | Sensitive data (PII, credentials, secrets) leak detection |
| **Total** | **658+** | |

---

## 🔥 Web Application Firewall (WAF) — 189 Rules

The WAF inspects every HTTP request in real-time using a two-layer defense:
- **Layer 1:** Fast keyword + regex pre-check (blocks obvious attacks instantly)
- **Layer 2:** Full WAF engine analysis with LRU cache (189 rules, risk scoring)

### Attack Types Blocked

| Category | Rules | Severity | Risk Score | Examples |
|---|---|---|---|---|
| **SQL Injection** | 21 | Critical | 98 | `' OR 1=1 --`, `UNION SELECT`, `DROP TABLE`, `INSERT INTO`, `EXEC xp_`, time-based blind (`WAITFOR DELAY`, `SLEEP()`), comment injection, tautology bypass |
| **XSS (Cross-Site Scripting)** | 46 | Critical | 97 | `<script>`, `<iframe>`, `<svg>`, `javascript:`, `onerror=`, `alert()`, `eval()`, `document.write()`, `innerHTML=`, `String.fromCharCode`, HTML entity encoding, hex encoding, URL encoding bypass |
| **Command Injection** | 37 | Critical | 98 | `; cat /etc/passwd`, `\| whoami`, `&& ls`, `` `cmd` ``, `$(cmd)`, `bash -i`, `python -c`, `perl -e`, `nc` (netcat), `nmap`, SSH tunneling, `sudo`, `chmod 777`, `usermod` |
| **Path Traversal** | 37 | Critical | 95 | `../../etc/passwd`, `%2e%2e%2f`, unicode overlong `%c0%ae`, null byte injection, `/proc/self/environ`, `/windows/system32`, `.env`, `.aws/credentials`, `.git/config`, `.ssh/id_rsa`, `wp-config.php` |
| **SSRF (Server-Side Request Forgery)** | 12 | High | 92 | `http://169.254.169.254/` (AWS metadata), `http://127.0.0.1`, RFC1918 ranges (10.x, 172.16.x, 192.168.x), `file://`, internal DNS (`.internal`, `.local`) |
| **Template Injection (SSTI)** | 8 | Critical | 95 | Jinja2 `{{7*7}}`, Velocity `${expr}`, FreeMarker `#{expr}`, ERB `<%= %>`, Jinja2 block `{%%}`, Java RCE (`class.forName`, `Runtime.getRuntime`, `ProcessBuilder`) |
| **Request Smuggling** | 5 | Critical | 98 | CL-CL, TE-CL, CL-TE, obfuscated Transfer-Encoding, method override headers |
| **Protocol Injection** | 7 | High | 92 | `gopher://`, `dict://`, `tftp://`, `ldap://`, `redis://`, `file:///`, PHP wrappers (`php://`, `expect://`, `phar://`), cloud storage (`s3://`, `gs://`) |
| **LDAP Injection** | 5 | High | 90 | `*)(`, `|()`, `&()`, attribute enumeration (`userPassword`, `memberOf`, `objectClass`) |
| **NoSQL Injection** | 6 | High | 90 | `$ne`, `$gt`, `$where`, `$regex`, `$exists`, `$nin`, `$all`, `$elemMatch` |
| **Data URI Attacks** | 5 | High | 95 | `data:text/html`, `data:text/javascript`, `data:application/x-javascript`, `data:image/svg+xml`, `data:;base64` |

---

## 🔍 Sigma Detection Rules — 441 Rules (MITRE ATT&CK Mapped)

Host and network event detection rules organized by MITRE ATT&CK tactic:

| Tactic | Rules | Key Detections |
|---|---|---|
| **Defense Evasion** | 60 | AV exclusion, event log clearing, timestomping, registry tampering, firewall disabling, ETW bypass, Sysmon unload, WDigest enable, PowerShell history clearing |
| **Persistence** | 50 | Registry run keys, scheduled tasks, WMI persistence, service installs, startup folders, COM object hijacking, browser extensions, cloud IAM backdoor |
| **Credential Access** | 45 | LSASS dump (mimikatz, procdump, comsvcs), SAM/NTDS extraction, DCSync, LSA secrets, cloud metadata tokens, browser credential theft, WiFi profiles, GPP passwords |
| **Command & Control (C2)** | 40 | DNS tunneling, DNS over HTTPS, encrypted C2 (RC4, asymmetric), HTTP beaconing, ICMP tunneling, WebSocket C2, WebDAV exfil, DGA domain detection, unusual cipher suites |
| **Initial Access** | 40 | Phishing (macro docs, malicious links, credential harvesting), drive-by downloads, RDP/SSH brute force, VPN from unusual countries, web app attacks (SQLi, RCE, path traversal, SSRF, Log4j) |
| **Discovery** | 35 | Account enumeration (ADSI, LDAP, WMI), permission discovery, registry queries (AV products, firewall, installed software), network info, DNS cache, SAM registry |
| **Execution** | 35 | PowerShell encoded/obfuscated commands, AMSI bypass, WMI process creation, VBA macros, script execution (JS, Python, HTA), LOLBin abuse, download cradles |
| **Privilege Escalation** | 35 | Token manipulation, DLL hijacking, service exploits, scheduled task abuse, UAC bypass, SeImpersonate abuse, kernel exploits, cloud IAM privilege escalation |
| **Lateral Movement** | 30 | Pass-the-Hash/Pass-the-Ticket, RDP lateral, SMB admin share, DCOM execution, WMI lateral, alternate authentication tokens, cloud shell access |
| **Impact** | 25 | Ransomware (Conti, LockBit, BlackCat patterns), MBR overwrite, volume shadow deletion, mass file encryption, database drop, firmware wipe, backup deletion |
| **Collection** | 20 | Browser data harvesting, clipboard access, screen capture, email export, code repo cloning, cloud sync folder staging, encrypted archive creation |
| **Exfiltration** | 20 | DNS exfil, ICMP exfil, SMTP exfil, cloud storage upload, Git push to external, Pastebin upload, traffic mirroring, scheduled transfers |

### Individual Sigma Rules (Examples)

| File | Description |
|---|---|
| `lsass_access_mimikatz.yml` | Detects Mimikatz credential dumping |
| `powershell_encoded_command.yml` | Base64 encoded PowerShell execution |
| `scheduled_task_malicious.yml` | Suspicious scheduled task creation |
| `wmi_persistence.yml` | WMI event subscription persistence |
| `c2_dns_tunnel_long_txt.yml` | DNS tunneling via long TXT records |
| `impact_ransomware_lockbit_patterns.yml` | LockBit ransomware behavior |
| `credential_dump_dcsync.yml` | Active Directory DCSync attack |
| `lateral_rdp_from_unexpected.yml` | Unexpected RDP lateral movement |

---

## 🛡️ Protection Shield Modules — 17 Modules

| Module | Description | Event Types Monitored |
|---|---|---|
| **network_shield** | Network traffic anomaly detection | Suricata alerts, DNS queries, flows, connections |
| **app_shield** | Application-layer attack detection | HTTP requests, web requests, API calls |
| **process_shield** | Suspicious process detection | New processes, agent telemetry, memory alerts |
| **system_shield** | System misconfiguration detection | System checks, config audits, SELinux events |
| **user_shield** | Social engineering detection | Emails, failed logins, phishing attempts |
| **data_shield** | Data exfiltration/tampering detection | File changes, bulk transfers, registry changes |
| **resource_shield** | Resource abuse detection (cryptojacking, etc.) | System checks, process events, HTTP requests |
| **self_heal** | Automated remediation | Tamper/rootkit detection, platform compromise |
| **waf** | Web Application Firewall (189 rules) | All HTTP traffic |
| **webshell** | Webshell file detection | File scans, suspicious files |
| **rootkit** | Rootkit detection | Agent telemetry, system checks |
| **tamper_guard** | Agent tamper detection | Agent heartbeats, system checks |
| **cryptojacking** | Cryptominer detection | System checks, process events |
| **dlp** | Data Loss Prevention (22 patterns) | All events with text payloads |
| **config_audit** | Configuration audit | Config audit requests |
| **brute_force** | Distributed brute force detection | Failed logins, auth failures |
| **phishing** | Phishing URL detection | URLs, hostnames |

---

## 🔗 Correlation Engine — Multi-Stage Attack Chain Detection

The correlation engine detects complex, multi-stage attacks by tracking entity behavior across sliding time windows:

| Correlation Rule | Description | Kill Chain |
|---|---|---|
| **port_scan_then_exploit** | Port scan followed by exploitation attempt from same source | Reconnaissance → Exploitation |
| **lateral_movement** | Multiple hosts accessed from single compromised host | Lateral Movement → Collection |
| **malware_then_suspicious_network** | Malware detection followed by suspicious outbound traffic | Execution → Command & Control |
| **credential_theft_then_exploitation** | Credential access followed by remote exploitation | Credential Access → Lateral Movement |

---

## 🔐 Data Loss Prevention (DLP) — 22 Patterns

Detects sensitive data in transit, at rest, and in event payloads:

### Critical Severity
| Pattern | Description |
|---|---|
| `aws_access_key` | AWS access keys (AKIA...) |
| `aws_secret_key` | AWS secret access keys |
| `gcp_service_account` | GCP service account keys |
| `azure_connection_string` | Azure connection strings |
| `private_ssh_key` | RSA/DSA/EC/OPENSSH private keys |
| `pgp_private_key` | PGP private key blocks |
| `jwt_token` | JWT tokens (eyJ...) |
| `credit_card` | Credit card numbers |
| `ssn` | Social Security Numbers |
| `database_connection_string` | PostgreSQL/MySQL/MongoDB/Redis connection strings |
| `basic_auth_header` | HTTP Basic Auth headers |
| `bearer_token` | HTTP Bearer tokens |

### High Severity
| Pattern | Description |
|---|---|
| `github_token` | GitHub personal access tokens (ghp_...) |
| `github_pat` | GitHub fine-grained tokens (github_pat_...) |
| `slack_token` | Slack tokens (xoxb-..., xoxp-...) |
| `discord_token` | Discord bot tokens |
| `generic_api_key` | Generic API key patterns |
| `password_inline` | Inline password assignments |

---

## 🔄 Real-Time Pipeline — 24/7 Processing

```
Attack/Event
    │
    ▼
┌─────────────┐
│  Ingestion   │ ← Syslog (UDP/TCP), File Watcher, Agents, Suricata, API
│  (5140/5141) │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Normalization│ ← Parse, normalize, deduplicate
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Enrichment  │ ← GeoIP, threat intel, asset context
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Detection   │ ← 441 Sigma rules + 189 WAF rules + anomaly detection
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Correlation  │ ← Multi-stage attack chain detection
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Alert     │ ← Deduplication, suppression, severity scoring
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    SOAR      │ ← Automated response: block IP, isolate device, disable user
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ AI Assistant │ ← Automated incident investigation and analysis
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  WebSocket   │ ← Real-time dashboard updates
└─────────────┘
```

---

## 📡 Monitoring & Alerting

| Component | Purpose | Port |
|---|---|---|
| **Prometheus** | Metrics collection (15s intervals) | 9090 |
| **Alertmanager** | Alert routing (critical → email, warning → grouped) | 9093 |
| **Grafana** | Dashboards (security, pipeline, overview) | 3001 |
| **Suricata NIDS** | Network intrusion detection | internal |

### Prometheus Alert Rules (22 rules)
- Service health: BackendDown, WorkerDown, RedisDown, PostgresDown
- Pipeline: PipelineStopped, NoEventsIngested, HighProcessingLatency, AlertRateSpike
- Streams: StreamConsumerLag, CriticalStreamLag, DeadLetterQueueGrowing
- Resources: HighMemoryUsage, CriticalCPUUsage, HighErrorRate
- Security: SOARDisabled, NoActiveAgents

---

## 🏗️ Infrastructure Security

| Feature | Implementation |
|---|---|
| **Non-root containers** | All services run as `cybernova:1000` |
| **Read-only filesystem** | Nginx container is read-only with tmpfs |
| **Cap drop ALL** | All Linux capabilities dropped, only NET_ADMIN/NET_RAW added |
| **No new privileges** | `security_opt: no-new-privileges:true` on all services |
| **TLS termination** | HTTPS with TLS 1.2/1.3, HSTS preload |
| **CSP headers** | Content-Security-Policy, X-Frame-Options DENY, X-Content-Type-Options nosniff |
| **Rate limiting** | Per-IP and per-plan rate limiting middleware |
| **JWT auth** | HS256 tokens with weak-secret rejection |
| **RBAC** | Role-based access control (admin, analyst, viewer) |
| **ABAC** | Attribute-based access control policies |
| **Docker secrets** | All credentials via Docker secrets (not env vars) |
| **WORM storage** | Write-Once-Read-Many audit log storage |
| **Key rotation** | Automated JWT/encryption key rotation |
| **Row-level security** | Postgres RLS for tenant isolation |

---

## 🧪 Test Coverage

| Test Category | Tests | Status |
|---|---|---|
| Unit tests | 434 | ✅ All passing |
| Detection/WAF/Sigma/Correlation | 32 | ✅ All passing |
| Pipeline/SOAR/Batch/Bus/RAG | 88 | ✅ All passing |
| Integration/Infrastructure | 127 | ✅ All passing |
| E2E/Chaos | 43 | ✅ All passing |
| Security (fuzz, live attacks) | 18 | ✅ All passing |
| Auth/Pipeline/WebSocket | 39 | ✅ All passing |
| **Total** | **781** | **✅ Zero failures** |

---

## 🔒 Supported Compliance Frameworks

| Framework | Status |
|---|---|
| PCI DSS | ✅ Evidence collection, CDE detection |
| GDPR | ✅ Data subject rights, breach notification |
| HIPAA | ✅ PHI detection, access controls |
| SOC 2 | ✅ Audit logging, access controls |
| ISO 27001 | ✅ Risk assessment, incident response |

---

## 📚 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
