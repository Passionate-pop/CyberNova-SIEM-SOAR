# 🛡️ CyberNova — AI-Powered Security Platform

**Open-source SIEM + SOAR + EDR. 658+ detection rules, 17 protection shields, 441 Sigma rules mapped to MITRE ATT&CK, auto-responds via SOAR playbooks.**

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CyberNova Pipeline Architecture                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INGESTION → NORMALIZATION → ENRICHMENT → DETECTION → SOAR          │
│                                                                      │
│  [syslog]     [schema map]   [geoip]      [rules engine]  [webhook] │
│  [agents]     [dedup]        [threat      [DSL rules]     [block]   │
│  [API]        [parse]        intel]       [17 shields]    [isolate] │
│  [suricata]                  [stego]      [WAF]            [log]    │
│  [filewatch]                              [correlation]             │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Option A: One-Click Install (Windows)

```bat
CyberNova-Install-Run.bat
```

Double-click → installs everything → opens browser automatically.

### Option B: Docker (Linux/Mac/Windows)

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/cybernova.git
cd cybernova

# 2. Generate secrets (or copy .env.example to .env)
cp .env.example .env

# 3. Start everything
docker compose up -d --build

# 4. Open in browser
# Marketing site:  http://localhost:8888
# Dashboard:        http://localhost:8888/app/
# API docs:         http://localhost:8000/docs
```

### Option C: Helm (Kubernetes)

```bash
helm install cybernova ./helm/cybernova
```

---

## 👤 User Flow

```
1. Open browser → 3D marketing website loads
2. Click "Get Started" → redirected to /app
3. Create account → Choose Individual or Organization
4. Accept Terms & Cookies → One-time consent
5. Install agent → Copy ONE command, paste in terminal
6. Dashboard → Real-time alerts, incidents, monitoring
```

### User Roles

| Role | Access | Description |
|------|--------|-------------|
| **Individual** | Full | Personal device protection |
| **Organization Admin** | Full + Users | Manage team, devices, settings |
| **Staff** | Read + Limited Write | View alerts, respond to incidents |
| **Viewer** | Read Only | Dashboard monitoring |

---

## 🛡️ What It Does

### SIEM — Security Information & Event Management

- **40+ ingestion sources**: Syslog (UDP/TCP), REST API, file watcher, Suricata IDS, host agents
- **Real-time pipeline**: Ingest → Normalize → Enrich → Detect → Alert
- **50+ detection rules** + 17 protection modules + WAF (SQLi, XSS, CMDi, LFI, SSRF, LDAPi)
- **18 Prometheus alert rules** for infrastructure monitoring

### SOAR — Security Orchestration, Automation & Response

- **Policy-driven playbooks**: Alerts → Response actions → Dispatch
- **Built-in actions**: Webhook, firewall block (iptables/nftables/netsh), device isolation
- **WebSocket push** for real-time alert streaming
- **AI investigation** for automated threat analysis

### EDR — Endpoint Detection & Response

- **Windows agent**: Processes, files, downloads, USB, PowerShell, registry, services, security event logs
- **Linux agent**: USB monitoring, keyloggers, FIM, memory YARA scanning, stego, rootkits, cryptojacking

---

## 🎯 Attack Coverage (658+ Detection Rules)

CyberNova defends against **658+ attack types** across network, web, host, cloud, and data layers. See [SECURITY.md](SECURITY.md) for the complete breakdown.

| Layer | Rules | Coverage |
|-------|-------|----------|
| **WAF** | 189 | SQLi, XSS, CMDi, path traversal, SSRF, SSTI, request smuggling, protocol injection, LDAPi, NoSQLi |
| **Sigma (MITRE ATT&CK)** | 441 | Defense evasion, persistence, credential access, C2, initial access, execution, privilege escalation, lateral movement, impact, collection, exfiltration |
| **Correlation** | 6+ | Multi-stage attack chains (recon → exploit, malware → C2, credential theft → lateral) |
| **DLP** | 22 | AWS/GCP/Azure keys, SSH/PGP keys, JWT tokens, credit cards, SSNs, connection strings |
| **Shields** | 17 | Network, app, process, system, user, data, resource, self-heal, webshell, rootkit, tamper, cryptojacking, brute force, phishing |

### Top Attack Types Blocked

| Category | Examples |
|----------|----------|
| **Web** | SQLi (21 patterns), XSS (46 patterns), CMDi (37 patterns), SSRF, SSTI (Jinja2/Velocity/ERB), request smuggling |
| **Network** | Port scanning, DNS tunneling, C2 beaconing, ICMP tunneling, DGA domains, encrypted C2 |
| **Host** | Ransomware (Conti/LockBit/BlackCat), rootkits, cryptominers, credential dumping (mimikatz), keyloggers |
| **Auth** | Brute force, password spraying, credential stuffing, pass-the-hash, Kerberoasting |
| **Cloud** | K8s secrets access, pod exec, RBAC escalation, cloud metadata abuse |
| **Data** | DLP violations (22 patterns), bulk exfiltration, registry tampering, shadow copy deletion |

---

## 🏗️ Architecture

### Services

| Service | Port | Role |
|---------|------|------|
| `backend` | 8000 | FastAPI + pipeline orchestrator |
| `frontend` | 8080 | React dashboard (Vite) |
| `postgres` | 5432 | Events, alerts, incidents |
| `redis` | 6379 | Streams, cache, pub/sub |
| `nginx` | 8888/443 | Reverse proxy, TLS, rate limiting |
| `pipeline-worker` | — | Redis Streams consumer |
| `prometheus` | 9090 | Metrics collection |
| `grafana` | 3001 | Dashboards & visualization |
| `alertmanager` | 9093 | Alert routing |
| `suricata` | — | Network IDS (optional) |

### Event Flow

```
Agent/Source → Ingestion → Normalization → Enrichment → Detection → Correlation → Alert → SOAR
                                                                                      ↓
                                                                              WebSocket → Dashboard
```

---

## 📡 API

Full OpenAPI docs at `http://localhost:8000/docs`

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | JWT login |
| `/api/v1/setup/admin` | POST | Create first admin |
| `/api/v1/ingest/event` | POST | Ingest event |
| `/api/v1/ingest/agent` | POST | Agent event ingestion |
| `/api/v1/dashboard/summary` | GET | Dashboard summary |
| `/api/v1/devices` | GET | List devices |
| `/api/v1/alerts` | GET | List alerts |
| `/ws` | WS | Real-time updates |

---

## 🔌 Integrations (13+)

Slack, Teams, PagerDuty, Jira, Splunk, MISP, TheHive, OpenCTI, VirusTotal, AbuseIPDB, AlienVault OTX, MaxMind GeoIP

All gracefully degrade when unconfigured.

---

## 🧪 Testing

```bash
# Unit tests (434+ tests)
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# E2E tests
python -m pytest tests/e2e/ -v

# Security tests
python -m pytest tests/security/ -v

# Frontend tests
cd cybernova-frontend && npm test

# Frontend typecheck
cd cybernova-frontend && npx tsc --noEmit
```

---

## 📊 Monitoring

- **Prometheus** metrics at `/metrics` — pipeline throughput, latency, error rates
- **Grafana** dashboards — auto-provisioned with pre-built panels
- **Alertmanager** — email, Slack, webhook routing
- **SLA metrics** — P50/P90/P99 latency, availability, queue depths

---

## 📁 Project Structure

```
cybernova/
├── cybernova/              # Python backend (FastAPI)
│   ├── api/                # REST API routes
│   ├── auth/               # Authentication & RBAC
│   ├── detection/          # Detection engine & rules
│   ├── pipeline/           # Event processing pipeline
│   ├── response/           # SOAR response actions
│   ├── protection/         # WAF, shields, defense modules
│   ├── ingestion/          # Event ingestion (syslog, agents)
│   └── monitoring/         # Health, metrics, tracing
├── cybernova-frontend/     # React dashboard (Vite + Tailwind)
├── web-page/               # Marketing site (Next.js)
├── cybernova-driver/       # Kernel modules (Linux/Windows)
├── tests/                  # Test suites
├── scripts/                # Deployment & utility scripts
├── monitoring/             # Prometheus, Grafana configs
├── nginx/                  # Reverse proxy configs
├── helm/                   # Kubernetes Helm chart
└── docker-compose.yml      # Full stack orchestration
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🔗 Links

- **Security & Attack Coverage**: [SECURITY.md](SECURITY.md)
- **Documentation**: [docs/](docs/)
- **API Reference**: `http://localhost:8000/docs`
- **Deployment Guide**: [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md)
- **Developer Reference**: [docs/DEVELOPER_REFERENCE.md](docs/DEVELOPER_REFERENCE.md)

---

**Built with ❤️ for the security community.**
