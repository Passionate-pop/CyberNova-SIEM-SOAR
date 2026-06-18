# CyberNova SIEM - Full Technical Checklist & Product Specification

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Pipeline Flow](#pipeline-flow)
3. [File-by-File Reference](#file-by-file-reference)
4. [Enterprise Requirements Gap Analysis](#enterprise-requirements-gap-analysis)
5. [Product Tier Classification](#product-tier-classification)
6. [Roadmap to Tier 1](#roadmap-to-tier-1)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                      DATA FLOW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                  │
│  [HOST AGENT] ──► [API:Gateway] ──► [Ingest Queue]                       │
│       │                                    │                              │
│       │                                    ▼                              │
│       │                            ┌─────────────────┐               │
│       │                            │  REDIS DEDUPE   │────► DROP   │
│       │                            └─────────────────┘               │
│       │                                    │                              │
│       │                                    ▼                              │
│       │                            ┌─────────────────┐               │
│       │                            │  REDIS LOCK   │────► SKIP   │
│       │                            └─────────────────┘               │
│       │                                    │                              │
│       │                                    ▼                              │
│       │                            ┌─────────────────┐               │
│       │                            │  RULES ENGINE │              │
│       │                            │  (Detection)  │              │
│       │                            └─────────────────┘               │
│       │                                    │                              │
│       │                                    ▼                              │
│       │                            ┌─────────────────┐               │
│       │                            │  CORRELATION   │              │
│       │                            │   ENGINE       │              │
│       │                            └─────────────────┘               │
│       │                                    │                              │
│       │                                    ▼                              │
│       │                            ┌─────────────────┐               │
│       │                            │  INCIDENT DB   │              │
│       │                            │ (Risk Score)   │              │
│       │                            └─────────────────┘               │
│       │                                    │                              │
│       │                                    ▼                              │
│       │                            ┌─────────────────┐               │
│       │                            │  SOAR ENGINE   │              │
│       │                            │  (Gated)       │              │
│       │                            └─────────────────┘               │
│       │                                    │                              │
│       ▼                                    ▼                              │
│  ┌──────────────────────────────────────────────────┐              │
│  │              REST API (AUTH PROTECTED)             │              │
│  │  /incidents /metrics /audit /incidents/{id}/close  │              │
│  └──────────────────────────────────────────────────┘              │
│                                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Flow (Step-by-Step)

### Stage 1: Data Collection
| Step | Component | What Happens | Files |
|------|----------|-------------|-------|
| 1.1 | Host Agent | Collects system events (network, process, file, registry, USB, PowerShell, browser) | `host_agent.py` |
| 1.2 | Event Formatting | Creates SecurityEvent with: event_type, severity, source_ip, dest_ip, hostname, timestamp | `host_agent.py` lines 33-73 |
| 1.3 | Local Filtering | Threshold-based (50+ connections), whitelist (SAFE_IPS, SAFE_DOMAIN_SUFFIXES), skip safe patterns | `host_agent.py` lines 88-145 |

### Stage 2: Ingestion & Deduplication
| Step | Component | What Happens | Files |
|------|----------|-------------|-------|
| 2.1 | HTTP POST | Sends to `/api/v1/ingest/agent` | `host_agent.py` line 201-219 |
| 2.2 | Auth | Validates JWT token | `auth/jwt_auth.py` |
| 2.3 | Redis Dedup | 60s window, key = event_type:source_ip:dest_ip:time_bucket | `database/redis/dedupe.py` lines 30-48 |
| 2.4 | Redis Lock | Prevents race conditions on incident creation | `database/redis/dedupe.py` lines 50-72 |

### Stage 3: Detection
| Step | Component | What Happens | Files |
|------|----------|-------------|-------|
| 3.1 | Rules Engine | Evaluates alert against registered rules | `backend/rules_engine.py` |
| 3.2 | EncodedPowerShellRule | Detects: -enc, base64, IEX, Invoke-Expression | `backend/rules_engine.py` lines 35-65 |
| 3.3 | ExternalBurstRule | Detects 50+ connections in 60s | `backend/rules_engine.py` lines 67-100 |
| 3.4 | SimpleRules | suspicious_download, startup_persistence | `backend/rules_engine.py` lines 102-115 |

### Stage 4: Correlation
| Step | Component | What Happens | Files |
|------|----------|-------------|-------|
| 4.1 | Correlation Engine | Checks alert against multi-event patterns | `correlation/engine.py` |
| 4.2 | BruteForce Rule | 5 failed_login + 1 success → brute_force_compromise | `correlation/engine.py` lines 40-65 |
| 4.3 | Intrusion Rule | port_scan + exploitation_attempt | `correlation/engine.py` lines 70-85 |
| 4.4 | Malware Rule | malicious_process/script/file | `correlation/engine.py` lines 88-105 |

### Stage 5: Incident Management
| Step | Component | What Happens | Files |
|------|----------|-------------|-------|
| 5.1 | Find Similar | Joins incidents + incidents_alerts on (event_type, source_ip, dest_ip, 5min window) | `database/postgres/incidents.py` lines 85-110 |
| 5.2 | Create Incident | If no match: INSERT into incidents with UUID | `database/postgres/incidents.py` lines 112-140 |
| 5.3 | Risk Accumulation | risk_score += alert.risk, cap at 1000 | `database/postgres/incidents.py` lines 160-200 |
| 5.4 | Severity Escalation | 150+ → critical, 80+ → high, 40+ → medium | `database/postgres/incidents.py` lines 202-215 |
| 5.5 | Evidence-Based Confirm | risk >= 120 OR pattern match → confirmed=TRUE | `database/postgres/incidents.py` lines 220-235 |
| 5.6 | Attach Alert | INSERT incidents_alerts + UPDATE incident | `database/postgres/incidents.py` lines 237-290 |

### Stage 6: Automated Response
| Step | Component | What Happens | Files |
|------|----------|-------------|-------|
| 6.1 | Fetch Incident | Get full incident details | `database/postgres/incidents.py` lines 305-340 |
| 6.2 | SOAR Gate Check | confirmed AND (risk >= 120 OR severity=critical) | `soar/engine.py` lines 85-110 |
| 6.3 | Action Execution | webhook, block_ip (simulated), log | `soar/engine.py` lines 30-100 |

### Stage 7: API & Visibility
| Step | Component | What Happens | Files |
|------|----------|-------------|-------|
| 7.1 | List Incidents | GET with filters: severity, confirmed, status, incident_type | `api/incidents.py` lines 65-120 |
| 7.2 | Incident Detail | GET single incident with timeline | `api/incidents.py` lines 122-155 |
| 7.3 | Child Alerts | GET all alerts for incident | `api/incidents.py` lines 157-185 |
| 7.4 | Lifecycle | POST close/reopen | `api/incidents.py` lines 187-235 |
| 7.5 | Metrics | GET pipeline stats | `api/incidents.py` lines 237-275 |
| 7.6 | Audit Log | GET audit trail | `audit/service.py` |

---

## File-by-File Reference

### Core Pipeline Files

| File | Purpose | Key Functions | Lines |
|------|---------|---------------|--------|
| `host_agent.py` | Windows security agent | SecurityEvent, HostAgent, _check_network, _map_severity | 808 |
| `cybernova/ingest/pipeline.py` | Ingestion orchestration | ingest_alert | 95 |
| `cybernova/database/redis/dedupe.py` | Redis dedupe + lock | is_duplicate, acquire_lock | 80 |
| `cybernova/database/postgres/incidents.py` | Incident DB ops | find_similar_incident, create_incident, attach_alert, get_incident, apply_risk_decay | 350 |
| `cybernova/database/postgres/incidents.sql` | DB schema | incidents, incidents_alerts tables | 30 |
| `cybernova/backend/rules_engine.py` | Detection rules | RulesEngine, EncodedPowerShellRule, ExternalBurstRule | 180 |
| `cybernova/correlation/engine.py` | Correlation engine | evaluate_correlation, create_correlated_incident | 150 |
| `cybernova/soar/engine.py` | SOAR automation | SoarEngine, trigger_soar | 130 |
| `cybernova/api/incidents.py` | REST API | All endpoints with RBAC | 283 |

### Supporting Files

| File | Purpose | Key Functions | Lines |
|------|---------|---------------|--------|
| `cybernova/auth/jwt_auth.py` | JWT authentication | create_token, decode_token, require_permission | 120 |
| `cybernova/monitoring/metrics.py` | Observability | MetricsCollector, get_pipeline_metrics | 160 |
| `cybernova/queue/retry_queue.py` | Retry queue + DLQ | push_to_retry, process_retry_queue | 110 |
| `cybernova/audit/service.py` | Audit trail | audit_service (DB-backed) | ~300 |

### Test Files

| File | Purpose | Tests |
|------|---------|-------|
| `tests/soc_validation.py` | SOC-grade validation | Noise, dedup, correlation, risk, SOAR, lifecycle |
| `tests/correlation_test.py` | Correlation harness | 5 failed + 1 success |

---

## Enterprise Requirements Gap Analysis

### Current State vs Enterprise Requirements

| Requirement | Status | Gap Severity | Notes |
|-------------|--------|-------------|-------|
| **Authentication** | ✅ Implemented | - | JWT + RBAC (admin/analyst/viewer) |
| **Authorization** | ✅ Implemented | - | Permission-based (read/write/delete) |
| **Multi-Tenant** | ❌ Missing | CRITICAL | Single tenant ("default") |
| **Retry Queue** | ✅ Implemented | - | Redis-based with DLQ |
| **Dead Letter Queue** | ✅ Implemented | - | DLQ for failed events |
| **Audit Logging** | ✅ Implemented | - | User, action, resource, timestamp |
| **Observability** | ⚠️ Partial | MEDIUM | In-memory metrics, no Prometheus exp |
| **Time Decay** | ✅ Implemented | - | 5% per 10 minutes |
| **Multi-Instance** | ❌ Missing | HIGH | Race conditions possible |
| **Queue Persistence** | ⚠️ Redis Only | MEDIUM | Kafka would be better |
| **Encryption** | ❌ Missing | CRITICAL | No TLS between components |
| **Rate Limiting** | ⚠️ Basic | LOW | Generic rate limit exists |
| **Backup/Recovery** | ❌ Missing | HIGH | No backup strategy |
| **SLA Monitoring** | ⚠️ Partial | MEDIUM | No formal SLA tracking |

### Feature Checklist for Enterprise SaaS

```
✅ = Implemented    ⚠️ = Partial    ❌ = Missing    🔴 = Critical

Core SIEM Features:
✅ Real-time ingestion
✅ Event normalization
✅ Rule-based detection
✅ Correlation (multi-event)
✅ Incident management
✅ Risk scoring (accumulation + escalation)
✅ Evidence-based confirmation
✅ SOAR automation (gated)
✅ REST API (incidents-first)
✅ Authentication/JWT
✅ Authorization/RBAC
🔴 Multi-tenancy
⚠️ Encryption (at rest / in transit)

Data Integrity:
✅ Retry queue
✅ Dead Letter Queue
🔴 Transaction logging
⚠️ Backup/Recovery
⚠️ Data archival

Observability:
⚠️ Metrics (basic)
🔴 Prometheus export
🔴 Grafana dashboards
🔴 Alerting on failures

Scalability:
🔴 Multi-instance coordination
🔴 Message queue (Kafka)
🔴 Horizontal scaling
🔴 CDN integration

Compliance:
⚠️ Audit logging
🔴 GDPR controls
🔴 Data residency
🔴 SOC 2 / ISO 27001
```

---

## Product Tier Classification

### Tier 4: Proof of Concept ✅ PASSED
- Basic event collection
- Simple rules
- No correlation
- Open API

### Tier 3: Functional SIEM ✅ PASSED
- Rule-based detection
- Multi-event correlation
- Risk scoring
- Incident model
- SOAR-lite

### Tier 2: Production-Capable ⚠️ ALMOST
- Auth + RBAC enforced
- Retry queue + DLQ
- Audit logging
- Time decay
- Basic observability

**What's missing for Tier 2:**
- [ ] Multi-tenancy (for SaaS)
- [ ] Prometheus/Grafana
- [ ] Backup strategy
- [ ] Encryption

### Tier 1: Enterprise SaaS 🔴 NOT YET
- Multi-tenant with isolation
- Kafka-based ingestion
- Full encryption
- Prometheus + Grafana
- Backup/DR automation
- SLA tracking
- SOC 2 / ISO 27001 ready

---

## Roadmap to Tier 1

### Phase 1: Multi-Tenancy (Weeks 1-2)
```
Priority: CRITICAL

- Add tenant_id to all tables (incidents, incidents_alerts)
- Add tenant_id filter to all queries
- Add tenant isolation in auth
- Add tenant-level RBAC (tenant admin, analyst, viewer)
- Multi-tenant endpoint: GET /api/v1/tenants
```

### Phase 2: Observability (Weeks 3-4)
```
Priority: HIGH

- Prometheus exporter for metrics
- Grafana dashboard templates
- Alert rules:
  • ingestion_drop_rate > 10%
  • retry_queue_length > 100
  • failed_correlation_rate > 5%
- Pipeline latency tracking
- Health check /ready
```

### Phase 3: Data Resilience (Weeks 5-6)
```
Priority: HIGH

- Kafka migration from Redis
- Point-in-time recovery
- Database backup automation
- Archive old incidents (>90 days)
- Data retention policies
```

### Phase 4: Security Hardening (Weeks 7-8)
```
Priority: CRITICAL

- TLS between all components
- Secrets management (HashiCorp Vault)
- Rate limiting per tenant
- IP allowlisting
- API key management
```

### Phase 5: Compliance (Weeks 9-10)
```
Priority: MEDIUM

- GDPR data export
- GDPR deletion
- Audit trail export
- SOC 2 controls documentation
- ISO 27001 alignment
```

---

## Technical Debt & Known Issues

| Issue | Severity | Fix |
|-------|----------|-----|
| In-memory metrics reset on restart | LOW | Use Redis/Prometheus |
| No connection pooling | MEDIUM | Add psycopg2 pool |
| Hardcoded secrets | CRITICAL | Use environment/vault |
| No health checks on DB | MEDIUM | Add /ready endpoint |
| Limited test coverage | HIGH | Add integration tests |

---

## Final Verdict

### Current Classification: **Tier 2 (Production-Capable - Almost)**

CyberNova can be deployed internally with confidence for:
- Internal SOC operations
- Startup security monitoring
- Security demonstration/POC
- Learning SIEM architecture

### To reach Tier 1 (Enterprise SaaS):
- ~10 weeks of additional development
- Multi-tenancy is the hardest requirement
- Observability needs completion
- Security hardening required

### What's Built Correctly:
- Detection engine (better than most open-source)
- Correlation (proper multi-event)
- Risk scoring (enterprise-appropriate)
- Incident lifecycle (complete)
- Gated SOAR (safe automation)

This is a legitimate SIEM core that would require ~30-40% more work to become a sellable SaaS product.

---

*Document Version: 1.0*
*Last Updated: 2026-04-19*