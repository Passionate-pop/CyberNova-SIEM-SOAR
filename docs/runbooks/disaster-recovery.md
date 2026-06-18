# CyberNova — Disaster Recovery Runbook

## Recovery Objectives

| Metric | Target | Criticality |
|--------|--------|-------------|
| **RPO** (Recovery Point Objective) | ≤ 1 hour | Data loss tolerance |
| **RTO** (Recovery Time Objective) | ≤ 15 minutes | Single instance failure |
| **RTO** (Recovery Time Objective) | ≤ 1 hour | Full region / data center failure |
| **RTO** (Recovery Time Objective) | ≤ 4 hours | Database corruption / point-in-time recovery |
| **Verification** | ≤ 30 minutes post-recovery | Integrity validation |

---

## Table of Contents

1. [Pre-Requisites](#1-pre-requisites)
2. [Architecture Overview](#2-architecture-overview)
3. [Scenario A: Single App Instance Failure](#3-scenario-a-single-app-instance-failure)
4. [Scenario B: Database Failure / Corruption](#4-scenario-b-database-failure--corruption)
5. [Scenario C: Redis Failure](#5-scenario-c-redis-failure)
6. [Scenario D: Full Region / Data Center Failure](#6-scenario-d-full-region--data-center-failure)
7. [Scenario E: Point-in-Time Recovery](#7-scenario-e-point-in-time-recovery)
8. [Post-Recovery Verification](#8-post-recovery-verification)
9. [Backup Verification Schedule](#9-backup-verification-schedule)
10. [Escalation Contacts](#10-escalation-contacts)

---

## 1. Pre-Requisites

### Required Access

- **Kubernetes** (`kubectl`) — cluster admin context
- **Cloud provider console** — AWS / GCP project with backup bucket access
- **PostgreSQL** (`psql`, `pg_restore`, `pg_dump`) — version 15+
- **Backup storage** — read access to `BACKUP_S3_BUCKET` or `BACKUP_GCS_BUCKET`
- **Redis** (`redis-cli`) — for Sentinel-managed failover verification

### Required Credentials

| Credential | Source |
|---|---|
| `POSTGRES_PASSWORD` | Kubernetes secret `cybernova-db` |
| `REDIS_PASSWORD` | Kubernetes secret `cybernova-redis` |
| `JWT_SECRET` | Kubernetes secret `cybernova-auth` |
| `ADMIN_PASSWORD` | LastPass / 1Password vault |
| AWS / GCP service account key | Cloud IAM console |

### Environment Information

| Parameter | Value Template |
|---|---|
| Primary DB endpoint | `postgres://cybernova@postgres-primary:5432/cybernova` |
| Read replica endpoint | `postgres://cybernova@postgres-replica:5432/cybernova` |
| Redis Sentinel endpoints | `sentinel-0:26379,sentinel-1:26379,sentinel-2:26379` |
| S3 backup bucket | `s3://cybernova-backups-{env}/` |
| GCS backup bucket | `gs://cybernova-backups-{env}/` |
| Kubernetes namespace | `cybernova` |

---

## 2. Architecture Overview

```
                    ┌──────────────┐
                    │  Load        │
                    │  Balancer    │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ App      │ │ App      │ │ App      │
        │ Replica  │ │ Replica  │ │ Replica  │
        │ (active) │ │(passive) │ │(passive) │
        └─────┬────┘ └────┬─────┘ └────┬─────┘
              │            │            │
              └──────┬─────┘            │
                     │                  │
              ┌──────▼───────┐   ┌──────▼──────┐
              │  PostgreSQL  │   │  Redis      │
              │  Primary     │   │  Sentinel   │
              │  + Replica   │   │  Cluster    │
              └──────────────┘   └─────────────┘
```

- **Active-passive failover**: Redis leader election (SET NX EX 30). Pipeline runs only on leader.
- **Read replicas**: Dashboard queries route to PostgreSQL read replica.
- **Redis Sentinel**: Automatic Redis master failover.
- **Backups**: Daily `pg_dump -Fc` to S3 and/or GCS. 30-day retention.
- **DLQ**: Failed pipeline events retried with exponential backoff (30s, 60s, 120s). Alerts created when retries exhausted.

---

## 3. Scenario A: Single App Instance Failure

**RTO:** ≤ 15 minutes

### Symptoms

- `GET /health` returns 503 for one pod
- Load balancer shows one backend unhealthy
- Pod in `CrashLoopBackOff` or `Error` state

### Diagnosis

```bash
# Check pod status
kubectl get pods -n cybernova -l app=cybernova

# View logs
kubectl logs -n cybernova -l app=cybernova --tail=100

# Describe pod for resource/health details
kubectl describe pod -n cybernova <pod-name>

# Check leader status via surviving replica
curl -s http://<surviving-pod>:8000/api/v1/ha/status
```

### Recovery Procedure

1. **Automatic**: Kubernetes `Deployment` with `replicas: 3` and `readinessProbe` auto-restarts the pod. Leader election promotes a passive replica to active within 30 seconds.

2. **Manual (if auto-recovery fails)**:
   ```bash
   # Force restart the failed pod
   kubectl delete pod -n cybernova <failed-pod-name>
   
   # Or scale up to replace
   kubectl scale deployment -n cybernova cybernova-app --replicas=3
   ```

3. **Verify**:
   ```bash
   # Wait for all pods to be ready
   kubectl wait --for=condition=Ready pods -n cybernova -l app=cybernova --timeout=60s
   
   # Check health endpoint
   curl -s http://localhost:8000/health | jq .
   
   # Confirm a leader exists
   curl -s http://localhost:8000/api/v1/ha/status | jq .
   ```

---

## 4. Scenario B: Database Failure / Corruption

**RTO:** ≤ 4 hours  
**RPO:** ≤ 1 hour (or last verified backup)

### Symptoms

- `GET /health` shows `"database": "failed"`
- `GET /api/v1/ha/health` returns unhealthy for `database`
- Application logs show `psycopg2.OperationalError: connection to server`
- Dashboard endpoints return 500 errors
- `SELECT 1` fails from `psql`

### Severity Levels

| Level | Condition | Action |
|-------|-----------|--------|
| **B1** | Connection pool exhausted | Increase `db_pool_size`, restart app |
| **B2** | Read replica lag > 30s | Fail dashboard queries to primary |
| **B3** | Primary corrupt / unreachable | Restore from latest backup |
| **B4** | Both primary and replica lost | Cross-region restore |

### B1: Connection Pool Exhaustion

```bash
# Check active connections
psql "$DATABASE_URL" -c "SELECT count(*) FROM pg_stat_activity;"
psql "$DATABASE_URL" -c "SELECT state, count(*) FROM pg_stat_activity GROUP BY state;"

# Kill idle connections
psql "$DATABASE_URL" -c "
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE state = 'idle'
  AND pid <> pg_backend_pid();
"

# Increase pool settings and restart app
kubectl set env deployment/cybernova-app DB_POOL_SIZE=50 DB_MAX_OVERFLOW=25
kubectl rollout restart deployment/cybernova-app
```

### B2: Read Replica Lag

```bash
# Check replica lag
psql "$DATABASE_URL" -c "SELECT now() - pg_last_xact_replay_timestamp() AS replication_lag;"

# If lag > 30s, fail dashboard to primary:
# Set DATABASE_URL_REPLICA to empty string (forces read-only sessions to primary)
kubectl set env deployment/cybernova-app DATABASE_URL_REPLICA=""
kubectl rollout restart deployment/cybernova-app

# Investigate replica health
psql "$DATABASE_URL" -c "SELECT * FROM pg_stat_replication;"
```

### B3: Primary Database Restore

```bash
# ── Phase 1: Isolate ──

# 1. Stop app pods to prevent further writes
kubectl scale deployment/cybernova-app --replicas=0 -n cybernova

# 2. Stop any background job pods
kubectl scale deployment/cybernova-backup --replicas=0 -n cybernova

# 3. Verify the primary is unreachable
psql -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" -c "SELECT 1;" || echo "Primary unreachable — confirmed"


# ── Phase 2: Identify best backup ──

# 4. List available local backups
ls -la /backups/cybernova_pg_*.dump

# 5. List S3 backups (if configured)
aws s3 ls s3://${BACKUP_S3_BUCKET}/postgres/ --human-readable | sort

# 6. List GCS backups (if configured)
gsutil ls -l gs://${BACKUP_GCS_BUCKET}/postgres/ | sort

# 7. Select the latest backup before the corruption time
#    Example: corruption detected at 14:30, use backup from 02:00 same day
LATEST_BACKUP=$(find /backups -name 'cybernova_pg_*.dump' -type f | sort | tail -1)
echo "Selected backup: ${LATEST_BACKUP}"


# ── Phase 3: Verify backup integrity ──

# 8. Verify backup before restoring to primary
./scripts/verify-backup.sh --backup-file "${LATEST_BACKUP}"

#    If verification fails, try the previous backup:
#    SECOND_BACKUP=$(find /backups -name 'cybernova_pg_*.dump' -type f | sort | tail -2 | head -1)


# ── Phase 4: Restore ──

# 9. Restore to primary database
./scripts/restore.sh "${LATEST_BACKUP}"

# 10. Verify the restored database
psql "$DATABASE_URL" -c "SELECT count(*) FROM tenants;"
psql "$DATABASE_URL" -c "SELECT count(*) FROM users;"
psql "$DATABASE_URL" -c "SELECT tablename FROM pg_tables WHERE schemaname='public';"


# ── Phase 5: Resume ──

# 11. Re-enable Redis dependencies (DLQ replay etc.)
kubectl scale deployment/cybernova-backup --replicas=1 -n cybernova

# 12. Start app pods
kubectl scale deployment/cybernova-app --replicas=3 -n cybernova

# 13. Monitor recovery
kubectl wait --for=condition=Ready pods -n cybernova -l app=cybernova --timeout=120s
curl -s http://localhost:8000/health | jq .
```

### B4: Cross-Region Restore

```bash
# 1. Failover to standby region
#    Update DNS CNAME to point to standby region load balancer

# 2. Restore from cross-region backup
aws s3 cp s3://${BACKUP_S3_BUCKET}-dr/postgres/cybernova_pg_*.dump /tmp/latest.dump \
    --region us-west-2

# 3. Restore to standby region PostgreSQL
PGHOST=standby-postgres.example.com ./scripts/restore.sh /tmp/latest.dump

# 4. Update app config to point to standby DB
kubectl set env deployment/cybernova-app DATABASE_URL="postgresql+asyncpg://...standby-postgres..."

# 5. Rollout and verify
kubectl rollout restart deployment/cybernova-app
```

---

## 5. Scenario C: Redis Failure

**RTO:** ≤ 15 minutes

### Symptoms

- `GET /health` shows `"redis": "unavailable"`
- App logs: `Redis unavailable — running without Redis`
- Pipeline falls back to in-memory mode
- Leader election falls back to local mode (all instances become leader)

### C1: Single Redis Node Failure (Sentinel Managed)

1. **Automatic**: Sentinel promotes a replica to master within ~10 seconds.
2. **Verify**:
   ```bash
   # Check which instance is master
   redis-cli -h sentinel-0 -p 26379 SENTINEL get-master-addr-by-name mymaster

   # Check Sentinel status
   redis-cli -h sentinel-0 -p 26379 SENTINEL masters
   
   # Verify app reconnected
   curl -s http://localhost:8000/api/v1/ha/health | jq '.checks.redis'
   ```

### C2: Complete Redis Cluster Failure

```bash
# ── Phase 1: App degrades gracefully ──

# The app auto-detects Redis unavailability and runs in degraded mode:
# - Pipeline uses InMemoryBus fallback
# - Leader election sets _local_mode = True (all instances are leader)
# - Dashboard caching disabled (direct DB queries)
# - Rate limiting falls back to in-memory counters

# No immediate action required — app self-heals when Redis returns.


# ── Phase 2: Restore Redis cluster ──

# 1. Check Redis pod status
kubectl get pods -n cybernova -l app=redis

# 2. Restart failed Redis pods
kubectl delete pod -n cybernova redis-0

# 3. Wait for Sentinel to re-elect
sleep 15

# 4. Verify Sentinel cluster health
redis-cli -h sentinel-0 -p 26379 SENTINEL masters | grep -E "name|status|address"


# ── Phase 3: Verify app reconnection ──

# 5. App detects Redis within 30s (health_check_interval in connection pool)
curl -s http://localhost:8000/api/v1/ha/health | jq '.checks.redis'
curl -s http://localhost:8000/api/v1/ha/status | jq '.leader_election'
```

---

## 6. Scenario D: Full Region / Data Center Failure

**RTO:** ≤ 1 hour  
**RPO:** ≤ 1 hour

### Pre-Requisites for Cross-Region Recovery

- Standby region with identical infrastructure (Terraform/Pulumi)
- Cross-region backup replication (S3 cross-region replication or `gsutil rsync`)
- DNS failover configured (Route53 health checks / GCP Cloud DNS)
- Read-only standby PostgreSQL instance running

### Recovery Procedure

```bash
# ── Phase 1: Activate standby region ──

# 1. Promote standby PostgreSQL to primary
psql -h standby-postgres -U cybernova -c "SELECT pg_promote();"

# 2. Verify standby DB is accepting writes
psql -h standby-postgres -U cybernova -d cybernova -c "CREATE TABLE dr_test (id int); DROP TABLE dr_test;"

# 3. Update app deployment to point to new primary
kubectl set env deployment/cybernova-app \
    DATABASE_URL="postgresql+asyncpg://cybernova@standby-postgres:5432/cybernova"
kubectl set env deployment/cybernova-app \
    DATABASE_URL_REPLICA="postgresql+asyncpg://cybernova@standby-postgres:5432/cybernova"


# ── Phase 2: Start app in standby region ──

# 4. Scale up app in standby region
kubectl scale deployment/cybernova-app --replicas=3 -n cybernova

# 5. Verify leader election
sleep 15
curl -s http://standby-app:8000/api/v1/ha/status | jq '.leader_election'


# ── Phase 3: DNS failover ──

# 6. Update DNS A/CNAME record to point to standby region load balancer
#    (Route53: aws route53 change-resource-record-set)
#    (Cloud DNS: gcloud dns record-sets update)


# ── Phase 4: Post-recovery ──

# 7. Run full integrity checks
./scripts/verify-backup.sh

# 8. Configure cross-region replication from new primary back to original region
#    (for when original region recovers)
```

---

## 7. Scenario E: Point-in-Time Recovery

**RPO:** ≤ 5 minutes (requires WAL archiving to S3/GCS)

### Pre-Requisites

- PostgreSQL WAL archiving enabled: `archive_mode = on`, `archive_command = 'aws s3 cp %p s3://${BACKUP_S3_BUCKET}/wal/%f'`
- Latest base backup available

### Procedure

```bash
# ── Identify target recovery time ──

# Example: an errant DELETE FROM alerts occurred at 2026-05-15 14:23:00 UTC
TARGET_TIME="2026-05-15 14:22:00 UTC"  # 1 minute before incident


# ── Recovery using pg_restore + WAL replay ──

# 1. Restore base backup to a temporary instance
pg_restore -d cybernova_recover /backups/cybernova_pg_20260515_020000.dump

# 2. Configure recovery.conf
cat >> /var/lib/postgresql/data/recovery.conf << EOF
restore_command = 'aws s3 cp s3://${BACKUP_S3_BUCKET}/wal/%f %p'
recovery_target_time = '${TARGET_TIME}'
recovery_target_action = 'promote'
EOF

# 3. Start PostgreSQL in recovery mode
pg_ctl start -D /var/lib/postgresql/data

# 4. Verify recovered data
psql -d cybernova_recover -c "SELECT count(*) FROM alerts WHERE created_at > '2026-05-15 14:20:00';"

# 5. Export recovered data to production
pg_dump -d cybernova_recover -t alerts \
    -c > recovered_alerts.sql
psql -d cybernova -f recovered_alerts.sql
```

---

## 8. Post-Recovery Verification

After any recovery operation, run the following checklist:

### 8.1 Application Health

```bash
# Basic health
curl -s http://localhost:8000/ | jq .
curl -s http://localhost:8000/health | jq .
curl -s http://localhost:8000/ready | jq .

# Detailed health
curl -s http://localhost:8000/health/detailed | jq .

# HA status (leader exists?)
curl -s http://localhost:8000/api/v1/ha/status | jq .
curl -s http://localhost:8000/api/v1/ha/leader | jq .
```

### 8.2 Database Integrity

```bash
# Run full backup verification
./scripts/verify-backup.sh

# Quick checks
psql "$DATABASE_URL" -c "
    SELECT 'tenants' AS tbl, count(*) FROM tenants
    UNION ALL
    SELECT 'users', count(*) FROM users
    UNION ALL
    SELECT 'alerts', count(*) FROM alerts
    UNION ALL
    SELECT 'devices', count(*) FROM devices
    ORDER BY tbl;
"
```

### 8.3 Pipeline Health

```bash
# Pipeline status
curl -s http://localhost:8000/api/v1/pipeline/status | jq .

# SLA metrics (P99, availability)
curl -s http://localhost:8000/api/v1/monitoring/sla | jq .

# Circuit breakers
curl -s http://localhost:8000/api/v1/monitoring/circuit-breakers | jq .
```

### 8.4 Dashboard Functionality

```bash
# Dashboard endpoints (with auth token)
TOKEN="<bearer-token>"
curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:8000/api/v1/dashboard/summary | jq .
curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:8000/api/v1/dashboard/executive | jq .
```

### 8.5 Data Integrity (Post-Recovery)

```bash
# Check for orphaned records
psql "$DATABASE_URL" -c "
    SELECT count(*) FROM alerts a
    LEFT JOIN tenants t ON a.tenant_id = t.id
    WHERE t.id IS NULL;
"

# Verify WORM chain integrity (if applicable)
curl -s http://localhost:8000/api/v1/worm/verify | jq .
```

### 8.6 Functional Smoke Test

```bash
# Ingest a test event
curl -s -X POST http://localhost:8000/api/v1/ingest/event \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"event_type": "test", "message": "DR recovery smoke test"}'

# Verify it was processed
curl -s http://localhost:8000/api/v1/dashboard/activity?limit=5 \
    -H "Authorization: Bearer $TOKEN" | jq '.[0]'

# Check no new DLQ entries
curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:8000/api/v1/admin/dlq | jq '. | length'
```

---

## 9. Backup Verification Schedule

| Frequency | Action | Responsible |
|---|---|---|
| **Daily** | Automated `pg_dump` to S3/GCS | CronJob / system |
| **Weekly** | `verify-backup.sh` restore + integrity check | CronJob / SRE |
| **Monthly** | Full DR drill (cross-region failover) | SRE team |
| **Quarterly** | Point-in-time recovery drill | SRE team |
| **Per-release** | Update this runbook | Dev team |

### Automated Verification

```yaml
# Kubernetes CronJob: weekly backup verification
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cybernova-verify-backup
  namespace: cybernova
spec:
  schedule: "0 6 * * 0"        # Every Sunday at 06:00 UTC
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: verify
            image: cybernova-backup:latest
            command:
            - /scripts/verify-backup.sh
            env:
            - name: VERIFY_PGHOST
              value: "postgres-staging"
            - name: BACKUP_S3_BUCKET
              value: "cybernova-backups-prod"
            - name: BACKUP_S3_REGION
              value: "us-east-1"
          restartPolicy: OnFailure
```

---

## 10. Escalation Contacts

| Role | Contact | Responsibility |
|---|---|---|
| **Primary SRE** | `@sre-pager` (PagerDuty) | First response, recovery execution |
| **Secondary SRE** | `#sre-backup` (Slack) | Backup verification, second opinion |
| **Database Admin** | `@dba` (PagerDuty) | PostgreSQL corruption / PITR |
| **Security Engineer** | `#security` (Slack) | Post-recovery security audit |
| **Engineering Lead** | `@eng-lead` (Slack) | Decision authority for cross-region failover |

### Escalation Flow

```
Incident Detected
       │
       ▼
  Primary SRE (15 min) ─── Resolved? ──→ Done
       │
       ▼
  Secondary SRE (15 min) ─── Resolved? ──→ Done
       │
       ▼
  DBA / Engineer Lead (30 min) ─── Resolved? ──→ Done
       │
       ▼
  VP Engineering (1 hour) ─── Cross-region failover decision
```

---

## Appendix A: Quick-Reference Commands

| Action | Command |
|--------|---------|
| Backup | `./scripts/db-backup.sh` |
| Verify backup | `./scripts/verify-backup.sh --backup-file <path>` |
| Restore | `./scripts/restore.sh <backup-file>` |
| Check health | `curl localhost:8000/health` |
| Check readiness | `curl localhost:8000/ready` |
| Check HA status | `curl localhost:8000/api/v1/ha/status` |
| List backups (local) | `ls -la /backups/cybernova_pg_*.dump` |
| List backups (S3) | `aws s3 ls s3://$BUCKET/postgres/` |
| List backups (GCS) | `gsutil ls gs://$BUCKET/postgres/` |

## Appendix B: RTO/RPO Calculator

Use this table to estimate recovery time based on backup size:

| Backup Size | Restore Time (pg_restore) | Upload Time (1 Gbps) |
|-------------|--------------------------|---------------------|
| 1 GB | ~1 min | ~8 sec |
| 10 GB | ~5 min | ~1 min |
| 100 GB | ~30 min | ~13 min |
| 500 GB | ~2 hours | ~68 min |
| 1 TB | ~4 hours | ~2.3 hours |

## Appendix C: Recovery Decision Tree

```
Database unhealthy?
├── Connection pool exhausted? → Increase pool size → Done
├── Read replica lag > 30s? → Failover to primary → Done
├── Primary corrupt?
│   ├── WAL archiving enabled? → Point-in-time recovery (RPO: 5 min)
│   └── No WAL? → Full restore from latest backup (RPO: ≤ 1 hour)
└── Both primary and replica lost?
    └── Cross-region restore (RTO: ≤ 4 hours)

Redis unhealthy?
├── Single node down? → Sentinel auto-failover (RTO: 10s)
├── All nodes down? → Degraded mode (RTO: 0s, no RPO)
└── Persistent failure? → Restore Redis cluster (RTO: 15 min)

App instance unhealthy?
├── Single pod crash? → Kubernetes auto-restart (RTO: 30s)
├── Multiple pods crash? → Leader election promotes passive (RTO: 30s)
└── All pods crash? → kubectl rollout restart (RTO: 5 min)
```
