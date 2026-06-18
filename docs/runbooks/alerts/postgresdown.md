# Alert: PostgresDown

**Severity:** critical  
**Category:** service_health  

## Description

PostgreSQL database is unreachable.

## Threshold

```
up{job='postgres'} == 0 for 1m
```

## Impact

Alert persistence, user authentication, audit logging, and all database-backed operations are unavailable. Detection rules cannot be loaded from DB.

## Troubleshooting

1. Check Postgres pod: `kubectl get pods -l app=postgres`
2. Inspect Postgres logs: `kubectl logs -l app=postgres --tail=50`
3. Check disk space: `kubectl exec -it postgres -- df -h`
4. Check connection count: `kubectl exec -it postgres -- psql -c 'SELECT count(*) FROM pg_stat_activity;'`
5. Verify persistent volume claim is bound

## Mitigation

1. Restart Postgres: `kubectl rollout restart statefulset/postgres`
2. If disk-full, extend PVC or clean old WAL files
3. If connection storm, increase `max_connections` then investigate source
4. If corrupt, restore from latest pg_dump backup

## Escalation

P1 incident — page on-call and DBA. Data loss risk.

## Related Dashboards

- Platform Overview
- Service Health panels

## Related Documents

- Disaster Recovery (docs/runbooks/disaster-recovery.md)
