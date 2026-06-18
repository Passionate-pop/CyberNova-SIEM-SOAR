# Alert: BackendDown

**Severity:** critical  
**Category:** service_health  

## Description

Backend API service is unreachable.

## Threshold

```
up{job='cybernova-backend'} == 0 for 2m
```

## Impact

All API endpoints are unavailable. Event ingestion, alert queries, and dashboard access are blocked. No new data enters the system.

## Troubleshooting

1. Check pod status: `kubectl get pods -l app=cybernova-backend`
2. Inspect logs: `kubectl logs -l app=cybernova-backend --tail=100`
3. Check resource usage: `kubectl top pod -l app=cybernova-backend`
4. Verify liveness probe: `kubectl describe pod -l app=cybernova-backend | grep Liveness`
5. Check for recent config changes in the last deployed version

## Mitigation

1. Restart the deployment: `kubectl rollout restart deployment/cybernova-backend`
2. If OOM-killed, increase memory limits in deployment manifest
3. If crash-looping, rollback to the last known-good version
4. Check database connectivity from the backend pod

## Escalation

P1 incident — page on-call via PagerDuty/Opsgenie. If unresolved in 5m, engage senior engineering. If database-related, engage DBA.

## Related Dashboards

- Platform Overview (cybernova-overview)
- Service Health panel

## Related Documents

- Deployment Runbook (docs/DEPLOYMENT_RUNBOOK.md)
- Disaster Recovery (docs/runbooks/disaster-recovery.md)
