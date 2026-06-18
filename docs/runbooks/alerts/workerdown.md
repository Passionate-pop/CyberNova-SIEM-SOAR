# Alert: WorkerDown

**Severity:** critical  
**Category:** service_health  

## Description

Pipeline worker process is unreachable.

## Threshold

```
up{job='cybernova-worker'} == 0 for 2m
```

## Impact

Pipeline stage processing stops. Enrichment, detection, and SOAR actions will not execute. Events accumulate in queues.

## Troubleshooting

1. Check worker pod: `kubectl get pods -l app=cybernova-worker`
2. Inspect worker logs: `kubectl logs -l app=cybernova-worker --tail=100`
3. Check worker readiness: `kubectl describe pod -l app=cybernova-worker`
4. Verify Redis connectivity from worker pod

## Mitigation

1. Restart worker: `kubectl rollout restart deployment/cybernova-worker`
2. Check queue depth to estimate backlog recovery time
3. If Redis connection issue, restart Redis first

## Escalation

P1 incident — page on-call. Backlog will grow until worker recovers.

## Related Dashboards

- Pipeline Dashboard (cybernova-pipeline)
- Worker Status panels

## Related Documents

- Deployment Runbook
- Pipeline Architecture docs
