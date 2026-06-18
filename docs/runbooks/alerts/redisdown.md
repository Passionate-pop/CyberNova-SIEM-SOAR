# Alert: RedisDown

**Severity:** critical  
**Category:** service_health  

## Description

Redis service is unreachable.

## Threshold

```
up{job='redis'} == 0 for 1m
```

## Impact

Event streaming, caching, queue management, and pub/sub all depend on Redis. System falls back to in-memory mode which has limited capacity.

## Troubleshooting

1. Check Redis pod: `kubectl get pods -l app=redis`
2. Inspect Redis logs: `kubectl logs -l app=redis --tail=50`
3. Check Redis metrics: `kubectl exec -it redis -- redis-cli INFO`
4. Verify persistent volume is available

## Mitigation

1. Restart Redis: `kubectl rollout restart statefulset/redis`
2. If OOM, increase `maxmemory` in Redis config
3. If disk-full, clear old RDB/AOF files or increase volume size
4. If persistent, fail over to Redis replica if available

## Escalation

P1 incident — page on-call. System will operate in degraded mode.

## Related Dashboards

- Platform Overview
- Service Health panels

## Related Documents

- Disaster Recovery (docs/runbooks/disaster-recovery.md)
