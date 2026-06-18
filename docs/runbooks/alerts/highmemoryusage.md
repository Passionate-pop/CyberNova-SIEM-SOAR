# Alert: HighMemoryUsage

**Severity:** warning  
**Category:** resources  

## Description

Backend process memory exceeds 1 GB.

## Threshold

```
process_resident_memory_bytes{job='cybernova-backend'} > 1e9
```

## Impact

Memory pressure may lead to degraded performance and potential OOM kills.

## Troubleshooting

1. Check memory breakdown: `kubectl top pod -l app=cybernova-backend`
2. Check for memory leak patterns in logs (GC logs, heap dumps)
3. Verify event queue depths — large backlogs increase memory usage
4. Check if a recent deployment changed memory configuration

## Mitigation

1. Increase memory limits in the deployment manifest
2. If leak suspected, collect heap dump and restart pod
3. Reduce in-memory cache sizes if configured
4. Scale horizontally to distribute load

## Escalation

P2 — email on-call. Escalate to P1 if memory reaches 2 GB.

## Related Dashboards

- Platform Overview
- Memory Usage panel

## Related Documents

- Capacity planning docs
