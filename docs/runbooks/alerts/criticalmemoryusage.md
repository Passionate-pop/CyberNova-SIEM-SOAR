# Alert: CriticalMemoryUsage

**Severity:** critical  
**Category:** resources  

## Description

Backend process memory exceeds 2 GB — imminent OOM risk.

## Threshold

```
process_resident_memory_bytes{job='cybernova-backend'} > 2e9 for 1m
```

## Impact

Process is at high risk of being OOM-killed, which would cause a full service outage.

## Troubleshooting

1. Immediately check memory: `kubectl top pod -l app=cybernova-backend`
2. Trigger a heap dump for post-mortem analysis
3. Check for a memory leak in recent code changes

## Mitigation

1. Immediately increase memory limits before OOM occurs
2. Restart the pod to reclaim memory
3. If OOM loop, rollback to last-known-good version

## Escalation

P1 — page on-call immediately. Imminent service outage risk.

## Related Dashboards

- Platform Overview
- Memory Usage panel

## Related Documents

- Capacity planning docs
- Performance tuning guide
