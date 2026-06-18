# Alert: HighErrorRate

**Severity:** critical  
**Category:** resources  

## Description

Pipeline error rate exceeds 10 errors per second.

## Threshold

```
rate(cybernova_events_failed_total[5m]) > 10
```

## Impact

High failure rate means events are being lost. Data integrity at risk.

## Troubleshooting

1. Check error distribution across pipeline stages
2. Inspect recent logs for error patterns
3. Check if a downstream dependency (DB, Redis, API) is failing
4. Review recent code or configuration changes

## Mitigation

1. If dependency failure, address the dependent service first
2. If code bug, rollback the recent change
3. If data quality issue, add input validation
4. If transient, errors may self-resolve — monitor for 5m

## Escalation

P1 — page on-call. Event loss occurring.

## Related Dashboards

- Pipeline Dashboard
- Event Processing Error Rate panel

## Related Documents

- Error handling docs
- Debugging guide
