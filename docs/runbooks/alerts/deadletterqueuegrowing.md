# Alert: DeadLetterQueueGrowing

**Severity:** warning  
**Category:** streams  

## Description

Dead letter queue depth exceeds 10 messages.

## Threshold

```
cybernova_dlq_depth > 10
```

## Impact

Events are failing processing and being sent to DLQ. These events need review — they may indicate data quality issues or bugs.

## Troubleshooting

1. Inspect DLQ entries via the DLQ management API
2. Identify common failure patterns (parse errors, missing fields)
3. Check if a recent pipeline change caused the failures
4. Review the original events for malformed data

## Mitigation

1. Reprocess DLQ events via the DLQ replay API
2. Fix the underlying issue (data validation, parser bug)
3. Add monitoring on DLQ to catch recurring issues

## Escalation

P2 — email on-call. Escalate if DLQ grows >1k in 1h.

## Related Dashboards

- Pipeline Dashboard
- Dead Letter Queue Depth panel

## Related Documents

- DLQ management guide
