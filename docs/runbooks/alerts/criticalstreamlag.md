# Alert: CriticalStreamLag

**Severity:** critical  
**Category:** streams  

## Description

Stream consumer lag exceeds 10,000 messages.

## Threshold

```
cybernova_stream_lag > 10000 for 5m
```

## Impact

Severe backlog. Events may take hours to process. Real-time detection and alerting are significantly delayed.

## Troubleshooting

1. Check consumer pod CPU/memory — may be resource-starved
2. Check for consumer errors or crashes in logs
3. Check if the downstream stage (detection, SOAR) is a bottleneck
4. Verify Redis stream is not corrupted

## Mitigation

1. Restart the consumer group to trigger rebalance
2. Add more consumer instances immediately
3. If downstream bottleneck, scale that stage first
4. As last resort, consider skipping non-critical events to catch up

## Escalation

P1 — page on-call. Data processing delay exceeds acceptable SLA.

## Related Dashboards

- Pipeline Dashboard
- Stream Consumer Lag panel

## Related Documents

- Disaster Recovery
- Stream architecture docs
