# Alert: StreamConsumerLag

**Severity:** warning  
**Category:** streams  

## Description

One or more stream consumer groups have lag > 1,000 messages.

## Threshold

```
cybernova_stream_lag > 1000
```

## Impact

Consumers are falling behind producers. Processing latency increases and the backlog of unprocessed events grows.

## Troubleshooting

1. Check per-stream lag in the Pipeline dashboard
2. Identify the consumer group with the highest lag
3. Check consumer health and processing rate
4. Verify there are no consumer restarts or rebalances

## Mitigation

1. Scale up consumers for the lagging stream
2. Increase consumer batch size and processing parallelism
3. If persistent, increase partition count and add more consumers

## Escalation

P2 — email on-call. Escalate to P1 if lag exceeds 100k.

## Related Dashboards

- Pipeline Dashboard
- Stream Consumer Lag panel

## Related Documents

- Stream architecture docs
