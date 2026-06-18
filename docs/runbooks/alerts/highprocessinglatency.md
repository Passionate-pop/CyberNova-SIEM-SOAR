# Alert: HighProcessingLatency

**Severity:** warning  
**Category:** pipeline  

## Description

P99 processing latency exceeds 2 seconds.

## Threshold

```
histogram_quantile(0.99, rate(cybernova_processing_latency_ms_bucket[5m])) > 2000
```

## Impact

Events take too long to process. Queue backlogs will grow and real-time alerting may be delayed.

## Troubleshooting

1. Check per-stage latency in the Pipeline dashboard
2. Identify the slowest pipeline stage
3. Check resource usage (CPU/memory) on the bottleneck stage
4. Inspect slow queries in Postgres if enrichment/ detection stage is slow
5. Check Redis response times

## Mitigation

1. Scale the bottleneck stage: increase worker count or resources
2. If specific rule causing slowdown, temporarily disable it
3. Reduce enrichment verbosity or detection rule complexity
4. Increase Redis maxmemory if cache thrashing

## Escalation

P2 — email on-call. Escalate to P1 if latency exceeds 10s.

## Related Dashboards

- Pipeline Dashboard
- Processing Latency panel

## Related Documents

- SLO configuration
- Pipeline tuning guide
