# Alert: CriticalProcessingLatency

**Severity:** critical  
**Category:** pipeline  

## Description

P99 processing latency exceeds 10 seconds.

## Threshold

```
histogram_quantile(0.99, rate(cybernova_processing_latency_ms_bucket[5m])) > 10000
```

## Impact

Severe processing delays. Events are backing up and near-real-time detection is effectively broken. Alert SLAs being breached.

## Troubleshooting

1. Immediately identify the bottleneck stage from the Pipeline dashboard
2. Check for resource exhaustion (CPU, memory, disk I/O)
3. Check for deadlocks or stuck workers
4. Inspect recent deployment changes that may have introduced latency

## Mitigation

1. Restart the pipeline to clear stuck state
2. Temporarily disable non-critical stages (enrichment, anomaly)
3. Scale up workers and resources immediately
4. If caused by a detection rule hotfix, rollback rule changes

## Escalation

P1 — page on-call immediately. Engage engineering team.

## Related Dashboards

- Pipeline Dashboard
- Processing Latency panel
- Stage SLO panels

## Related Documents

- SLO configuration
- Disaster Recovery
