# Alert: PipelineStopped

**Severity:** critical  
**Category:** pipeline  

## Description

The unified pipeline orchestrator is not running.

## Threshold

```
cybernova_pipeline_running == 0 for 1m
```

## Impact

No events flow through the system. Ingestion, normalization, enrichment, detection, correlation, alerting, and SOAR all cease.

## Troubleshooting

1. Check pipeline status via API: `curl /api/v1/pipeline/status`
2. Inspect pipeline logs: `kubectl logs -l app=cybernova-backend | grep PIPELINE`
3. Check leader election status: `curl /api/v1/monitoring/ha/leader`
4. Verify event bus is healthy

## Mitigation

1. Restart the pipeline via API if leader: pipeline restart endpoint
2. If leader election issue, check HA configuration
3. If bus failure, restart the event bus service

## Escalation

P1 incident — page on-call immediately. Every minute of downtime causes data loss if ingestion sources are not buffering.

## Related Dashboards

- Pipeline Dashboard (cybernova-pipeline)
- Pipeline Running panel

## Related Documents

- Pipeline Architecture docs
