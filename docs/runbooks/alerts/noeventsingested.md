# Alert: NoEventsIngested

**Severity:** warning  
**Category:** pipeline  

## Description

No events have been ingested in the last 15 minutes.

## Threshold

```
rate(cybernova_events_ingested_total[10m]) == 0 for 15m
```

## Impact

Ingestion sources may be down or disconnected. If the pipeline is running but receiving no data, upstream sources need investigation.

## Troubleshooting

1. Verify ingestion sources are sending data
2. Check source connectors (syslog, file watcher, agent, API)
3. Check network connectivity between sources and backend
4. Inspect source-specific logs for errors
5. Check if sources are backed up or rate-limited

## Mitigation

1. Restart ingestion source connectors if down
2. Check firewall rules and network ACLs
3. Verify agent heartbeat: check agent_status table
4. If syslog, check syslog receiver status

## Escalation

P2 — email on-call. Escalate to P1 if no events for >1 hour.

## Related Dashboards

- Platform Overview
- Events Ingested panel

## Related Documents

- Deployment Runbook
- Ingestion configuration docs
