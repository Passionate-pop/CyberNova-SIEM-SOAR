# Alert: SOARDisabled

**Severity:** warning  
**Category:** security  

## Description

Built-in SOAR (automated response) is disabled.

## Threshold

```
cybernova_soar_enabled == 0
```

## Impact

Automated incident response actions (block IP, isolate host, disable user) will not execute. Response relies entirely on manual SOC actions.

## Troubleshooting

1. Check SOAR configuration: `GET /api/v1/admin/soar/config`
2. Verify SOAR enabled flag in settings
3. Check if SOAR was intentionally disabled for maintenance

## Mitigation

1. Re-enable SOAR: set `soar_enabled=true` in config and restart
2. If disabled for maintenance, schedule re-enable after maintenance window

## Escalation

P2 — email on-call. Escalate to P1 if disabled >1 hour during active threat.

## Related Dashboards

- Security Dashboard

## Related Documents

- SOAR configuration guide
- Playbook documentation
