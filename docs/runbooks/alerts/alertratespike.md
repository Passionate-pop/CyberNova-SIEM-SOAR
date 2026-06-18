# Alert: AlertRateSpike

**Severity:** critical  
**Category:** pipeline  

## Description

Alert rate spike detected: 5m rate is 5x the 1h average.

## Threshold

```
rate(cybernova_alerts_generated_total[5m]) / rate(cybernova_alerts_generated_total[1h]) > 5
```

## Impact

Sudden surge in alerts indicates either an active attack or a bad rule change. SOC needs immediate attention.

## Troubleshooting

1. Check the Alert Rate Spike panel in the Security dashboard
2. Identify the triggering rule(s) from the Top Detection Rules table
3. Cross-reference with recent deployment or rule changes
4. Check for active CVE exploitation or scanning campaigns

## Mitigation

1. If attack: activate incident response playbook
2. If false positive: disable the triggering rule and file a bug
3. If scanning: consider rate-limiting or blocking at the perimeter

## Escalation

P1 — page on-call immediately. Possible active security incident.

## Related Dashboards

- Security Dashboard
- Alert Rate Spike panel

## Related Documents

- Incident Response Playbook
- Detection rule change log
