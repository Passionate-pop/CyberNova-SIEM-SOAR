# Alert: HighAlertRate

**Severity:** warning  
**Category:** pipeline  

## Description

Alert generation rate exceeds 100 alerts per second.

## Threshold

```
rate(cybernova_alerts_generated_total[5m]) > 100
```

## Impact

Potential alert storm. SOC analysts may be overwhelmed and true positives could be lost in noise. Downstream systems may be overloaded.

## Troubleshooting

1. Check the Top Detection Rules table in the Security dashboard
2. Identify which rule(s) are firing most frequently
3. Check for misconfigured rules or overly broad detections
4. Verify if alert deduplication is working correctly
5. Check for ongoing attack or scanning activity

## Mitigation

1. Temporarily disable the most noisy rule via the detection rules API
2. Create suppression rules for known false positive patterns
3. Increase threshold or cooldown on the noisy rule
4. Enable more aggressive deduplication if warranted

## Escalation

P2 — email on-call. Escalate to P1 if sustained >500/s for 5m.

## Related Dashboards

- Security Dashboard
- Alerts by Severity panel
- Top Detection Rules

## Related Documents

- Detection rule tuning guide
- Suppression documentation
