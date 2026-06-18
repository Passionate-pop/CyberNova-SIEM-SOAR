# Alert: NoActiveAgents

**Severity:** warning  
**Category:** security  

## Description

No endpoint agents have reported in the last hour.

## Threshold

```
count(cybernova_agent_heartbeat) == 0 for 1h
```

## Impact

No endpoint visibility. Host-level detection, file monitoring, and agent-based response capabilities are unavailable.

## Troubleshooting

1. Check agent deployment status in the Agents dashboard
2. Verify agent communication endpoint is reachable
3. Check if agents were bulk-disconnected or uninstalled
4. Check TLS certificate expiry on agents

## Mitigation

1. If agent update broke connectivity, rollback agent version
2. If certificate issue, re-deploy agents with updated certs
3. If server endpoint changed, update agent configuration

## Escalation

P2 — email on-call. Escalate to P1 if no agents for >4 hours.

## Related Dashboards

- Security Dashboard
- Agent Status panel

## Related Documents

- Agent deployment guide
- Agent troubleshooting docs
