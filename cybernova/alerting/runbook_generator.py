"""
Runbook generator. Creates per-alert markdown files and indexes into RAG for SOC lookup.
"""
from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.alerting.runbook")

_default_runbook_dir = tempfile.mkdtemp(prefix="cybernova_runbooks_")
RUNBOOKS_DIR = Path(os.environ.get("RUNBOOKS_DIR", _default_runbook_dir))


@dataclass
class AlertRunbook:
    """Structured runbook for a single alert rule."""

    name: str
    severity: str
    category: str
    description: str
    threshold: str
    impact: str
    troubleshooting: List[str] = field(default_factory=list)
    mitigation: List[str] = field(default_factory=list)
    escalation: str = ""
    related_dashboards: List[str] = field(default_factory=list)
    related_docs: List[str] = field(default_factory=list)


# alert runbook definitions (one per prometheus rule)

ALERT_RUNBOOKS: List[AlertRunbook] = [
    # service health
    AlertRunbook(
        name="BackendDown",
        severity="critical",
        category="service_health",
        description="Backend API service is unreachable.",
        threshold="up{job='cybernova-backend'} == 0 for 2m",
        impact="All API endpoints are unavailable. Event ingestion, alert queries, "
               "and dashboard access are blocked. No new data enters the system.",
        troubleshooting=[
            "Check pod status: `kubectl get pods -l app=cybernova-backend`",
            "Inspect logs: `kubectl logs -l app=cybernova-backend --tail=100`",
            "Check resource usage: `kubectl top pod -l app=cybernova-backend`",
            "Verify liveness probe: `kubectl describe pod -l app=cybernova-backend | grep Liveness`",
            "Check for recent config changes in the last deployed version",
        ],
        mitigation=[
            "Restart the deployment: `kubectl rollout restart deployment/cybernova-backend`",
            "If OOM-killed, increase memory limits in deployment manifest",
            "If crash-looping, rollback to the last known-good version",
            "Check database connectivity from the backend pod",
        ],
        escalation="P1 incident — page on-call via PagerDuty/Opsgenie. "
                   "If unresolved in 5m, engage senior engineering. "
                   "If database-related, engage DBA.",
        related_dashboards=["Platform Overview (cybernova-overview)", "Service Health panel"],
        related_docs=["Deployment Runbook (docs/DEPLOYMENT_RUNBOOK.md)",
                       "Disaster Recovery (docs/runbooks/disaster-recovery.md)"],
    ),
    AlertRunbook(
        name="WorkerDown",
        severity="critical",
        category="service_health",
        description="Pipeline worker process is unreachable.",
        threshold="up{job='cybernova-worker'} == 0 for 2m",
        impact="Pipeline stage processing stops. Enrichment, detection, and SOAR actions "
               "will not execute. Events accumulate in queues.",
        troubleshooting=[
            "Check worker pod: `kubectl get pods -l app=cybernova-worker`",
            "Inspect worker logs: `kubectl logs -l app=cybernova-worker --tail=100`",
            "Check worker readiness: `kubectl describe pod -l app=cybernova-worker`",
            "Verify Redis connectivity from worker pod",
        ],
        mitigation=[
            "Restart worker: `kubectl rollout restart deployment/cybernova-worker`",
            "Check queue depth to estimate backlog recovery time",
            "If Redis connection issue, restart Redis first",
        ],
        escalation="P1 incident — page on-call. Backlog will grow until worker recovers.",
        related_dashboards=["Pipeline Dashboard (cybernova-pipeline)", "Worker Status panels"],
        related_docs=["Deployment Runbook", "Pipeline Architecture docs"],
    ),
    AlertRunbook(
        name="RedisDown",
        severity="critical",
        category="service_health",
        description="Redis service is unreachable.",
        threshold="up{job='redis'} == 0 for 1m",
        impact="Event streaming, caching, queue management, and pub/sub all depend on Redis. "
               "System falls back to in-memory mode which has limited capacity.",
        troubleshooting=[
            "Check Redis pod: `kubectl get pods -l app=redis`",
            "Inspect Redis logs: `kubectl logs -l app=redis --tail=50`",
            "Check Redis metrics: `kubectl exec -it redis -- redis-cli INFO`",
            "Verify persistent volume is available",
        ],
        mitigation=[
            "Restart Redis: `kubectl rollout restart statefulset/redis`",
            "If OOM, increase `maxmemory` in Redis config",
            "If disk-full, clear old RDB/AOF files or increase volume size",
            "If persistent, fail over to Redis replica if available",
        ],
        escalation="P1 incident — page on-call. System will operate in degraded mode.",
        related_dashboards=["Platform Overview", "Service Health panels"],
        related_docs=["Disaster Recovery (docs/runbooks/disaster-recovery.md)"],
    ),
    AlertRunbook(
        name="PostgresDown",
        severity="critical",
        category="service_health",
        description="PostgreSQL database is unreachable.",
        threshold="up{job='postgres'} == 0 for 1m",
        impact="Alert persistence, user authentication, audit logging, and all database-backed "
               "operations are unavailable. Detection rules cannot be loaded from DB.",
        troubleshooting=[
            "Check Postgres pod: `kubectl get pods -l app=postgres`",
            "Inspect Postgres logs: `kubectl logs -l app=postgres --tail=50`",
            "Check disk space: `kubectl exec -it postgres -- df -h`",
            "Check connection count: `kubectl exec -it postgres -- psql -c 'SELECT count(*) FROM pg_stat_activity;'`",
            "Verify persistent volume claim is bound",
        ],
        mitigation=[
            "Restart Postgres: `kubectl rollout restart statefulset/postgres`",
            "If disk-full, extend PVC or clean old WAL files",
            "If connection storm, increase `max_connections` then investigate source",
            "If corrupt, restore from latest pg_dump backup",
        ],
        escalation="P1 incident — page on-call and DBA. Data loss risk.",
        related_dashboards=["Platform Overview", "Service Health panels"],
        related_docs=["Disaster Recovery (docs/runbooks/disaster-recovery.md)"],
    ),

    # pipeline
    AlertRunbook(
        name="PipelineStopped",
        severity="critical",
        category="pipeline",
        description="The unified pipeline orchestrator is not running.",
        threshold="cybernova_pipeline_running == 0 for 1m",
        impact="No events flow through the system. Ingestion, normalization, enrichment, "
               "detection, correlation, alerting, and SOAR all cease.",
        troubleshooting=[
            "Check pipeline status via API: `curl /api/v1/pipeline/status`",
            "Inspect pipeline logs: `kubectl logs -l app=cybernova-backend | grep PIPELINE`",
            "Check leader election status: `curl /api/v1/monitoring/ha/leader`",
            "Verify event bus is healthy",
        ],
        mitigation=[
            "Restart the pipeline via API if leader: pipeline restart endpoint",
            "If leader election issue, check HA configuration",
            "If bus failure, restart the event bus service",
        ],
        escalation="P1 incident — page on-call immediately. Every minute of downtime "
                   "causes data loss if ingestion sources are not buffering.",
        related_dashboards=["Pipeline Dashboard (cybernova-pipeline)", "Pipeline Running panel"],
        related_docs=["Pipeline Architecture docs"],
    ),
    AlertRunbook(
        name="NoEventsIngested",
        severity="warning",
        category="pipeline",
        description="No events have been ingested in the last 15 minutes.",
        threshold="rate(cybernova_events_ingested_total[10m]) == 0 for 15m",
        impact="Ingestion sources may be down or disconnected. If the pipeline is running "
               "but receiving no data, upstream sources need investigation.",
        troubleshooting=[
            "Verify ingestion sources are sending data",
            "Check source connectors (syslog, file watcher, agent, API)",
            "Check network connectivity between sources and backend",
            "Inspect source-specific logs for errors",
            "Check if sources are backed up or rate-limited",
        ],
        mitigation=[
            "Restart ingestion source connectors if down",
            "Check firewall rules and network ACLs",
            "Verify agent heartbeat: check agent_status table",
            "If syslog, check syslog receiver status",
        ],
        escalation="P2 — email on-call. Escalate to P1 if no events for >1 hour.",
        related_dashboards=["Platform Overview", "Events Ingested panel"],
        related_docs=["Deployment Runbook", "Ingestion configuration docs"],
    ),
    AlertRunbook(
        name="HighProcessingLatency",
        severity="warning",
        category="pipeline",
        description="P99 processing latency exceeds 2 seconds.",
        threshold="histogram_quantile(0.99, rate(cybernova_processing_latency_ms_bucket[5m])) > 2000",
        impact="Events take too long to process. Queue backlogs will grow and "
               "real-time alerting may be delayed.",
        troubleshooting=[
            "Check per-stage latency in the Pipeline dashboard",
            "Identify the slowest pipeline stage",
            "Check resource usage (CPU/memory) on the bottleneck stage",
            "Inspect slow queries in Postgres if enrichment/ detection stage is slow",
            "Check Redis response times",
        ],
        mitigation=[
            "Scale the bottleneck stage: increase worker count or resources",
            "If specific rule causing slowdown, temporarily disable it",
            "Reduce enrichment verbosity or detection rule complexity",
            "Increase Redis maxmemory if cache thrashing",
        ],
        escalation="P2 — email on-call. Escalate to P1 if latency exceeds 10s.",
        related_dashboards=["Pipeline Dashboard", "Processing Latency panel"],
        related_docs=["SLO configuration", "Pipeline tuning guide"],
    ),
    AlertRunbook(
        name="CriticalProcessingLatency",
        severity="critical",
        category="pipeline",
        description="P99 processing latency exceeds 10 seconds.",
        threshold="histogram_quantile(0.99, rate(cybernova_processing_latency_ms_bucket[5m])) > 10000",
        impact="Severe processing delays. Events are backing up and near-real-time "
               "detection is effectively broken. Alert SLAs being breached.",
        troubleshooting=[
            "Immediately identify the bottleneck stage from the Pipeline dashboard",
            "Check for resource exhaustion (CPU, memory, disk I/O)",
            "Check for deadlocks or stuck workers",
            "Inspect recent deployment changes that may have introduced latency",
        ],
        mitigation=[
            "Restart the pipeline to clear stuck state",
            "Temporarily disable non-critical stages (enrichment, anomaly)",
            "Scale up workers and resources immediately",
            "If caused by a detection rule hotfix, rollback rule changes",
        ],
        escalation="P1 — page on-call immediately. Engage engineering team.",
        related_dashboards=["Pipeline Dashboard", "Processing Latency panel", "Stage SLO panels"],
        related_docs=["SLO configuration", "Disaster Recovery"],
    ),
    AlertRunbook(
        name="HighAlertRate",
        severity="warning",
        category="pipeline",
        description="Alert generation rate exceeds 100 alerts per second.",
        threshold="rate(cybernova_alerts_generated_total[5m]) > 100",
        impact="Potential alert storm. SOC analysts may be overwhelmed and "
               "true positives could be lost in noise. Downstream systems may be overloaded.",
        troubleshooting=[
            "Check the Top Detection Rules table in the Security dashboard",
            "Identify which rule(s) are firing most frequently",
            "Check for misconfigured rules or overly broad detections",
            "Verify if alert deduplication is working correctly",
            "Check for ongoing attack or scanning activity",
        ],
        mitigation=[
            "Temporarily disable the most noisy rule via the detection rules API",
            "Create suppression rules for known false positive patterns",
            "Increase threshold or cooldown on the noisy rule",
            "Enable more aggressive deduplication if warranted",
        ],
        escalation="P2 — email on-call. Escalate to P1 if sustained >500/s for 5m.",
        related_dashboards=["Security Dashboard", "Alerts by Severity panel", "Top Detection Rules"],
        related_docs=["Detection rule tuning guide", "Suppression documentation"],
    ),
    AlertRunbook(
        name="AlertRateSpike",
        severity="critical",
        category="pipeline",
        description="Alert rate spike detected: 5m rate is 5x the 1h average.",
        threshold="rate(cybernova_alerts_generated_total[5m]) / rate(cybernova_alerts_generated_total[1h]) > 5",
        impact="Sudden surge in alerts indicates either an active attack or a "
               "bad rule change. SOC needs immediate attention.",
        troubleshooting=[
            "Check the Alert Rate Spike panel in the Security dashboard",
            "Identify the triggering rule(s) from the Top Detection Rules table",
            "Cross-reference with recent deployment or rule changes",
            "Check for active CVE exploitation or scanning campaigns",
        ],
        mitigation=[
            "If attack: activate incident response playbook",
            "If false positive: disable the triggering rule and file a bug",
            "If scanning: consider rate-limiting or blocking at the perimeter",
        ],
        escalation="P1 — page on-call immediately. Possible active security incident.",
        related_dashboards=["Security Dashboard", "Alert Rate Spike panel"],
        related_docs=["Incident Response Playbook", "Detection rule change log"],
    ),

    # streams
    AlertRunbook(
        name="StreamConsumerLag",
        severity="warning",
        category="streams",
        description="One or more stream consumer groups have lag > 1,000 messages.",
        threshold="cybernova_stream_lag > 1000",
        impact="Consumers are falling behind producers. Processing latency increases "
               "and the backlog of unprocessed events grows.",
        troubleshooting=[
            "Check per-stream lag in the Pipeline dashboard",
            "Identify the consumer group with the highest lag",
            "Check consumer health and processing rate",
            "Verify there are no consumer restarts or rebalances",
        ],
        mitigation=[
            "Scale up consumers for the lagging stream",
            "Increase consumer batch size and processing parallelism",
            "If persistent, increase partition count and add more consumers",
        ],
        escalation="P2 — email on-call. Escalate to P1 if lag exceeds 100k.",
        related_dashboards=["Pipeline Dashboard", "Stream Consumer Lag panel"],
        related_docs=["Stream architecture docs"],
    ),
    AlertRunbook(
        name="CriticalStreamLag",
        severity="critical",
        category="streams",
        description="Stream consumer lag exceeds 10,000 messages.",
        threshold="cybernova_stream_lag > 10000 for 5m",
        impact="Severe backlog. Events may take hours to process. Real-time detection "
               "and alerting are significantly delayed.",
        troubleshooting=[
            "Check consumer pod CPU/memory — may be resource-starved",
            "Check for consumer errors or crashes in logs",
            "Check if the downstream stage (detection, SOAR) is a bottleneck",
            "Verify Redis stream is not corrupted",
        ],
        mitigation=[
            "Restart the consumer group to trigger rebalance",
            "Add more consumer instances immediately",
            "If downstream bottleneck, scale that stage first",
            "As last resort, consider skipping non-critical events to catch up",
        ],
        escalation="P1 — page on-call. Data processing delay exceeds acceptable SLA.",
        related_dashboards=["Pipeline Dashboard", "Stream Consumer Lag panel"],
        related_docs=["Disaster Recovery", "Stream architecture docs"],
    ),
    AlertRunbook(
        name="DeadLetterQueueGrowing",
        severity="warning",
        category="streams",
        description="Dead letter queue depth exceeds 10 messages.",
        threshold="cybernova_dlq_depth > 10",
        impact="Events are failing processing and being sent to DLQ. These events "
               "need review — they may indicate data quality issues or bugs.",
        troubleshooting=[
            "Inspect DLQ entries via the DLQ management API",
            "Identify common failure patterns (parse errors, missing fields)",
            "Check if a recent pipeline change caused the failures",
            "Review the original events for malformed data",
        ],
        mitigation=[
            "Reprocess DLQ events via the DLQ replay API",
            "Fix the underlying issue (data validation, parser bug)",
            "Add monitoring on DLQ to catch recurring issues",
        ],
        escalation="P2 — email on-call. Escalate if DLQ grows >1k in 1h.",
        related_dashboards=["Pipeline Dashboard", "Dead Letter Queue Depth panel"],
        related_docs=["DLQ management guide"],
    ),

    # resources
    AlertRunbook(
        name="HighMemoryUsage",
        severity="warning",
        category="resources",
        description="Backend process memory exceeds 1 GB.",
        threshold="process_resident_memory_bytes{job='cybernova-backend'} > 1e9",
        impact="Memory pressure may lead to degraded performance and potential OOM kills.",
        troubleshooting=[
            "Check memory breakdown: `kubectl top pod -l app=cybernova-backend`",
            "Check for memory leak patterns in logs (GC logs, heap dumps)",
            "Verify event queue depths — large backlogs increase memory usage",
            "Check if a recent deployment changed memory configuration",
        ],
        mitigation=[
            "Increase memory limits in the deployment manifest",
            "If leak suspected, collect heap dump and restart pod",
            "Reduce in-memory cache sizes if configured",
            "Scale horizontally to distribute load",
        ],
        escalation="P2 — email on-call. Escalate to P1 if memory reaches 2 GB.",
        related_dashboards=["Platform Overview", "Memory Usage panel"],
        related_docs=["Capacity planning docs"],
    ),
    AlertRunbook(
        name="CriticalMemoryUsage",
        severity="critical",
        category="resources",
        description="Backend process memory exceeds 2 GB — imminent OOM risk.",
        threshold="process_resident_memory_bytes{job='cybernova-backend'} > 2e9 for 1m",
        impact="Process is at high risk of being OOM-killed, which would cause "
               "a full service outage.",
        troubleshooting=[
            "Immediately check memory: `kubectl top pod -l app=cybernova-backend`",
            "Trigger a heap dump for post-mortem analysis",
            "Check for a memory leak in recent code changes",
        ],
        mitigation=[
            "Immediately increase memory limits before OOM occurs",
            "Restart the pod to reclaim memory",
            "If OOM loop, rollback to last-known-good version",
        ],
        escalation="P1 — page on-call immediately. Imminent service outage risk.",
        related_dashboards=["Platform Overview", "Memory Usage panel"],
        related_docs=["Capacity planning docs", "Performance tuning guide"],
    ),
    AlertRunbook(
        name="HighErrorRate",
        severity="critical",
        category="resources",
        description="Pipeline error rate exceeds 10 errors per second.",
        threshold="rate(cybernova_events_failed_total[5m]) > 10",
        impact="High failure rate means events are being lost. Data integrity at risk.",
        troubleshooting=[
            "Check error distribution across pipeline stages",
            "Inspect recent logs for error patterns",
            "Check if a downstream dependency (DB, Redis, API) is failing",
            "Review recent code or configuration changes",
        ],
        mitigation=[
            "If dependency failure, address the dependent service first",
            "If code bug, rollback the recent change",
            "If data quality issue, add input validation",
            "If transient, errors may self-resolve — monitor for 5m",
        ],
        escalation="P1 — page on-call. Event loss occurring.",
        related_dashboards=["Pipeline Dashboard", "Event Processing Error Rate panel"],
        related_docs=["Error handling docs", "Debugging guide"],
    ),

    # security
    AlertRunbook(
        name="SOARDisabled",
        severity="warning",
        category="security",
        description="Built-in SOAR (automated response) is disabled.",
        threshold="cybernova_soar_enabled == 0",
        impact="Automated incident response actions (block IP, isolate host, disable user) "
               "will not execute. Response relies entirely on manual SOC actions.",
        troubleshooting=[
            "Check SOAR configuration: `GET /api/v1/admin/soar/config`",
            "Verify SOAR enabled flag in settings",
            "Check if SOAR was intentionally disabled for maintenance",
        ],
        mitigation=[
            "Re-enable SOAR: set `soar_enabled=true` in config and restart",
            "If disabled for maintenance, schedule re-enable after maintenance window",
        ],
        escalation="P2 — email on-call. Escalate to P1 if disabled >1 hour during active threat.",
        related_dashboards=["Security Dashboard"],
        related_docs=["SOAR configuration guide", "Playbook documentation"],
    ),
    AlertRunbook(
        name="NoActiveAgents",
        severity="warning",
        category="security",
        description="No endpoint agents have reported in the last hour.",
        threshold="count(cybernova_agent_heartbeat) == 0 for 1h",
        impact="No endpoint visibility. Host-level detection, file monitoring, and "
               "agent-based response capabilities are unavailable.",
        troubleshooting=[
            "Check agent deployment status in the Agents dashboard",
            "Verify agent communication endpoint is reachable",
            "Check if agents were bulk-disconnected or uninstalled",
            "Check TLS certificate expiry on agents",
        ],
        mitigation=[
            "If agent update broke connectivity, rollback agent version",
            "If certificate issue, re-deploy agents with updated certs",
            "If server endpoint changed, update agent configuration",
        ],
        escalation="P2 — email on-call. Escalate to P1 if no agents for >4 hours.",
        related_dashboards=["Security Dashboard", "Agent Status panel"],
        related_docs=["Agent deployment guide", "Agent troubleshooting docs"],
    ),
]


def generate_runbook_md(runbook: AlertRunbook) -> str:
    """Render an AlertRunbook as a markdown document."""
    lines = [
        f"# Alert: {runbook.name}",
        "",
        f"**Severity:** {runbook.severity}  ",
        f"**Category:** {runbook.category}  ",
        "",
        "## Description",
        "",
        runbook.description,
        "",
        "## Threshold",
        "",
        f"```\n{runbook.threshold}\n```",
        "",
        "## Impact",
        "",
        runbook.impact,
        "",
        "## Troubleshooting",
        "",
    ]
    for i, step in enumerate(runbook.troubleshooting, 1):
        lines.append(f"{i}. {step}")
    lines.extend([
        "",
        "## Mitigation",
        "",
    ])
    for i, step in enumerate(runbook.mitigation, 1):
        lines.append(f"{i}. {step}")
    lines.extend([
        "",
        "## Escalation",
        "",
        runbook.escalation,
        "",
    ])
    if runbook.related_dashboards:
        lines.extend([
            "## Related Dashboards",
            "",
        ])
        for d in runbook.related_dashboards:
            lines.append(f"- {d}")
        lines.append("")
    if runbook.related_docs:
        lines.extend([
            "## Related Documents",
            "",
        ])
        for d in runbook.related_docs:
            lines.append(f"- {d}")
        lines.append("")
    return "\n".join(lines)


def write_runbook(runbook: AlertRunbook, output_dir: Path) -> Path:
    """Write a single runbook markdown file to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / f"{runbook.name.lower()}.md"
    content = generate_runbook_md(runbook)
    filepath.write_text(content, encoding="utf-8")
    log.info("Wrote runbook: %s", filepath)
    return filepath


def generate_all(output_dir: Optional[Path] = None) -> List[Path]:
    """Generate runbook files for all alert rules."""
    out = output_dir or RUNBOOKS_DIR
    paths: List[Path] = []
    for runbook in ALERT_RUNBOOKS:
        path = write_runbook(runbook, out)
        paths.append(path)
    log.info("Generated %d runbook files in %s", len(paths), out)
    return paths


async def ingest_all(rag, output_dir: Optional[Path] = None) -> int:
    """Index all generated runbooks into the AI RAG knowledge base."""
    out = output_dir or RUNBOOKS_DIR
    if not out.exists():
        log.warning("Runbook directory %s does not exist — skipping ingest", out)
        return 0

    total = 0
    for md_file in sorted(out.glob("*.md")):
        content = md_file.read_text(encoding="utf-8")
        doc_id = f"runbook:{md_file.stem}"
        metadata = {
            "type": "runbook",
            "alert": md_file.stem,
            "source": "runbook_generator",
        }
        try:
            count = await rag.index_document(doc_id, content, metadata)
            total += count
            log.info("Ingested %s (%d chunks)", doc_id, count)
        except Exception as exc:
            log.error("Failed to ingest runbook %s: %s", md_file.name, exc)
    log.info("RAG ingest complete: %d total chunks across %d runbooks", total, len(list(out.glob("*.md"))))
    return total


async def generate_and_ingest(rag=None, output_dir: Optional[Path] = None) -> None:
    """Convenience: generate all runbooks then ingest into RAG."""
    generate_all(output_dir)
    if rag is not None:
        await ingest_all(rag, output_dir)
    log.info("Runbook generation and ingest complete")


class RunbookGenerator:
    """Runbook generator singleton wrapping generation and ingest."""

    @property
    def runbooks(self) -> List[AlertRunbook]:
        return list(ALERT_RUNBOOKS)

    @property
    def definitions(self) -> List[Dict[str, Any]]:
        return [{"name": r.name, "severity": r.severity, "category": r.category} for r in ALERT_RUNBOOKS]

    def generate(self, runbook: AlertRunbook) -> str:
        return generate_runbook_md(runbook)

    def write(self, runbook: AlertRunbook, output_dir: Optional[Path] = None) -> Path:
        return write_runbook(runbook, output_dir or RUNBOOKS_DIR)

    def generate_all(self, output_dir: Optional[Path] = None) -> List[Path]:
        return generate_all(output_dir)

    async def ingest_all(self, rag, output_dir: Optional[Path] = None) -> int:
        return await ingest_all(rag, output_dir)

    async def generate_and_ingest(self, rag=None, output_dir: Optional[Path] = None) -> None:
        await generate_and_ingest(rag, output_dir)


# Module-level singleton for clean API access
runbook_generator = RunbookGenerator()


if __name__ == "__main__":
    import sys
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else RUNBOOKS_DIR
    generated = generate_all(out)
    for p in generated:
        log.info("  %s", p)
    log.info("Generated %d runbooks in %s", len(generated), out)
