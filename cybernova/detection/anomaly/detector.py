from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.detection.anomaly.baseline import event_baseline

log = logging.getLogger("cybernova.detection.anomaly.detector")

ANOMALY_RULES = [
    {
        "name": "high_event_rate",
        "description": "Event rate significantly exceeds baseline",
        "severity": "medium",
        "z_score_threshold": 3.0,
    },
    {
        "name": "unusual_source_ip",
        "description": "Source IP has unusually high event count",
        "severity": "high",
        "z_score_threshold": 3.0,
    },
    {
        "name": "unusual_hour",
        "description": "Event volume at this hour is anomalous",
        "severity": "low",
        "z_score_threshold": 2.0,
    },
    {
        "name": "spike_in_event_type",
        "description": "Sudden spike in a specific event type",
        "severity": "high",
        "z_score_threshold": 4.0,
    },
]


class AnomalyDetector:
    def __init__(self):
        self._results: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

    async def score_event(self, tenant_id: str, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        await event_baseline.record_event(tenant_id, event_data)
        event_type = event_data.get("event_type", "unknown")
        anomalies = []

        rate = await event_baseline.get_event_rate(tenant_id, event_type)
        mean = await event_baseline.get_mean_rate(tenant_id, event_type)
        std = await event_baseline.get_rate_std(tenant_id, event_type)

        if mean > 0 and std > 0:
            z_score = (rate - mean) / std
            if z_score > 3.0:
                anomalies.append({
                    "rule": "high_event_rate",
                    "severity": "medium",
                    "score": round(z_score, 2),
                    "current_rate": round(rate, 2),
                    "mean_rate": round(mean, 2),
                    "description": f"Event rate {rate:.1f}/min exceeds baseline {mean:.1f}/min (z={z_score:.1f})",
                })

        unusual_ips = await event_baseline.get_unusual_source_ips(tenant_id, threshold=3.0)
        source_ip = event_data.get("source_ip", "")
        if source_ip and source_ip in unusual_ips:
            anomalies.append({
                "rule": "unusual_source_ip",
                "severity": "high",
                "score": 0.8,
                "source_ip": source_ip,
                "description": f"Source IP {source_ip} has unusually high event count",
            })

        hourly_anomaly = await event_baseline.get_hourly_anomaly(tenant_id)
        current_hour = datetime.now(timezone.utc).hour
        if hourly_anomaly and current_hour < len(hourly_anomaly) and hourly_anomaly[current_hour]:
            anomalies.append({
                "rule": "unusual_hour",
                "severity": "low",
                "score": 0.5,
                "hour": current_hour,
                "description": f"Event volume at hour {current_hour} is anomalous compared to baseline",
            })

        if anomalies:
            max_score = max(a.get("score", 0) if isinstance(a.get("score"), (int, float)) else 0.5 for a in anomalies)
            result = {
                "event_id": event_data.get("id", ""),
                "tenant_id": tenant_id,
                "event_type": event_type,
                "anomaly_score": min(1.0, max_score / 10),
                "anomalies": anomalies,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            async with self._lock:
                if tenant_id not in self._results:
                    self._results[tenant_id] = []
                self._results[tenant_id].append(result)
                if len(self._results[tenant_id]) > 1000:
                    self._results[tenant_id] = self._results[tenant_id][-1000:]
            return result

        return None

    async def get_recent_anomalies(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        async with self._lock:
            return (self._results.get(tenant_id, [])[-limit:])[::-1]

    async def get_anomaly_stats(self, tenant_id: str) -> Dict[str, Any]:
        async with self._lock:
            results = self._results.get(tenant_id, [])
            rule_counts: Dict[str, int] = {}
            for r in results:
                for a in r.get("anomalies", []):
                    rule = a.get("rule", "unknown")
                    rule_counts[rule] = rule_counts.get(rule, 0) + 1
            return {
                "total_anomalies": len(results),
                "avg_anomaly_score": round(sum(r.get("anomaly_score", 0) for r in results) / max(len(results), 1), 3),
                "rule_breakdown": rule_counts,
                "baseline": await event_baseline.get_stats(tenant_id),
            }


anomaly_detector = AnomalyDetector()
