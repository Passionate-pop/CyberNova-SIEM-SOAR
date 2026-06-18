from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybernova.ueba.features import (
    extract_authentication_features, extract_login_features,
    extract_network_features, extract_resource_features,
)
from cybernova.ueba.models import (
    BehavioralEvent, EntityType,
)
from cybernova.ueba.profiler import ueba_profiler
from cybernova.ueba.risk_scorer import compute_weighted_risk

log = logging.getLogger("cybernova.ueba.detector")


class UEBADetector:
    def analyze_login(self, entity_id: str, entity_type: EntityType, tenant_id: str,
                      login_events: List[Dict[str, Any]], source_ip: str = "") -> Optional[Dict[str, Any]]:
        features = extract_login_features(login_events)
        event = BehavioralEvent(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            event_type="login_behavior",
            features=features,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            risk_score=compute_weighted_risk(features),
        )
        alert = ueba_profiler.process_event(event)
        return self._format_result(event, alert)

    def analyze_network(self, entity_id: str, entity_type: EntityType, tenant_id: str,
                        network_events: List[Dict[str, Any]], source_ip: str = "") -> Optional[Dict[str, Any]]:
        features = extract_network_features(network_events)
        event = BehavioralEvent(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            event_type="network_behavior",
            features=features,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            risk_score=compute_weighted_risk(features),
        )
        alert = ueba_profiler.process_event(event)
        return self._format_result(event, alert)

    def analyze_resource(self, entity_id: str, entity_type: EntityType, tenant_id: str,
                         resource_events: List[Dict[str, Any]], source_ip: str = "") -> Optional[Dict[str, Any]]:
        features = extract_resource_features(resource_events)
        event = BehavioralEvent(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            event_type="resource_behavior",
            features=features,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            risk_score=compute_weighted_risk(features),
        )
        alert = ueba_profiler.process_event(event)
        return self._format_result(event, alert)

    def analyze_auth(self, entity_id: str, entity_type: EntityType, tenant_id: str,
                     auth_events: List[Dict[str, Any]], source_ip: str = "") -> Optional[Dict[str, Any]]:
        features = extract_authentication_features(auth_events)
        event = BehavioralEvent(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            event_type="auth_behavior",
            features=features,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source_ip=source_ip,
            risk_score=compute_weighted_risk(features),
        )
        alert = ueba_profiler.process_event(event)
        return self._format_result(event, alert)

    def analyze_from_telemetry(self, entity_id: str, entity_type: EntityType, tenant_id: str,
                               telemetry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        features = {}
        if "events" in telemetry:
            features.update(extract_login_features(telemetry["events"]))
        if "network" in telemetry:
            features.update(extract_network_features(telemetry["network"]))
        if "resources" in telemetry:
            features.update(extract_resource_features(telemetry["resources"]))
        if "auth" in telemetry:
            features.update(extract_authentication_features(telemetry["auth"]))

        if not features:
            return None

        event = BehavioralEvent(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=tenant_id,
            event_type="composite_behavior",
            features=features,
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_score=compute_weighted_risk(features),
        )
        alert = ueba_profiler.process_event(event)
        return self._format_result(event, alert)

    def _format_result(self, event: BehavioralEvent, alert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        result = {
            "entity_id": event.entity_id,
            "entity_type": event.entity_type.value,
            "event_type": event.event_type,
            "risk_score": event.risk_score,
            "is_anomaly": event.is_anomaly,
            "anomaly_reasons": event.anomaly_reasons,
        }
        if alert:
            result["alert"] = alert
        return result


ueba_detector = UEBADetector()
