"""Integration registry — manages lifecycle of all third-party connectors."""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional
from cybernova.plugins.registry import IntegrationPlugin, plugin_registry

log = logging.getLogger("cybernova.integrations.registry")


class IntegrationRegistry:
    def __init__(self):
        self._connectors: Dict[str, IntegrationPlugin] = {}
        self._initialized = False

    async def register(self, connector: IntegrationPlugin) -> None:
        await connector.initialize()
        self._connectors[connector.name] = connector
        await plugin_registry.register(connector)
        log.info("Integration registered: %s v%s", connector.name, connector.version)

    async def initialize_all(self) -> int:
        count = 0
        connectors = [
            SlackConnector(), TeamsConnector(), PagerDutyConnector(),
            JiraConnector(), ServiceNowConnector(), MISPConnector(), TheHiveConnector(),
            SplunkConnector(), OpenCTIConnector(),
        ]
        for c in connectors:
            try:
                await self.register(c)
                count += 1
            except Exception as e:
                log.warning("Failed to register %s: %s", c.__class__.__name__, e)
        self._initialized = True
        return count

    def get(self, name: str) -> Optional[IntegrationPlugin]:
        return self._connectors.get(name)

    def list_all(self) -> List[Dict[str, str]]:
        return [{"name": n, "version": c.version, "type": c.plugin_type}
                for n, c in self._connectors.items()]

    async def send_to_all(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, bool]:
        results = {}
        for name, connector in self._connectors.items():
            try:
                resp = await connector.execute({"event": event_type, "payload": payload})
                results[name] = resp.get("success", False)
            except Exception as e:
                log.error("Integration %s failed: %s", name, e)
                results[name] = False
        return results

    async def shutdown_all(self):
        for name, connector in self._connectors.items():
            try:
                await connector.teardown()
            except Exception as e:
                log.warning("Teardown %s failed: %s", name, e)


integration_registry = IntegrationRegistry()

# Late imports to avoid circular deps
from cybernova.integrations.slack_connector import SlackConnector  # noqa: E402
from cybernova.integrations.teams_connector import TeamsConnector  # noqa: E402
from cybernova.integrations.pagerduty_connector import PagerDutyConnector  # noqa: E402
from cybernova.integrations.jira_connector import JiraConnector  # noqa: E402
from cybernova.integrations.servicenow_connector import ServiceNowConnector  # noqa: E402
from cybernova.integrations.misp_connector import MISPConnector  # noqa: E402
from cybernova.integrations.thehive_connector import TheHiveConnector  # noqa: E402
from cybernova.integrations.splunk_connector import SplunkConnector  # noqa: E402
from cybernova.integrations.opencti_connector import OpenCTIConnector  # noqa: E402
