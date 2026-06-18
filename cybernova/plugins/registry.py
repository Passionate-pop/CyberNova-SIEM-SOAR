"""
CyberNova — Plugin System
Supports custom detectors, integrations, and response actions.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("cybernova.plugins")


class PluginMetadata:
    """Tracks operational metadata for a plugin instance."""

    def __init__(self) -> None:
        self.enabled: bool = True
        self.last_used: Optional[datetime] = None
        self.error_count: int = 0
        self.last_error: Optional[str] = None
        self.initialized_at: Optional[datetime] = None

    def record_use(self) -> None:
        self.last_used = datetime.now(timezone.utc)

    def record_error(self, error: str) -> None:
        self.error_count += 1
        self.last_error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "initialized_at": self.initialized_at.isoformat() if self.initialized_at else None,
        }


class BasePlugin(ABC):
    """Base class for all CyberNova plugins."""

    name: str = "unnamed_plugin"
    version: str = "0.1.0"
    plugin_type: str = "generic"  # detector | integration | response_action

    def __init__(self) -> None:
        self.metadata = PluginMetadata()

    @abstractmethod
    async def initialize(self) -> None:
        """Called when plugin is loaded."""
        self.metadata.initialized_at = datetime.now(timezone.utc)

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the plugin's main function."""
        ...

    async def teardown(self) -> None:
        """Called when plugin is unloaded."""
        pass

    def validate(self) -> List[str]:
        """Validate plugin configuration. Returns list of errors (empty = valid)."""
        errors: List[str] = []
        if not self.name or self.name == "unnamed_plugin":
            errors.append("Plugin name must be set")
        if not self.version:
            errors.append("Plugin version must be set")
        return errors


class DetectorPlugin(BasePlugin):
    """Base class for detection plugins."""

    plugin_type = "detector"

    @abstractmethod
    async def detect(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return list of detected threats."""
        ...

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {"detections": await self.detect(context)}


class IntegrationPlugin(BasePlugin):
    """Base class for third-party integration plugins."""

    plugin_type = "integration"

    @abstractmethod
    async def send_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send an event to the external integration.

        Args:
            event_type: The type of event to send (e.g. 'alert', 'incident', 'case').
            payload: The event data to send.

        Returns:
            A dict with at minimum a 'success' bool and optionally a 'response' or 'error' key.
        """
        ...

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check connectivity to the external integration service.

        Returns:
            A dict with 'healthy' (bool), 'latency_ms' (float), and optionally 'details'.
        """
        ...


class ResponsePlugin(BasePlugin):
    """Base class for response action plugins."""

    plugin_type = "response_action"

    @abstractmethod
    async def execute_action(self, action_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a response action.

        Args:
            action_name: The name of the action to perform.
            params: Parameters for the action.

        Returns:
            A dict with 'success' (bool), 'action' (str), and optionally 'result' or 'error'.
        """
        ...

    @abstractmethod
    async def validate_params(self, action_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate action parameters before execution.

        Args:
            action_name: The name of the action to validate.
            params: Parameters to validate.

        Returns:
            A dict with 'valid' (bool) and optionally 'errors' (list of str).
        """
        ...


class PluginRegistry:
    """Central registry for all plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, BasePlugin] = {}

    async def register(self, plugin: BasePlugin) -> None:
        """Register a plugin after validation and initialization."""
        errors = plugin.validate()
        if errors:
            raise ValueError(f"Plugin {plugin.name} validation failed: {'; '.join(errors)}")

        await plugin.initialize()
        self._plugins[plugin.name] = plugin
        log.info("Plugin registered: %s v%s (%s)", plugin.name, plugin.version, plugin.plugin_type)

    async def unregister(self, name: str) -> None:
        """Unregister a plugin and run its teardown."""
        plugin = self._plugins.pop(name, None)
        if plugin:
            try:
                await plugin.teardown()
            except Exception as e:
                log.warning("Plugin %s teardown error: %s", name, e)
            log.info("Plugin unregistered: %s", name)

    def get(self, name: str) -> Optional[BasePlugin]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_by_type(self, plugin_type: str) -> List[BasePlugin]:
        """Get all plugins of a given type."""
        return [p for p in self._plugins.values() if p.plugin_type == plugin_type]

    def list_all(self) -> List[Dict[str, str]]:
        """List all registered plugins."""
        return [
            {"name": p.name, "version": p.version, "type": p.plugin_type}
            for p in self._plugins.values()
        ]

    def plugin_details(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed info about a plugin including metadata."""
        plugin = self._plugins.get(name)
        if not plugin:
            return None
        return {
            "name": plugin.name,
            "version": plugin.version,
            "type": plugin.plugin_type,
            "metadata": plugin.metadata.to_dict(),
        }

    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin."""
        plugin = self._plugins.get(name)
        if not plugin:
            return False
        plugin.metadata.enabled = True
        log.info("Plugin enabled: %s", name)
        return True

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin."""
        plugin = self._plugins.get(name)
        if not plugin:
            return False
        plugin.metadata.enabled = False
        log.info("Plugin disabled: %s", name)
        return True


plugin_registry = PluginRegistry()
