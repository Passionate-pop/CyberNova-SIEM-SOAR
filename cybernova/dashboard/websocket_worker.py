"""
CyberNova — Dashboard WebSocket Push Worker
Periodically broadcasts dashboard snapshots to all connected tenants.
"""
from __future__ import annotations

import asyncio
import logging

from cybernova.api.websocket import connection_manager, ws_handler

log = logging.getLogger("cybernova.dashboard.websocket_worker")


class DashboardPushWorker:

    def __init__(self):
        self._stop = False

    async def start(self) -> None:
        log.info("Dashboard push worker started")
        while not self._stop:
            await asyncio.sleep(10)
            tenant_ids = connection_manager.get_tenant_ids()
            for tenant_id in tenant_ids:
                try:
                    await ws_handler.broadcast_dashboard_snapshot(tenant_id)
                except Exception as e:
                    log.debug("Dashboard push error for tenant %s: %s", tenant_id, e)

    async def stop(self) -> None:
        self._stop = True
        log.info("Dashboard push worker stopped")


dashboard_push_worker = DashboardPushWorker()
