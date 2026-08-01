"""
CyberNova — Agent Command Router
Endpoints for agent management and command dispatch.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter

log = logging.getLogger("cybernova.agent_commands")

router = APIRouter(prefix="/api/v1/agent", tags=["Agent Commands"])

# Agent commands will be added here in the future as needed
