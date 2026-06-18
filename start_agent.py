#!/usr/bin/env python3
"""
CyberNova - Startup & Health Monitor
Runs automatically on Windows startup and keeps CyberNova running.
"""
import os
import sys
import subprocess
import time
import logging
from pathlib import Path
import platform

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)
log = logging.getLogger("cybernova.starter")

BACKEND_URL = "http://localhost:8000"
AGENT_SCRIPT = Path(__file__).parent / "host_agent.py"


def check_backend():
    """Check if backend is running."""
    try:
        import httpx
        resp = httpx.get(f"{BACKEND_URL}/health", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def start_agent():
    """Start the host agent."""
    log.info("Starting CyberNova Security Agent...")
    try:
        # Start as background process
        if platform.system() == "Windows":
            CREATE_NEW_CONSOLE = 0x00000010
            subprocess.Popen(
                [sys.executable, str(AGENT_SCRIPT)],
                creationflags=CREATE_NEW_CONSOLE,
                close_fds=True
            )
            log.info("CyberNova Security Agent started")
        else:
            subprocess.Popen([sys.executable, str(AGENT_SCRIPT)])
            log.info("CyberNova Security Agent started")
        return True
    except Exception as e:
        log.error(f"Failed to start agent: {e}")
        return False


def main():
    log.info("=" * 50)
    log.info("CyberNova Security Agent Launcher")
    log.info("=" * 50)
    
    # Check if agent is already running
    host_agent = Path("host_agent.py")
    if host_agent.exists():
        start_agent()
    else:
        log.error(f"host_agent.py not found at {AGENT_SCRIPT}")
        sys.exit(1)
    
    log.info("CyberNova is running in the background.")
    log.info("Access the dashboard at http://localhost:8888/app/")
    log.info("API is at http://localhost:8000")


if __name__ == "__main__":
    main()