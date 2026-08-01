"""
Start the CyberNova host agent with credentials from agent_config.json.
This launches the agent for 24/7 background monitoring.
"""
import json
import os
import subprocess
import sys

# Read config
config_path = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "CyberNova", "agent_config.json")
if not os.path.exists(config_path):
    # Fallback to project root
    config_path = "agent_config.json"
if not os.path.exists(config_path):
    config_path = os.path.join(os.path.dirname(__file__), "..", "login.json")

print(f"Reading config from: {config_path}")

with open(config_path) as f:
    cfg = json.load(f)

token = cfg.get("token", "")
api_url = cfg.get("api_url", "http://localhost:8000")

# Find host_agent.py
agent_path = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "CyberNova", "host_agent.py")
if not os.path.exists(agent_path):
    # Try project root
    agent_path = os.path.join(os.path.dirname(__file__), "..", "host_agent.py")
if not os.path.exists(agent_path):
    print("ERROR: host_agent.py not found!")
    sys.exit(1)

print(f"Agent script: {agent_path}")
print(f"Backend URL:  {api_url}")
print(f"Token:        {token[:20]}...{token[-10:]}")
print()

# Verify backend is reachable first
import requests
try:
    r = requests.get(f"{api_url}/", timeout=5)
    print(f"Backend status: {r.status_code} - {r.json().get('pipeline', '?')}")
except Exception as e:
    print(f"WARNING: Backend check failed: {e}")
    print("Starting agent anyway...")

# Set env vars and start the agent
env = os.environ.copy()
env["CYBERNOVA_DEVICE_TOKEN"] = token
env["CYBERNOVA_API_URL"] = api_url

print("\nStarting CyberNova Host Agent...")
print("=" * 60)

# Start in a new window so it can run independently
if sys.platform == "win32":
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    proc = subprocess.Popen(
        ["python", agent_path],
        env=env,
        startupinfo=startupinfo,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
else:
    proc = subprocess.Popen(
        ["python3", agent_path],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

print(f"Agent started! PID: {proc.pid}")
print(f"\nThe agent will scan your system every 30 seconds.")
print(f"Any suspicious files/registry/processes will be reported")
print(f"to the CyberNova dashboard in real-time.")
print(f"\nDashoard: {api_url}/app/")
print()

# Show first few lines of output
import time
time.sleep(2)
try:
    output = proc.stdout.read(1024).decode("utf-8", errors="replace")
    if output:
        print("Agent initial output:")
        for line in output.split("\n")[:15]:
            if line.strip():
                print(f"  {line}")
except:
    pass
