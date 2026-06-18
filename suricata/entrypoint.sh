#!/bin/bash
set -e

# Set up nfqueue iptables rules
# Requires --cap-add=NET_ADMIN
IPTABLES=iptables
if [ -x /sbin/iptables ]; then
    IPTABLES=/sbin/iptables
fi

# Allow loopback traffic to bypass NFQUEUE (critical for event_bridge to reach localhost:8000)
$IPTABLES -I INPUT -i lo -j ACCEPT 2>/dev/null || echo "[entrypoint] iptables loopback INPUT bypass skipped"
$IPTABLES -I OUTPUT -o lo -j ACCEPT 2>/dev/null || echo "[entrypoint] iptables loopback OUTPUT bypass skipped"

# Forward external traffic to Suricata NFQUEUE for inspection
$IPTABLES -A INPUT -j NFQUEUE --queue-num 0 2>/dev/null || echo "[entrypoint] iptables INPUT -> NFQUEUE skipped (no permissions)"
$IPTABLES -A OUTPUT -j NFQUEUE --queue-num 0 2>/dev/null || echo "[entrypoint] iptables OUTPUT -> NFQUEUE skipped (no permissions)"
$IPTABLES -I FORWARD -j NFQUEUE --queue-num 0 2>/dev/null || echo "[entrypoint] iptables FORWARD -> NFQUEUE skipped (no permissions)"

# Ensure eve log directory exists
mkdir -p /var/log/suricata

# Start Suricata in nfqueue mode in background
suricata -c /etc/suricata/suricata.yaml \
    --pidfile /var/run/suricata.pid \
    -q 0 \
    -D 2>&1 | while IFS= read -r line; do echo "[suricata] $line"; done

# Wait for eve.json to be created
for i in $(seq 1 30); do
    if [ -f /var/log/suricata/eve.json ]; then
        break
    fi
    sleep 1
done

# Start event bridge (foreground — keeps container alive)
echo "[entrypoint] Starting event bridge..."
exec python3 /opt/cybernova/event_bridge.py
