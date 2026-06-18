FROM jasonish/suricata:7.0

# Install Python + dependencies for event bridge (AlmaLinux base)
RUN dnf install -y \
    python3 \
    python3-pip \
    python3-aiohttp \
    iptables \
    net-tools \
    procps-ng \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# Copy configs and bridge script
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY event_bridge.py /opt/cybernova/event_bridge.py
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh && \
    suricata-update -q 2>/dev/null || true

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD suricata --build-info || exit 1

ENTRYPOINT ["/entrypoint.sh"]
