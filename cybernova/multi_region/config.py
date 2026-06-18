from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List

log = logging.getLogger("cybernova.multi_region.config")

REGIONS = {
    "us-east-1": "United States (East)",
    "us-west-2": "United States (West)",
    "eu-west-1": "Europe (West)",
    "eu-central-1": "Europe (Central)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "sa-east-1": "South America (Sao Paulo)",
}

DEFAULT_PEER_REGIONS = ["us-west-2", "eu-west-1"]


@dataclass
class RegionConfig:
    enabled: bool = False
    current_region: str = "us-east-1"
    peer_regions: List[str] = field(default_factory=lambda: list(DEFAULT_PEER_REGIONS))
    replication_topic: str = "cybernova-global-events"
    replication_batch_size: int = 100
    replication_interval: int = 60
    heartbeat_interval: int = 30
    failover_timeout: int = 120
    api_endpoints: Dict[str, str] = field(default_factory=dict)


region_config = RegionConfig()


def load_region_config(config_path: str = "") -> RegionConfig:
    if not config_path:
        return region_config
    try:
        with open(config_path) as f:
            data = json.load(f)
        for k, v in data.items():
            if hasattr(region_config, k):
                setattr(region_config, k, v)
        log.info("Region config loaded from %s", config_path)
    except Exception as e:
        log.warning("Could not load region config: %s", e)
    return region_config
