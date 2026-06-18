"""
CyberNova — Performance Tuner
Dynamically adjusts connection pool sizes, batch sizes, and concurrency limits
based on system load and benchmark results.
"""
import logging
from typing import Any, Dict, Optional

log = logging.getLogger("cybernova.performance.tuner")

DEFAULT_CONFIG = {
    "db_pool_size": 10,
    "db_max_overflow": 20,
    "redis_pool_size": 10,
    "pipeline_batch_size": 100,
    "pipeline_concurrency": 10,
    "soar_concurrency": 5,
    "feed_poll_interval": 3600,
    "retention_interval": 86400,
    "anomaly_window_minutes": 60,
}


class PerformanceTuner:
    """
    Manages performance tuning parameters.
    Adjusts settings based on benchmark results and system load.
    """
    
    def __init__(self):
        self._config = dict(DEFAULT_CONFIG)
        self._best_config = dict(DEFAULT_CONFIG)
        self._best_eps = 0.0
    
    async def apply_config(self, config: Dict[str, Any]) -> None:
        """Apply a performance configuration."""
        from cybernova.config.settings import get_settings
        settings = get_settings()
        
        if "db_pool_size" in config:
            settings.db_pool_size = config["db_pool_size"]
        if "db_max_overflow" in config:
            settings.db_max_overflow = config["db_max_overflow"]
        if "pipeline_batch_size" in config:
            settings.pipeline_batch_size = config["pipeline_batch_size"]
        
        self._config.update(config)
        log.info("Performance config applied: %s", config)
    
    async def auto_tune(self, benchmark_results: Optional[list] = None) -> Dict[str, Any]:
        """
        Analyze benchmark results and recommend optimal config.
        Returns recommended configuration.
        """
        if not benchmark_results:
            return self._config
        
        recommendations = dict(DEFAULT_CONFIG)
        
        best_eps = 0
        for r in benchmark_results:
            eps = r.get("eps", 0)
            if eps > best_eps:
                best_eps = eps
                if eps > self._best_eps:
                    self._best_eps = eps
                    self._best_config["pipeline_batch_size"] = r.get("batch_size", 100)
        
        best_batch = self._best_config.get("pipeline_batch_size", 100)
        if best_batch >= 500:
            recommendations["db_pool_size"] = 20
            recommendations["db_max_overflow"] = 40
        elif best_batch >= 100:
            recommendations["db_pool_size"] = 10
            recommendations["db_max_overflow"] = 20
        else:
            recommendations["db_pool_size"] = 5
            recommendations["db_max_overflow"] = 10
        
        recommendations["pipeline_batch_size"] = best_batch
        
        return recommendations
    
    def get_config(self) -> Dict[str, Any]:
        return dict(self._config)
    
    def get_best_config(self) -> Dict[str, Any]:
        return dict(self._best_config)
    
    def get_best_eps(self) -> float:
        return self._best_eps


performance_tuner = PerformanceTuner()
