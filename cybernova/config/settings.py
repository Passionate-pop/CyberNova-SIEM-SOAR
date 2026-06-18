"""
CyberNova — Centralized Configuration
Loads from .env with Pydantic validation. Supports Docker secrets via *_FILE env vars.
Zero hardcoded secrets.

Secret resolution priority:
  1. Direct env var (e.g., JWT_SECRET=abc)
  2. File-based secret (e.g., JWT_SECRET_FILE=/run/secrets/jwt_secret)
  3. Default value from Settings class
"""
from __future__ import annotations

import os
import logging
from functools import lru_cache
from pathlib import Path
from typing import List
from urllib.parse import quote

from pydantic_settings import BaseSettings

log = logging.getLogger("cybernova.settings")


class Settings(BaseSettings):
    """Application settings loaded from environment variables / .env file."""

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }

    def model_post_init(self, __context) -> None:
        """Post-initialization hook: load Docker secrets after field values are set."""
        self._load_file_secrets()

    # ── Application ──
    app_name: str = "CyberNova"
    app_version: str = "2.0.0"
    environment: str = "production"
    debug: bool = False
    host: str = "0.0.0.0"  # nosec - required for API service binding
    port: int = 8000
    max_request_size: int = 1048576  # 1MB default
    log_level: str = "INFO"

    # ── Syslog Server ──
    syslog_enabled: bool = False
    syslog_udp_host: str = "0.0.0.0"  # nosec - required for network service binding
    syslog_udp_port: int = 5140
    syslog_tcp_host: str = "0.0.0.0"  # nosec - required for network service binding
    syslog_tcp_port: int = 5141

    # ── Security ──
    secret_key: str = "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING"
    admin_password: str = ""  # injected via ADMIN_PASSWORD_FILE
    agent_password: str = ""  # injected via AGENT_PASSWORD_FILE
    access_token_expire_minutes: int = 30
    cors_origins: str = "http://localhost,http://localhost:3000,http://localhost:5173,http://localhost:8080,http://localhost:8888,http://127.0.0.1,https://localhost"
    rate_limit: int = 100
    max_login_attempts: int = 5
    lockout_minutes: int = 15

    # ── SOAR Webhook ──
    cybernova_webhook_token: str = ""

    # ── Database ──
    database_url: str = ""
    database_url_replica: str = ""  # read replica for dashboard queries
    db_pool_size: int = 0  # 0 = auto-calculate from EPS formula
    db_max_overflow: int = 0  # 0 = auto-calculate (pool_size // 2)
    db_pool_timeout: int = 10
    db_pool_recycle: int = 1800  # recycle connections after 30 min
    db_max_connections: int = 250  # PostgreSQL max_connections target
    db_expected_eps: int = 10_000  # expected events per second for pool sizing
    db_batch_size: int = 100  # pipeline worker batch size
    postgres_password: str = ""  # injected via POSTGRES_PASSWORD_FILE

    # ── Redis ──
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: str = ""
    redis_url_override: str = ""
    redis_sentinel_hosts: str = ""  # comma-separated "host1:port1,host2:port2"
    redis_sentinel_master: str = "mymaster"  # Sentinel master group name
    disable_streams: bool = False
    redis_pool_size: int = 50
    redis_socket_timeout: int = 10
    redis_socket_connect_timeout: int = 5
    redis_maxmemory: str = "512mb"
    redis_maxmemory_policy: str = "allkeys-lru"
    redis_memory_warn_pct: int = 60
    redis_memory_check_interval: int = 60

    # ── Kafka / Redpanda ──
    kafka_bootstrap_servers: str = ""
    kafka_security_protocol: str = "PLAINTEXT"
    kafka_sasl_mechanism: str = ""
    kafka_sasl_username: str = ""
    kafka_sasl_password: str = ""
    kafka_group_id: str = "cybernova-pipeline"
    kafka_max_batch_size: int = 1000
    kafka_retry_backoff_ms: int = 500
    kafka_commit_interval_ms: int = 5000
    kafka_partitions: int = 3
    partition_by_tenant: bool = True
    partition_mode: str = "key"

    # ── Threat Intelligence ──
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""

    # ── Built-in SOAR ──
    soar_enabled: bool = True
    soar_auto_approve_timeout: int = 15  # seconds — auto-block if no user response

    # ── Integrations (Third-Party Connectors) ──
    integrations_slack_webhook: str = ""
    integrations_slack_token: str = ""
    integrations_teams_webhook: str = ""
    integrations_pagerduty_key: str = ""
    integrations_jira_url: str = ""
    integrations_jira_email: str = ""
    integrations_jira_token: str = ""
    integrations_jira_project: str = "SEC"
    integrations_misp_url: str = ""
    integrations_misp_key: str = ""
    integrations_thehive_url: str = ""
    integrations_thehive_key: str = ""
    integrations_splunk_url: str = ""
    integrations_splunk_token: str = ""
    integrations_splunk_index: str = "security"
    integrations_opencti_url: str = ""
    integrations_opencti_token: str = ""
    integrations_taxii_url: str = ""
    integrations_taxii_username: str = ""
    integrations_taxii_password: str = ""
    integrations_taxii2_url: str = ""
    integrations_taxii2_username: str = ""
    integrations_taxii2_password: str = ""
    integrations_servicenow_url: str = ""
    integrations_servicenow_username: str = ""
    integrations_servicenow_password: str = ""

    # ── CyberNova Base URL (used in integration links) ──
    cybernova_base_url: str = "http://localhost:8000"

    # ── AI (local only — Ollama/LM Studio, $0) ──
    ai_provider: str = "local"
    embedding_model: str = "all-MiniLM-L6-v2"

    # ── Email / Notifications ──
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_email: str = "noreply@cybernova.io"
    from_name: str = "CyberNova"


    # ── On-Call / Alerting ──
    oncall_email: str = ""

    # ── Shutdown Grace Period ──
    shutdown_grace_period: int = 30  # seconds to drain in-flight events before hard shutdown

    # ── Retention / Cold Storage ──
    cold_storage_path: str = "data/cold_storage"
    retention_run_interval: int = 86400
    retention_default_days_alerts: int = 90
    retention_default_days_events: int = 14

    # ── Agent Signing ──
    agent_signing_private_key: str = ""

    # ── OpenTelemetry ──
    otel_endpoint: str = "http://localhost:4318/v1/traces"
    otel_service_name: str = "cybernova"
    otel_enabled: bool = True

    # ── Backup / Disaster Recovery ──
    backup_retention_days: int = 30

    # ── Docker Secrets Support ─────────────────────────────────
    # Maps env var names to their Docker secret file counterparts.
    # If the _FILE var is set, the file content overrides the field value.
    _FILE_SECRET_MAP = {
        "database_url": "DATABASE_URL_FILE",  # nosec - env var name, not secret value
        "postgres_password": "POSTGRES_PASSWORD_FILE",  # nosec - env var name, not secret value
        "redis_password": "REDIS_PASSWORD_FILE",  # nosec - env var name, not secret value
        "smtp_password": "SMTP_PASSWORD_FILE",  # nosec - env var name, not secret value
        "integrations_slack_webhook": "SLACK_WEBHOOK_FILE",  # nosec - env var name, not secret value
        "integrations_slack_token": "SLACK_TOKEN_FILE",  # nosec - env var name, not secret value
        "integrations_teams_webhook": "TEAMS_WEBHOOK_FILE",  # nosec - env var name, not secret value
        "integrations_pagerduty_key": "PAGERDUTY_KEY_FILE",  # nosec - env var name, not secret value
        "integrations_jira_token": "JIRA_TOKEN_FILE",  # nosec - env var name, not secret value
        "integrations_misp_key": "MISP_KEY_FILE",  # nosec - env var name, not secret value
        "integrations_thehive_key": "THEHIVE_KEY_FILE",  # nosec - env var name, not secret value
        "integrations_splunk_token": "SPLUNK_TOKEN_FILE",  # nosec - env var name, not secret value
        "integrations_opencti_token": "OPENCTI_TOKEN_FILE",  # nosec - env var name, not secret value
        "virustotal_api_key": "VIRUSTOTAL_API_KEY_FILE",  # nosec - env var name, not secret value
        "abuseipdb_api_key": "ABUSEIPDB_API_KEY_FILE",  # nosec - env var name, not secret value
        "otx_api_key": "OTX_API_KEY_FILE",  # nosec - env var name, not secret value
        "cybernova_webhook_token": "WEBHOOK_TOKEN_FILE",  # nosec - env var name, not secret value
        "integrations_servicenow_password": "SERVICENOW_PASSWORD_FILE",  # nosec - env var name, not secret value
        "admin_password": "ADMIN_PASSWORD_FILE",  # nosec - env var name, not secret value
        "agent_password": "AGENT_PASSWORD_FILE",  # nosec - env var name, not secret value
    }

    def _load_file_secrets(self) -> None:
        """Read *_FILE env vars and override corresponding fields."""
        for field_name, file_var in self._FILE_SECRET_MAP.items():
            file_path = os.environ.get(file_var)
            if file_path:
                try:
                    with open(file_path, "r") as f:
                        value = f.read().strip()
                    if value:
                        setattr(self, field_name, value)
                        log.debug("Loaded secret for %s from %s", field_name, file_path)
                except Exception as e:
                    log.warning("Failed to read secret file %s for %s: %s", file_path, field_name, e)

    # ── Derived ──
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def _build_database_url(self, scheme: str = "postgresql+asyncpg") -> str:
        """Build a database URL with injected password.

        Args:
            scheme: The SQLAlchemy dialect scheme.
                    Use 'postgresql+asyncpg' for async (fast, no deadlocks).
                    Use 'postgresql+psycopg' for sync/Alembic.
        """
        url = self.database_url
        if not url:
            db_path = Path(__file__).resolve().parent.parent.parent / "cybernova.db"
            return f"sqlite+aiosqlite:///{db_path}"
        if self.postgres_password and "postgresql" in url:
            try:
                parts = url.split("://", 1)
                auth_and_host = parts[1].split("/", 1)
                user_and_host = auth_and_host[0]
                db_and_params = "/" + auth_and_host[1] if len(auth_and_host) > 1 else ""
                if "@" in user_and_host:
                    user_part, host = user_and_host.rsplit("@", 1)
                    user = user_part.split(":", 1)[0] if ":" in user_part else user_part
                else:
                    # No @ means no user info in URL — just host
                    user = "cybernova"
                    host = user_and_host
                encoded_password = quote(self.postgres_password, safe='')
                # Replace whatever scheme is in the URL with the requested one
                url = f"{scheme}://{user}:{encoded_password}@{host}{db_and_params}"
            except (IndexError, ValueError) as e:
                if not url:
                    log.info("DATABASE_URL not configured — using SQLite fallback")
                else:
                    log.warning("Failed to parse DATABASE_URL '%s': %s — using as-is", url, e)
        return url

    @property
    def effective_database_url(self) -> str:
        """Async database URL — uses asyncpg (fast, deadlock-free)."""
        return self._build_database_url(scheme="postgresql+asyncpg")

    @property
    def effective_replica_database_url(self) -> str:
        if self.database_url_replica:
            return self.database_url_replica
        return ""

    @property
    def sync_database_url(self) -> str:
        """Sync database URL — uses psycopg3 for Alembic migrations."""
        return self._build_database_url(scheme="postgresql+psycopg")

    @property
    def resolved_redis_url(self) -> str:
        if self.redis_url_override:
            return self.redis_url_override
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"

    def validate(self) -> list[str]:
        """Return list of validation warnings/errors. Empty = all good.

        Raises ValueError for CRITICAL violations that must block startup:
        - DEBUG=True in production (exposes stack traces, secrets, internal state)
        - SECRET_KEY set to a known weak default in production (compromises JWT)
        """
        issues: list[str] = []

        # ── CRITICAL: DEBUG in production ────────────────────────────────────
        # Stack traces expose: SQL queries (with data), file paths, env vars,
        # internal IPs, and code structure. Attackers use this for reconnaissance.
        if self.environment == "production" and self.debug:
            raise ValueError(
                "DEBUG=True in production environment. This is a CRITICAL "
                "security vulnerability. DEBUG mode exposes detailed stack traces, "
                "environment variables, source code snippets, and database query "
                "information to end users. Set DEBUG=False in your .env or "
                "environment variables before starting the application."
            )

        # ── CRITICAL: Weak SECRET_KEY in production ─────────────────────────
        # The SECRET_KEY is used for JWT token signing. A weak or default key
        # allows attackers to forge authentication tokens and impersonate any user.
        _weak_secrets = frozenset({
            "",
            "CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING",
            "cybernova-secret-key-change-in-production",
        })
        if self.environment == "production":
            if self.secret_key in _weak_secrets:
                raise ValueError(
                    "SECRET_KEY is set to a known weak default value. "
                    "This compromises ALL JWT token signatures — attackers can "
                    "forge authentication tokens and gain unauthorized access. "
                    "Generate a secure key:  "
                    "python -c \"import secrets; print(secrets.token_hex(32))\""
                )
            if len(self.secret_key) < 32:
                issues.append(
                    f"SECRET_KEY is only {len(self.secret_key)} characters. "
                    "Minimum 32 characters (256 bits) required for HMAC-SHA256 "
                    "in production."
                )

        # ── Non-critical: dev mode with default key ──────────────────────────
        if not self.is_production:
            if self.secret_key in _weak_secrets:
                issues.append(
                    "SECRET_KEY is set to a known default. Recommended to set a "
                    "unique key even in development."
                )

        return issues


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()

