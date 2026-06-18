from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.cspm.scanners.kubernetes.secrets")


def _get_core_api():
    try:
        from kubernetes import client, config
        config.load_incluster_config()
        return client.CoreV1Api()
    except ImportError:
        log.warning("kubernetes SDK not installed — K8s secrets checks unavailable")
        return None
    except Exception:
        try:
            from kubernetes import client, config
            config.load_kube_config()
            return client.CoreV1Api()
        except Exception as exc:
            log.warning("Failed to load K8s config: %s", exc)
            return None


def check_k8s_secrets_encrypted() -> Dict[str, Any]:
    api = _get_core_api()
    if api is None:
        return {"status": "error", "resource_id": "k8s", "details": "kubernetes SDK unavailable"}

    try:
        secrets = api.list_secret_for_all_namespaces().items
        total = len(secrets)

        return {
            "status": "info",
            "resource_id": f"k8s:{total}secrets",
            "details": {
                "total_secrets": total,
                "note": "Verify etcd encryption is enabled at the cluster level via EncryptionConfiguration",
            },
        }
    except Exception as exc:
        log.error("K8s secrets check failed: %s", exc)
        return {"status": "error", "resource_id": "k8s", "details": str(exc)}
