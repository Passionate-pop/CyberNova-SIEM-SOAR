from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.cspm.scanners.kubernetes.network")


def _get_networking_api():
    try:
        from kubernetes import client, config
        config.load_incluster_config()
        return client.NetworkingV1Api()
    except ImportError:
        log.warning("kubernetes SDK not installed — K8s network checks unavailable")
        return None
    except Exception:
        try:
            from kubernetes import client, config
            config.load_kube_config()
            return client.NetworkingV1Api()
        except Exception as exc:
            log.warning("Failed to load K8s config: %s", exc)
            return None


def _get_core_api():
    try:
        from kubernetes import client, config
        config.load_incluster_config()
        return client.CoreV1Api()
    except ImportError:
        return None
    except Exception:
        try:
            from kubernetes import client, config
            config.load_kube_config()
            return client.CoreV1Api()
        except Exception:
            return None


def check_k8s_network_policies() -> Dict[str, Any]:
    net_api = _get_networking_api()
    core_api = _get_core_api()
    if net_api is None or core_api is None:
        return {"status": "error", "resource_id": "k8s", "details": "kubernetes SDK unavailable"}

    try:
        namespaces = core_api.list_namespace().items
        ns_with_policies = set()
        policies = net_api.list_network_policy_for_all_namespaces().items
        for p in policies:
            ns_with_policies.add(p.metadata.namespace)

        ns_without_policies = [
            ns.metadata.name for ns in namespaces
            if ns.metadata.name not in ns_with_policies
        ]

        return {
            "status": "passed" if not ns_without_policies else "failed",
            "resource_id": f"k8s:{len(namespaces)}namespaces",
            "details": {
                "total_namespaces": len(namespaces),
                "namespaces_without_network_policies": ns_without_policies,
            },
        }
    except Exception as exc:
        log.error("K8s network policies check failed: %s", exc)
        return {"status": "error", "resource_id": "k8s", "details": str(exc)}
