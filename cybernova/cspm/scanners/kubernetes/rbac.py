from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.cspm.scanners.kubernetes.rbac")


def _get_core_api():
    try:
        from kubernetes import client, config
        config.load_incluster_config()
        return client.CoreV1Api()
    except ImportError:
        log.warning("kubernetes SDK not installed — K8s RBAC checks unavailable")
        return None
    except Exception:
        try:
            from kubernetes import client, config
            config.load_kube_config()
            return client.CoreV1Api()
        except Exception as exc:
            log.warning("Failed to load K8s config: %s", exc)
            return None


def _get_rbac_api():
    try:
        from kubernetes import client, config
        config.load_incluster_config()
        return client.RbacAuthorizationV1Api()
    except ImportError:
        log.warning("kubernetes SDK not installed — K8s RBAC checks unavailable")
        return None
    except Exception:
        try:
            from kubernetes import client, config
            config.load_kube_config()
            return client.RbacAuthorizationV1Api()
        except Exception as exc:
            log.warning("Failed to load K8s config: %s", exc)
            return None


def check_k8s_rbac_cluster_admin() -> Dict[str, Any]:
    rbac_api = _get_rbac_api()
    if rbac_api is None:
        return {"status": "error", "resource_id": "k8s", "details": "kubernetes SDK unavailable"}

    try:
        bindings = rbac_api.list_cluster_role_binding().items
        cluster_admin_bindings = []
        for binding in bindings:
            if binding.role_ref.name == "cluster-admin":
                subjects = binding.subjects or []
                for subject in subjects:
                    cluster_admin_bindings.append({
                        "binding": binding.metadata.name,
                        "subject_kind": subject.kind,
                        "subject_name": subject.name,
                        "namespace": subject.namespace or "cluster-wide",
                    })

        return {
            "status": "failed" if cluster_admin_bindings else "passed",
            "resource_id": "k8s:rbac",
            "details": {
                "cluster_admin_bindings": cluster_admin_bindings,
            },
        }
    except Exception as exc:
        log.error("K8s RBAC cluster admin check failed: %s", exc)
        return {"status": "error", "resource_id": "k8s", "details": str(exc)}
