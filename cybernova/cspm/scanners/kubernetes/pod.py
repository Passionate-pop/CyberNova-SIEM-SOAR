from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger("cybernova.cspm.scanners.kubernetes.pod")


def _get_core_api():
    try:
        from kubernetes import client, config
        config.load_incluster_config()
        return client.CoreV1Api()
    except ImportError:
        log.warning("kubernetes SDK not installed — K8s pod checks unavailable")
        return None
    except Exception:
        try:
            from kubernetes import client, config
            config.load_kube_config()
            return client.CoreV1Api()
        except Exception as exc:
            log.warning("Failed to load K8s config: %s", exc)
            return None


def check_k8s_pod_security() -> Dict[str, Any]:
    core_api = _get_core_api()
    if core_api is None:
        return {"status": "error", "resource_id": "k8s", "details": "kubernetes SDK unavailable"}

    try:
        pods = core_api.list_pod_for_all_namespaces().items
        privileged_pods = []
        for pod in pods:
            containers = pod.spec.containers or []
            for c in containers:
                sec = c.security_context
                if sec and sec.privileged:
                    privileged_pods.append({
                        "pod": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "container": c.name,
                    })
                    break

        return {
            "status": "failed" if privileged_pods else "passed",
            "resource_id": f"k8s:{len(pods)}pods",
            "details": {
                "total_pods": len(pods),
                "privileged_pods": privileged_pods,
            },
        }
    except Exception as exc:
        log.error("K8s pod security check failed: %s", exc)
        return {"status": "error", "resource_id": "k8s", "details": str(exc)}


def check_k8s_container_resource_limits() -> Dict[str, Any]:
    core_api = _get_core_api()
    if core_api is None:
        return {"status": "error", "resource_id": "k8s", "details": "kubernetes SDK unavailable"}

    try:
        pods = core_api.list_pod_for_all_namespaces().items
        no_limits = []
        for pod in pods:
            containers = pod.spec.containers or []
            for c in containers:
                if not c.resources or not c.resources.limits:
                    no_limits.append({
                        "pod": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "container": c.name,
                    })

        return {
            "status": "passed" if not no_limits else "failed",
            "resource_id": f"k8s:{len(pods)}pods",
            "details": {
                "total_pods": len(pods),
                "containers_without_limits": no_limits,
            },
        }
    except Exception as exc:
        log.error("K8s resource limits check failed: %s", exc)
        return {"status": "error", "resource_id": "k8s", "details": str(exc)}


def check_k8s_non_root_containers() -> Dict[str, Any]:
    core_api = _get_core_api()
    if core_api is None:
        return {"status": "error", "resource_id": "k8s", "details": "kubernetes SDK unavailable"}

    try:
        pods = core_api.list_pod_for_all_namespaces().items
        root_containers = []
        for pod in pods:
            containers = pod.spec.containers or []
            for c in containers:
                sec = c.security_context
                run_as_non_root = sec.run_as_non_root if sec else None
                if run_as_non_root is not True:
                    root_containers.append({
                        "pod": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "container": c.name,
                    })

        return {
            "status": "passed" if not root_containers else "failed",
            "resource_id": f"k8s:{len(pods)}pods",
            "details": {
                "total_pods": len(pods),
                "containers_may_run_as_root": root_containers,
            },
        }
    except Exception as exc:
        log.error("K8s non-root check failed: %s", exc)
        return {"status": "error", "resource_id": "k8s", "details": str(exc)}


def check_k8s_readonly_root_fs() -> Dict[str, Any]:
    core_api = _get_core_api()
    if core_api is None:
        return {"status": "error", "resource_id": "k8s", "details": "kubernetes SDK unavailable"}

    try:
        pods = core_api.list_pod_for_all_namespaces().items
        writable_containers = []
        for pod in pods:
            containers = pod.spec.containers or []
            for c in containers:
                sec = c.security_context
                read_only = sec.read_only_root_filesystem if sec else None
                if read_only is not True:
                    writable_containers.append({
                        "pod": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "container": c.name,
                    })

        return {
            "status": "passed" if not writable_containers else "failed",
            "resource_id": f"k8s:{len(pods)}pods",
            "details": {
                "total_pods": len(pods),
                "writable_root_containers": writable_containers,
            },
        }
    except Exception as exc:
        log.error("K8s read-only rootfs check failed: %s", exc)
        return {"status": "error", "resource_id": "k8s", "details": str(exc)}
