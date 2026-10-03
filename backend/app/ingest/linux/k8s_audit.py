"""Kubernetes API-server audit log parser (JSON lines of ``audit.k8s.io`` events).

The audit log is the record of who did what in a cluster: every request to the API server with
the caller, the verb, the object, where it came from and whether it was allowed. For an
intrusion that is the trail of a pod exec, a secret read, a role binding change or a privileged
workload being created.

    {"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","stage":"ResponseComplete",
     "requestURI":"/api/v1/namespaces/default/pods/web/exec","verb":"create",
     "user":{"username":"alice","groups":["system:authenticated"]},"sourceIPs":["203.0.113.9"],
     "objectRef":{"resource":"pods","subresource":"exec","namespace":"default","name":"web"},
     "responseStatus":{"code":101},"requestReceivedTimestamp":"2024-03-01T10:20:30.123456Z",
     "annotations":{"authorization.k8s.io/decision":"allow"}}

Lines are flagged, never judged: ``suspicious_indicators`` lists generic, widely documented
markers (an exec into a pod, a secret read, an RBAC change, a privileged or host-mounting
workload, an anonymous caller) for an analyst to review. Request and response bodies can be
very large, so a line over ``MAX_LINE_CHARS`` is not parsed and is reported as such.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from typing import Any

ARTIFACT_FAMILY = "linux_k8s_audit"
ARTIFACT_TYPE = "k8s_audit"
MAX_LINE_CHARS = 2 * 1024 * 1024
MAX_GROUPS = 32
MAX_CONTAINERS = 64

_WRITE_VERBS = {"create", "update", "patch", "delete", "deletecollection"}
_READ_VERBS = {"get", "list", "watch"}
_RBAC_RESOURCES = {"clusterrolebindings", "rolebindings", "clusterroles", "roles"}
_WORKLOAD_RESOURCES = {"pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs", "replicationcontrollers"}
_CONTAINER_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "cri-dockerd.sock")
_DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH"}
# Flags that on their own warrant "high" rather than "medium" for the table's severity.
HIGH_SEVERITY_FLAGS = {"privileged_container", "cluster_admin_binding", "docker_socket_mount", "anonymous_success"}


def looks_like_k8s_audit(content: str) -> bool:
    """True when the first non-empty line is an ``audit.k8s.io`` event."""
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        return stripped.startswith("{") and '"audit.k8s.io' in stripped[:4096]
    return False


def _timestamp(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    text = text[:-1] + "+00:00" if text.endswith("Z") else text
    import re

    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def _first_ip(values: Any) -> str:
    for candidate in values if isinstance(values, list) else []:
        try:
            return str(ipaddress.ip_address(str(candidate).strip().strip("[]")))
        except ValueError:
            continue
    return ""


def _pod_specs(resource: str, body: Any) -> list[dict]:
    """The pod spec(s) a workload request carries, whichever kind of workload it is."""
    if not isinstance(body, dict):
        return []
    spec = body.get("spec")
    if not isinstance(spec, dict):
        return []
    if resource == "pods":
        return [spec]
    template = spec.get("template")
    if resource == "cronjobs":
        job = spec.get("jobTemplate")
        template = ((job or {}).get("spec") or {}).get("template") if isinstance(job, dict) else None
    inner = template.get("spec") if isinstance(template, dict) else None
    return [inner] if isinstance(inner, dict) else []


def _workload_flags(spec: dict) -> set[str]:
    flags: set[str] = set()
    for key, flag in (("hostPID", "host_pid"), ("hostNetwork", "host_network"), ("hostIPC", "host_ipc")):
        if spec.get(key) is True:
            flags.add(flag)
    containers = [c for field in ("containers", "initContainers") for c in (spec.get(field) or []) if isinstance(c, dict)][:MAX_CONTAINERS]
    for container in containers:
        context = container.get("securityContext") if isinstance(container.get("securityContext"), dict) else {}
        if context.get("privileged") is True:
            flags.add("privileged_container")
        if context.get("allowPrivilegeEscalation") is True:
            flags.add("privilege_escalation_allowed")
        added = (context.get("capabilities") or {}).get("add") if isinstance(context.get("capabilities"), dict) else None
        if isinstance(added, list) and _DANGEROUS_CAPS & {str(cap).upper() for cap in added}:
            flags.add("dangerous_capability")
    for volume in (spec.get("volumes") or [])[:MAX_CONTAINERS]:
        host_path = volume.get("hostPath") if isinstance(volume, dict) else None
        if isinstance(host_path, dict):
            flags.add("host_path_mount")
            path = str(host_path.get("path") or "")
            if path == "/":
                flags.add("host_root_mount")
            if any(path.endswith(sock) for sock in _CONTAINER_SOCKETS):
                flags.add("docker_socket_mount")
    return flags


def _indicators(event: dict, *, verb: str, resource: str, subresource: str, username: str, groups: list[str], code: int | None) -> list[str]:
    flags: set[str] = set()
    if resource == "pods" and subresource in {"exec", "attach", "portforward"}:
        flags.add(f"pod_{subresource}")
    if resource == "secrets":
        if verb in _READ_VERBS:
            flags.add("secret_access")
        elif verb in _WRITE_VERBS:
            flags.add("secret_change")
    if resource in _RBAC_RESOURCES and verb in _WRITE_VERBS:
        flags.add("rbac_change")
        role_ref = (event.get("requestObject") or {}).get("roleRef") if isinstance(event.get("requestObject"), dict) else None
        if isinstance(role_ref, dict) and role_ref.get("name") == "cluster-admin":
            flags.add("cluster_admin_binding")
    if resource == "serviceaccounts" and subresource == "token" and verb == "create":
        flags.add("token_request")
    if username == "system:anonymous" or "system:unauthenticated" in groups:
        flags.add("anonymous_request")
        if code is not None and code < 400:
            flags.add("anonymous_success")
    if isinstance(event.get("impersonatedUser"), dict):
        flags.add("impersonation")
    if resource in _WORKLOAD_RESOURCES and verb in {"create", "update", "patch"}:
        for spec in _pod_specs(resource, event.get("requestObject")):
            flags |= _workload_flags(spec)
    return sorted(flags)


def _row_base(source_path: str, line_number: int, raw: str, message: str) -> dict[str, Any]:
    return {
        "artifact_family": ARTIFACT_FAMILY,
        "artifact_type": ARTIFACT_TYPE,
        "source_file": source_path,
        "line_number": line_number,
        "timestamp": None,
        "timestamp_status": "missing",
        "message": message[:2000],
        "raw_excerpt": raw[:2000],
    }


def parse_k8s_audit(content: str, *, source_path: str = "") -> list[dict]:
    rows: list[dict] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if len(stripped) > MAX_LINE_CHARS:
            rows.append(_row_base(source_path, line_number, stripped, f"[kairon] audit event of {len(stripped)} characters not parsed (limit {MAX_LINE_CHARS})"))
            continue
        try:
            event = json.loads(stripped)
        except ValueError:
            rows.append(_row_base(source_path, line_number, stripped, stripped))
            continue
        if not isinstance(event, dict) or not ("verb" in event or "requestURI" in event):
            rows.append(_row_base(source_path, line_number, stripped, stripped))
            continue

        reference = event.get("objectRef") if isinstance(event.get("objectRef"), dict) else {}
        user = event.get("user") if isinstance(event.get("user"), dict) else {}
        status = event.get("responseStatus") if isinstance(event.get("responseStatus"), dict) else {}
        annotations = event.get("annotations") if isinstance(event.get("annotations"), dict) else {}
        verb = str(event.get("verb") or "")
        resource = str(reference.get("resource") or "")
        subresource = str(reference.get("subresource") or "")
        username = str(user.get("username") or "")
        groups = [str(g) for g in (user.get("groups") or [])[:MAX_GROUPS]] if isinstance(user.get("groups"), list) else []
        code = status.get("code") if isinstance(status.get("code"), int) else None
        name = str(reference.get("name") or "")
        namespace = str(reference.get("namespace") or "")
        decision = str(annotations.get("authorization.k8s.io/decision") or "")
        stamp = _timestamp(event.get("requestReceivedTimestamp") or event.get("stageTimestamp"))
        target = "/".join(part for part in (resource, name) if part) + (f"/{subresource}" if subresource else "")
        indicators = _indicators(event, verb=verb, resource=resource, subresource=subresource, username=username, groups=groups, code=code)
        impersonated = event.get("impersonatedUser") if isinstance(event.get("impersonatedUser"), dict) else {}

        summary = f"{username or 'unknown'} {verb or '?'} {target or str(event.get('requestURI') or '')}"
        if namespace:
            summary += f" (namespace {namespace})"
        if code is not None:
            summary += f" -> {code}"
        if decision:
            summary += f" [{decision}]"

        row = _row_base(source_path, line_number, stripped, summary)
        row.update({
            "timestamp": stamp,
            "timestamp_status": "ok" if stamp else "missing",
            "username": username or None,
            "source_ip": _first_ip(event.get("sourceIPs")),
            "http_status": code,
            "http_user_agent": str(event.get("userAgent") or "")[:512],
            "url_path": str(event.get("requestURI") or "")[:2000],
            "k8s_verb": verb,
            "k8s_resource": resource,
            "k8s_subresource": subresource,
            "k8s_namespace": namespace,
            "k8s_object": name,
            "k8s_decision": decision,
            "k8s_groups": groups,
            "k8s_impersonated": str(impersonated.get("username") or ""),
            "k8s_audit_id": str(event.get("auditID") or ""),
            "k8s_stage": str(event.get("stage") or ""),
            "k8s_level": str(event.get("level") or ""),
            "suspicious_indicators": indicators,
        })
        rows.append(row)
    return rows
