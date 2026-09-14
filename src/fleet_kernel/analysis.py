"""Keep service symptoms, attribution confidence and evidence loss separate."""

from collections import Counter
from importlib.metadata import version

from fleetlab.contracts import validate_telemetry

from .events import Capture

METRIC_VALUES = {
    "outcome": {"connected", "pending", "refused", "timeout", "other-error"},
    "capture_source": {"synthetic-replay", "linux-ebpf"},
}


def kernel_contract(resource, labels):
    result = validate_telemetry(resource, labels)
    for key, value in labels.items():
        if key not in METRIC_VALUES or value not in METRIC_VALUES[key]:
            result["errors"].append(
                {
                    "code": "kernel_label_budget",
                    "field": key,
                    "message": "Kernel metrics allow only bounded outcome and capture_source labels",
                }
            )
    result["valid"] = not result["errors"]
    return result


def analyze(capture: Capture, inventory: dict):
    service = inventory["service"]
    stale = any(i["code"] == "stale_source" for i in service["issues"])
    owner = service.get("owner")
    attribution = "missing" if not owner else "stale" if stale else "current"
    resource = {
        "service.name": "kernel-client",
        "service.namespace": "kernel-workbench",
        "deployment.environment.name": "learning",
        "k8s.cluster.name": "learning",
        "team.owner": owner if attribution == "current" else "",
    }
    counts = Counter(e.outcome for e in capture.events)
    failed = sum(counts[o] for o in ("refused", "timeout", "other-error"))
    durations = sorted(e.duration_ns / 1000 for e in capture.events)
    losses = any(
        (
            capture.gap,
            capture.map_failures,
            capture.unmatched_exits,
            capture.perf_submit_failures,
            capture.perf_lost_notifications,
            capture.userspace_dropped,
        )
    )
    findings = []
    if failed:
        findings.append(
            f"{failed} of {len(capture.events)} observed connect syscalls returned an error."
        )
    elif capture.events:
        findings.append("No errors were observed in the captured connect syscalls.")
    else:
        findings.append("No connect events were captured; service health is unknown.")
    if losses:
        findings.append(
            "Capture is incomplete or reports loss. Delivery recovery cannot reconstruct uncaptured events."
        )
    if counts["pending"]:
        findings.append(
            "Pending nonblocking connects are not counted as failures; completion is unobserved."
        )
    if attribution != "current":
        findings.append(
            f"Ownership is {attribution}; the instrumentation contract blocks export until catalog metadata is current."
        )
    findings.append(
        "A refusal identifies a syscall outcome, not the root cause of a service incident."
    )
    contracts = [
        kernel_contract(resource, {"outcome": e.outcome, "capture_source": capture.source})
        for e in capture.events
    ]
    return {
        "source": capture.source,
        "attempted": capture.attempted,
        "kernel_completed": capture.kernel_completed,
        "observed": len(capture.events),
        "capture_gap": capture.gap,
        "capture_complete": not losses,
        "failures": failed,
        "pending": counts["pending"],
        "observed_error_rate": round(failed / len(capture.events), 4) if capture.events else None,
        "p95_syscall_us": round(durations[max(0, (95 * len(durations) + 99) // 100 - 1)], 2)
        if durations
        else None,
        "owner": owner,
        "attribution": attribution,
        "owner_provenance": service["provenance"].get("owner"),
        "resource": resource,
        "metric_contract_passed": bool(contracts) and all(c["valid"] for c in contracts),
        "metric_series": len({e.outcome for e in capture.events})
        if contracts and all(c["valid"] for c in contracts)
        else 0,
        "findings": findings,
        "outcomes": dict(counts),
        "packages": {
            name: version(name) for name in ("fleet-infrastructure-catalog", "fleet-telemetry-lab")
        },
        "events": [
            {
                "sequence": e.sequence,
                "outcome": e.outcome,
                "syscall_us": round(e.duration_ns / 1000, 2),
            }
            for e in capture.events
        ],
        "loss_counters": {
            name: getattr(capture, name)
            for name in (
                "map_failures",
                "unmatched_exits",
                "perf_submit_failures",
                "perf_lost_notifications",
                "userspace_dropped",
            )
        },
    }


def shareable_summary(analysis, delivery=None):
    """Allowlist: no raw process IDs, host identifiers, event IDs or wall-clock times."""
    keys = (
        "source",
        "attempted",
        "kernel_completed",
        "observed",
        "capture_gap",
        "capture_complete",
        "failures",
        "pending",
        "observed_error_rate",
        "p95_syscall_us",
        "attribution",
        "metric_contract_passed",
        "metric_series",
        "outcomes",
        "loss_counters",
        "packages",
    )
    result = {key: analysis[key] for key in keys}
    if delivery:
        result["delivery"] = {
            k: delivery[k]
            for k in ("mode", "state", "sent", "accepted", "received", "duplicates", "assertions")
            if k in delivery
        }
    return result
