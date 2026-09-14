import asyncio
import json
from importlib.metadata import distribution
from pathlib import Path

import pytest
from fleetlab.models import Experiment
from pydantic import ValidationError

from fleet_kernel.analysis import analyze, kernel_contract, shareable_summary
from fleet_kernel.events import Capture, ConnectEvent, replay
from fleet_kernel.inventory import catalog_context
from fleet_kernel.service import Workbench
from fleet_kernel.workload import exercise


@pytest.fixture
def workbench(tmp_path):
    value = Workbench(tmp_path)
    yield value
    value.close()


@pytest.mark.parametrize(
    "profile,expected",
    [
        ("healthy", (0, 12, "current")),
        ("connection-failures", (4, 12, "current")),
        ("capture-loss", (3, 9, "current")),
        ("unknown-owner", (4, 12, "missing")),
        ("stale-owner", (4, 12, "stale")),
    ],
)
def test_analysis_and_real_catalog_reconciliation(workbench, profile, expected):
    result = workbench.investigate(profile)
    a = result["analysis"]
    assert (a["failures"], a["observed"], a["attribution"]) == expected
    assert a["metric_contract_passed"] == (expected[2] == "current")
    assert a["capture_complete"] == (profile != "capture-loss")
    assert {s["id"] for s in result["inventory"]["exposure"]["services"]} == {
        "service:kernel-client",
        "service:frontend",
    }
    if expected[2] != "missing":
        assert a["owner_provenance"]["source"] == "learning-catalog"
    with workbench.factory() as db:
        saved = db.get(Experiment, result["id"])
        assert saved.results["analysis"] == a


@pytest.mark.parametrize(
    "result,outcome",
    [
        (0, "connected"),
        (-111, "refused"),
        (-110, "timeout"),
        (-115, "pending"),
        (-114, "pending"),
        (-13, "other-error"),
    ],
)
def test_linux_return_semantics(result, outcome):
    assert ConnectEvent(sequence=0, tgid=42, duration_ns=100, result=result).outcome == outcome


def test_pending_is_not_failure(tmp_path):
    capture = replay("healthy")
    capture.events[0] = capture.events[0].model_copy(update={"result": -115})
    a = analyze(capture, catalog_context(tmp_path, "healthy"))
    assert a["pending"] == 1 and a["failures"] == 0
    assert any("completion is unobserved" in text for text in a["findings"])


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data["events"].append(data["events"][0]),
        lambda data: data["events"][0].update(tgid=999),
        lambda data: data.update(kernel_completed=0),
        lambda data: data.update(source="made-up"),
        lambda data: data.update(extra_field="unrecognized"),
        lambda data: data["events"][0].update(duration_ns=-1),
    ],
)
def test_invalid_or_mixed_process_capture_is_rejected(mutation):
    data = replay().model_dump()
    mutation(data)
    with pytest.raises(ValidationError):
        Capture.model_validate(data)


def test_loss_counters_do_not_get_double_counted(tmp_path):
    data = replay("capture-loss")
    data.perf_lost_notifications = data.perf_submit_failures
    a = analyze(data, catalog_context(tmp_path, "capture-loss"))
    assert a["capture_gap"] == 3
    assert a["capture_complete"] is False
    assert a["loss_counters"]["perf_lost_notifications"] == 3


@pytest.mark.parametrize(
    "label", ["pid", "tgid", "ip", "comm", "event.id", "request_id", "path", "unexpected"]
)
def test_kernel_label_budget_blocks_unbounded_identity(workbench, label):
    resource = workbench.investigate()["analysis"]["resource"]
    result = kernel_contract(resource, {label: "anything"})
    assert not result["valid"]


def test_unknown_outcome_label_is_rejected(workbench):
    resource = workbench.investigate()["analysis"]["resource"]
    assert not kernel_contract(resource, {"outcome": "arbitrary-string"})["valid"]


def test_missing_owner_blocks_export(workbench):
    result = workbench.investigate("unknown-owner")
    with pytest.raises(ValueError, match="ownership"):
        asyncio.run(workbench.deliver(result, "durable-crash"))


def test_summary_uses_allowlist(workbench):
    a = workbench.investigate()["analysis"]
    a.update(hostname="PRIVATE_HOST", pid=9876, credential="PRIVATE_SECRET")
    a["resource"]["process.command_line"] = "PRIVATE_COMMAND"
    text = json.dumps(shareable_summary(a))
    assert "PRIVATE" not in text
    assert "events" not in json.loads(text)
    assert "owner_provenance" not in text


def test_import_and_export(workbench, tmp_path):
    source = tmp_path / "capture.json"
    source.write_text(replay("capture-loss").model_dump_json())
    result = workbench.load_capture(source)
    assert result["imported"]
    output = json.loads(Path(workbench.export(result)).read_text())
    assert output["capture_gap"] == 3
    source.write_text("x" * 512_001)
    with pytest.raises(ValueError, match="512 KB"):
        workbench.load_capture(source)


@pytest.mark.parametrize("profile,successes", [("healthy", 12), ("connection-failures", 8)])
def test_real_loopback_workload(profile, successes):
    assert exercise(12, profile) == {
        "attempted": 12,
        "successes": successes,
        "failures": 12 - successes,
    }


@pytest.mark.parametrize(
    "package,commit",
    [
        ("fleet-infrastructure-catalog", "a8ebf82eba5d2df0a327fabc9d3439993785102d"),
        ("fleet-telemetry-lab", "0934e4c37e51d7305db41afa90a4069b24aecefc"),
    ],
)
def test_packages_are_installed_from_immutable_commits(package, commit):
    metadata = distribution(package)
    direct = json.loads(metadata.read_text("direct_url.json"))
    assert direct["vcs_info"]["commit_id"] == commit
    assert "site-packages" in str(metadata.locate_file(""))
