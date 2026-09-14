import asyncio
import os

import pytest

from fleet_kernel.delivery import run_delivery
from fleet_kernel.probe import capture_live, preflight
from fleet_kernel.service import Workbench


@pytest.mark.ebpf
@pytest.mark.parametrize("profile,failures", [("healthy", 0), ("connection-failures", 4)])
def test_linux_capture_to_packages_to_collector(tmp_path, profile, failures):
    if os.environ.get("KERNEL_LIVE_TEST") != "1":
        pytest.skip("Live Linux verification is opt-in; no eBPF claim is made by this test run")
    assert preflight()["ready"], preflight()
    capture = capture_live(12, profile)
    assert capture.source == "linux-ebpf"
    assert capture.kernel_completed == len(capture.events) == 12
    assert all(e.tgid == capture.target_tgid for e in capture.events)
    workbench = Workbench(tmp_path)
    try:
        result = workbench.investigate(capture=capture)
        assert result["analysis"]["capture_complete"]
        assert result["analysis"]["failures"] == failures
        delivery = asyncio.run(run_delivery(result["analysis"], "durable-crash"))
        assert delivery["state"] == "passed", delivery
        assert delivery["received"] == 12
    finally:
        workbench.close()
