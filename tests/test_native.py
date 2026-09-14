import asyncio

import pytest

from fleet_kernel.delivery import collector_path, run_delivery
from fleet_kernel.service import Workbench


@pytest.mark.native
@pytest.mark.parametrize(
    "mode,received", [("buffer-recovery", 9), ("durable-crash", 9), ("volatile-crash", 0)]
)
def test_real_collector_keeps_capture_and_delivery_loss_separate(tmp_path, mode, received):
    if not collector_path().is_file():
        pytest.skip("Collector is not installed; native verification was not performed")
    workbench = Workbench(tmp_path)
    try:
        result = workbench.investigate("capture-loss")
        delivered = asyncio.run(run_delivery(result["analysis"], mode))
        assert delivered["state"] == "passed", delivered
        assert delivered["sent"] == delivered["accepted"] == 9
        assert delivered["received"] == received
        assert all(delivered["assertions"].values())
        assert result["analysis"]["capture_gap"] == 3
    finally:
        workbench.close()
