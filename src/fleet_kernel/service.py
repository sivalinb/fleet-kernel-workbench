"""Application composition; upstream package code is imported, never vendored."""

import json
from pathlib import Path
from uuid import uuid4

from fleetlab.models import make_database
from fleetlab.runs import save_run

from .analysis import analyze, shareable_summary
from .delivery import run_delivery
from .events import Capture, replay
from .inventory import catalog_context


class Workbench:
    def __init__(self, directory=".runtime"):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.engine, self.factory = make_database(
            "sqlite:///" + str(self.directory / "experiments.db")
        )

    def investigate(self, profile="connection-failures", count=12, capture=None, imported=False):
        capture = capture or replay(profile, int(count))
        run_id = uuid4().hex
        inventory = catalog_context(self.directory / "runs" / run_id, capture.profile)
        result = {
            "id": run_id,
            "name": capture.profile,
            "state": "analyzed",
            "analysis": analyze(capture, inventory),
            "inventory": inventory,
            "capture": capture.model_dump(),
            "imported": imported,
            "delivery": None,
        }
        save_run(self.factory, result)
        return result

    def load_capture(self, path):
        path = Path(path)
        if path.stat().st_size > 512_000:
            raise ValueError("Capture exceeds the 512 KB import limit")
        return self.investigate(
            capture=Capture.model_validate_json(path.read_bytes()), imported=True
        )

    async def deliver(self, result, mode):
        if not result:
            raise ValueError("Analyze a capture first")
        result = json.loads(json.dumps(result))
        result["delivery"] = await run_delivery(result["analysis"], mode)
        result["state"] = result["delivery"]["state"]
        save_run(self.factory, result)
        return result

    def export(self, result):
        directory = self.directory / "reports" / result["id"]
        directory.mkdir(parents=True, exist_ok=True)
        output = directory / "findings.json"
        output.write_text(
            json.dumps(shareable_summary(result["analysis"], result["delivery"]), indent=2) + "\n"
        )
        return str(output)

    def close(self):
        self.engine.dispose()
