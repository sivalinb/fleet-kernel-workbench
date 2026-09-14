"""Put the selected kernel observations through a real, isolated Collector.

The installed reliability package supplies configuration, the fault relay and
metric parsing. This module adds kernel log payloads and a verifying local sink.
"""

import asyncio
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from uuid import uuid4

import httpx
import yaml
from fleetlab.isolation import allocate_ports, isolated_config
from fleetlab.telemetry import parse_collector_metrics

MODES = {"buffer-recovery", "durable-crash", "volatile-crash"}


class EvidenceSink:
    def __init__(self):
        self.records = {}
        self.occurrences = 0
        self.lock = threading.Lock()
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.path != "/otlp/v1/logs":
                    self.send_error(404)
                    return
                size = int(self.headers.get("Content-Length", 0))
                if not 0 < size <= 1_000_000:
                    self.send_error(413)
                    return
                try:
                    payload = json.loads(self.rfile.read(size))
                    records = []
                    for resource in payload["resourceLogs"]:
                        for scope in resource["scopeLogs"]:
                            for log in scope["logRecords"]:
                                attrs = {
                                    a["key"]: a["value"].get("stringValue")
                                    for a in log["attributes"]
                                }
                                records.append((attrs["event.id"], log["body"]["stringValue"]))
                    with sink.lock:
                        for event_id, body in records:
                            sink.records[event_id] = body
                            sink.occurrences += 1
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b"{}")
                except (KeyError, TypeError, ValueError):
                    self.send_error(400)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return "http://127.0.0.1:" + str(self.server.server_port)

    def snapshot(self):
        with self.lock:
            return dict(self.records), self.occurrences

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def log_payload(resource, event_id, body):
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": k, "value": {"stringValue": v}} for k, v in resource.items()
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "fleet-kernel-workbench"},
                        "logRecords": [
                            {
                                "timeUnixNano": str(time.time_ns()),
                                "severityNumber": 9,
                                "body": {"stringValue": body},
                                "attributes": [
                                    {"key": "event.id", "value": {"stringValue": event_id}}
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


def collector_path():
    return Path(os.environ.get("KERNEL_COLLECTOR_BINARY", ".runtime/bin/collector")).resolve()


async def run_delivery(analysis, mode="durable-crash", binary=None):
    if mode not in MODES:
        raise ValueError("Unknown delivery experiment")
    if not analysis["metric_contract_passed"]:
        raise ValueError(
            "Current catalog ownership is required before exporting these observations"
        )
    if not 4 <= len(analysis["events"]) <= 40:
        raise ValueError("Delivery experiments accept 4–40 captured observations")
    binary = Path(binary or collector_path()).resolve()
    if not binary.is_file():
        raise RuntimeError("Collector missing. Install it with python scripts/install_collector.py")
    result = {
        "mode": mode,
        "state": "running",
        "sent": len(analysis["events"]),
        "accepted": 0,
        "received": 0,
        "duplicates": 0,
        "assertions": {},
        "samples": [],
    }
    run = uuid4().hex
    bodies = {
        f"{run}:{e['sequence']}": json.dumps(
            {**e, "capture_source": analysis["source"]}, sort_keys=True
        )
        for e in analysis["events"]
    }
    canary = run + ":canary"
    processes = []
    sink = EvidenceSink()
    token = secrets.token_hex(24)
    env = {**os.environ, "LOKI_URL": sink.url, "LAB_API_TOKEN": token}
    # Do not inherit checkout path overrides into installed-package subprocesses.
    env.pop("PYTHONPATH", None)
    try:
        with tempfile.TemporaryDirectory(prefix="kernel-delivery-") as tmp:
            directory = Path(tmp)
            (directory / "wal").mkdir()
            ports = allocate_ports(4)
            receiver, health, metrics, relay_port = ports
            config = isolated_config(directory, ports, mode, len(bodies))
            config["service"]["pipelines"].pop("traces")
            config["exporters"].pop("otlphttp/traces")
            config["exporters"]["otlphttp/logs"].update(encoding="json", compression="none")
            config_file = directory / "collector.yaml"
            config_file.write_text(yaml.safe_dump(config))
            with (directory / "process.log").open("w+") as log:

                def launch(command):
                    process = subprocess.Popen(command, stdout=log, stderr=log, env=env)
                    processes.append(process)
                    return process

                async with httpx.AsyncClient(timeout=3, trust_env=False) as client:

                    async def ready(url, process):
                        for _ in range(100):
                            if process.poll() is not None:
                                raise RuntimeError(
                                    "An owned telemetry process exited before readiness"
                                )
                            try:
                                if (await client.get(url)).is_success:
                                    return
                            except httpx.HTTPError:
                                pass
                            await asyncio.sleep(0.1)
                        raise RuntimeError("An owned telemetry process did not become ready")

                    async def sample(phase):
                        response = await client.get(f"http://127.0.0.1:{metrics}/metrics")
                        response.raise_for_status()
                        counters = parse_collector_metrics(response.text)
                        if counters is None:
                            raise RuntimeError("Collector counters are unavailable")
                        result["samples"].append({"phase": phase, **counters})
                        return counters

                    async def send(event_id, body):
                        response = await client.post(
                            f"http://127.0.0.1:{receiver}/v1/logs",
                            json=log_payload(analysis["resource"], event_id, body),
                        )
                        if not response.is_success:
                            return False
                        partial = (
                            response.json().get("partialSuccess", {}) if response.content else {}
                        )
                        return int(partial.get("rejectedLogRecords", 0)) == 0

                    relay = f"http://127.0.0.1:{relay_port}"
                    relay_process = launch(
                        [
                            sys.executable,
                            "-m",
                            "uvicorn",
                            "fleetlab.relay:app",
                            "--host",
                            "127.0.0.1",
                            "--port",
                            str(relay_port),
                            "--no-access-log",
                        ]
                    )
                    command = [str(binary), "--config=" + str(config_file)]
                    collector = launch(command)
                    await ready(relay + "/health", relay_process)
                    await ready(f"http://127.0.0.1:{health}/", collector)
                    headers = {"authorization": "Bearer " + token}
                    (
                        await client.post(relay + "/control", json={"seconds": 45}, headers=headers)
                    ).raise_for_status()
                    for event_id, body in bodies.items():
                        result["accepted"] += int(await send(event_id, body))
                    for _ in range(30):
                        before = await sample("Export blocked")
                        relay_state = (await client.get(relay + "/health")).json()
                        if before["queued_batches"] > 0 and relay_state["rejected"] > 0:
                            break
                        await asyncio.sleep(0.1)
                    if before["queued_batches"] <= 0 or relay_state["rejected"] == 0:
                        raise RuntimeError(
                            "No rejected export and backlog were observed; loss comparison is invalid"
                        )
                    if mode in {"durable-crash", "volatile-crash"}:
                        collector.kill()
                        await asyncio.to_thread(collector.wait, 3)
                        collector = launch(command)
                        await ready(f"http://127.0.0.1:{health}/", collector)
                    (
                        await client.post(relay + "/control", json={"seconds": 0}, headers=headers)
                    ).raise_for_status()
                    canary_accepted = await send(canary, "recovery-canary")
                    for _ in range(100):
                        after = await sample("Recovery")
                        records, total = sink.snapshot()
                        found = set(records) & set(bodies)
                        expected_count = 0 if mode == "volatile-crash" else len(bodies)
                        if (
                            canary in records
                            and after["queued_batches"] == 0
                            and len(found) == expected_count
                        ):
                            # Queue empty + delivered canary separates expected loss from failed recovery.
                            break
                        await asyncio.sleep(0.1)
                    result.update(received=len(found), duplicates=max(0, total - len(records)))
                    result["assertions"] = {
                        "all_ingress_accepted": result["accepted"] == len(bodies),
                        "export_fault_observed": relay_state["rejected"] > 0,
                        "backlog_observed": before["queued_batches"] > 0,
                        "recovery_canary_arrived": canary_accepted
                        and records.get(canary) == "recovery-canary",
                        "queue_drained": after["queued_batches"] == 0,
                        "expected_delivery_boundary": len(found) == expected_count,
                        "delivered_bodies_preserved": all(records[e] == bodies[e] for e in found),
                    }
                    result["state"] = "passed" if all(result["assertions"].values()) else "failed"
                    return result
    finally:
        # Only owned process handles are touched; cleanup also runs on cancellation.
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    await asyncio.to_thread(process.wait, 3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    await asyncio.to_thread(process.wait, 3)
        await asyncio.to_thread(sink.close)
