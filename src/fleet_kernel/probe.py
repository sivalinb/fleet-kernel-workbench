"""Linux BCC capture; Python controls a small embedded BPF C tracepoint program."""

import importlib.util
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

from .events import Capture, ConnectEvent

# Tracepoints avoid architecture-specific syscall argument registers.
# TGID filtering happens before any map update or event submission.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
struct event_t { u64 duration_ns; u32 tgid; s32 result; };
BPF_HASH(starts, u64, u64, 256);
BPF_ARRAY(stats, u64, 4);
BPF_PERF_OUTPUT(events);
static inline void count(u32 index) {
    u64 *value = stats.lookup(&index);
    if (value) __sync_fetch_and_add(value, 1);
}
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u64 identity = bpf_get_current_pid_tgid();
    if ((identity >> 32) != TARGET_TGID) return 0;
    u64 now = bpf_ktime_get_ns();
    if (starts.update(&identity, &now) < 0) count(1);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    u64 identity = bpf_get_current_pid_tgid();
    if ((identity >> 32) != TARGET_TGID) return 0;
    count(0);
    u64 *start = starts.lookup(&identity);
    if (!start) { count(2); return 0; }
    struct event_t event = {};
    event.duration_ns = bpf_ktime_get_ns() - *start;
    event.tgid = identity >> 32;
    event.result = args->ret;
    starts.delete(&identity);
    if (events.perf_submit(args, &event, sizeof(event)) < 0) count(3);
    return 0;
}
"""


def preflight():
    linux = platform.system() == "Linux"
    bcc = importlib.util.find_spec("bcc") is not None
    paths = [
        Path("/sys/kernel/tracing/events/syscalls"),
        Path("/sys/kernel/debug/tracing/events/syscalls"),
    ]
    tracepoints = linux and any(
        all((p / s / "format").is_file() for s in ("sys_enter_connect", "sys_exit_connect"))
        for p in paths
    )
    privileged = linux and os.geteuid() == 0
    return {
        "linux": linux,
        "bcc_python": bcc,
        "connect_tracepoints": tracepoints,
        "privileged_process": privileged,
        "ready": linux and bcc and tracepoints and privileged,
        "note": "Preflight is advisory; the Linux verifier and host policy decide whether loading succeeds.",
    }


def capture_live(count=12, profile="connection-failures"):
    if (
        not isinstance(count, int)
        or not 4 <= count <= 40
        or profile not in {"healthy", "connection-failures"}
    ):
        raise ValueError("Live capture accepts 4–40 owned healthy/refusal connections")
    if not preflight()["ready"]:
        raise RuntimeError(
            "Live capture requires Linux, BCC, connect tracepoints and a privileged CLI process; run fleet-kernel doctor"
        )
    from bcc import BPF

    child = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "fleet_kernel.workload",
            "--count",
            str(count),
            "--profile",
            profile,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    probe = None
    events, losses = [], {"perf_lost_notifications": 0, "userspace_dropped": 0}
    try:
        probe = BPF(text=BPF_PROGRAM.replace("TARGET_TGID", str(child.pid)))

        def receive(cpu, data, size):
            event = probe["events"].event(data)
            if len(events) >= 1000:
                losses["userspace_dropped"] += 1
                return
            events.append(
                ConnectEvent(
                    sequence=len(events),
                    tgid=int(event.tgid),
                    duration_ns=int(event.duration_ns),
                    result=int(event.result),
                )
            )

        def lost(cpu, count):
            losses["perf_lost_notifications"] += count

        probe["events"].open_perf_buffer(receive, page_cnt=64, lost_cb=lost)
        child.stdin.write("start\n")
        child.stdin.flush()
        deadline = time.monotonic() + 15
        while child.poll() is None:
            if time.monotonic() > deadline:
                raise RuntimeError("Owned workload exceeded its capture bound")
            probe.perf_buffer_poll(timeout=100)
        for _ in range(5):
            probe.perf_buffer_poll(timeout=100)
        output = json.loads(child.stdout.read())
        if child.returncode != 0 or output["attempted"] != count:
            raise RuntimeError("Owned workload did not complete")
        stats = [int(probe["stats"][probe["stats"].Key(i)].value) for i in range(4)]
        return Capture(
            source="linux-ebpf",
            profile=profile,
            target_tgid=child.pid,
            attempted=output["attempted"],
            kernel_completed=stats[0],
            map_failures=stats[1],
            unmatched_exits=stats[2],
            perf_submit_failures=stats[3],
            events=events,
            **losses,
        )
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()
        if probe is not None:
            probe.cleanup()
