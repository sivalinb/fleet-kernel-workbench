"""Bounded capture envelope. A connect syscall duration is not network RTT."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ConnectEvent(StrictModel):
    sequence: int = Field(ge=0, le=999)
    tgid: int = Field(ge=1, le=2**32 - 1)
    duration_ns: int = Field(ge=0, le=10**12)
    result: int = Field(ge=-4095, le=0)

    @property
    def outcome(self):
        if self.result == 0:
            return "connected"
        if self.result in {-115, -114}:  # Linux EINPROGRESS / EALREADY
            return "pending"
        if self.result == -111:
            return "refused"
        if self.result == -110:
            return "timeout"
        return "other-error"


class Capture(StrictModel):
    schema_version: Literal[1] = 1
    source: Literal["synthetic-replay", "linux-ebpf"]
    profile: Literal[
        "healthy", "connection-failures", "capture-loss", "unknown-owner", "stale-owner"
    ]
    scope: Literal["owned-loopback-child"] = "owned-loopback-child"
    target_tgid: int = Field(ge=1, le=2**32 - 1)
    attempted: int = Field(ge=1, le=1000)
    kernel_completed: int = Field(ge=0, le=1000)
    map_failures: int = Field(default=0, ge=0, le=1000)
    unmatched_exits: int = Field(default=0, ge=0, le=1000)
    perf_submit_failures: int = Field(default=0, ge=0, le=1000)
    perf_lost_notifications: int = Field(default=0, ge=0, le=10000)
    userspace_dropped: int = Field(default=0, ge=0, le=1000)
    events: list[ConnectEvent] = Field(max_length=1000)

    @model_validator(mode="after")
    def coherent(self):
        if len({e.sequence for e in self.events}) != len(self.events):
            raise ValueError("Duplicate sequence numbers")
        if any(e.tgid != self.target_tgid for e in self.events):
            raise ValueError("Capture contains an event outside its owned process scope")
        if not len(self.events) <= self.kernel_completed <= self.attempted:
            raise ValueError("Observed <= kernel completed <= workload attempted is required")
        if self.source == "linux-ebpf" and self.profile not in {"healthy", "connection-failures"}:
            raise ValueError("Live capture supports only owned healthy/refusal workloads")
        return self

    @property
    def gap(self):
        return self.attempted - len(self.events)


PROFILES = {
    "healthy": "Healthy connections",
    "connection-failures": "Connection refusals",
    "capture-loss": "Missing kernel evidence",
    "unknown-owner": "Missing service owner",
    "stale-owner": "Stale catalog ownership",
}


def replay(profile="connection-failures", count=12):
    if profile not in PROFILES or not isinstance(count, int) or not 4 <= count <= 40:
        raise ValueError("Choose a known profile and 4–40 connections")
    events = [
        ConnectEvent(
            sequence=i,
            tgid=4242,  # Invented process identity, never a host observation.
            duration_ns=40_000 + (i % 5) * 11_000,
            result=-111 if profile != "healthy" and i % 3 == 2 else 0,
        )
        for i in range(count)
    ]
    lost = count // 4 if profile == "capture-loss" else 0
    return Capture(
        source="synthetic-replay",
        profile=profile,
        target_tgid=4242,
        attempted=count,
        kernel_completed=count,
        perf_submit_failures=lost,
        events=events[: count - lost],
    )
