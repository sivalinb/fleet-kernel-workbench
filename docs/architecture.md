# Architecture and package boundaries

![System architecture](../src/fleet_kernel/assets/architecture.svg)

## Capture → context → delivery

The Linux controller creates a blocked Python child, loads a probe filtered to that child's TGID, opens the perf buffer, then releases the child. The child creates listening and reserved-but-not-listening loopback sockets. Its blocking connects produce successes and controlled refusals. No packets or application payloads are captured.

Two syscall tracepoints correlate entry and exit using a per-thread `pid_tgid` key. The kernel reports duration and return value. A bounded capture envelope validates sequence uniqueness, process scope, counts and Linux return codes. Map failures, unmatched exits, perf submission failures, perf loss notifications and userspace drops remain separate counters. They can overlap and are not summed as independent lost events.

Synthetic replay enters at the same envelope boundary. It never loads a kernel probe. Its measurements are invented and labeled; downstream reconciliation and Collector experiments are still real operations.

The catalog adapter creates a separate SQLite inventory for each investigation and ingests an explicit fictional service binding. It delegates reconciliation, source freshness, field provenance and reverse dependency traversal to the installed catalog package. Missing or stale ownership blocks export rather than silently assigning a current owner. Identity is established by the controller's owned child scope, not by guessing from a process name or IP address.

The workbench imports the telemetry package's required resource contract and adds an allowlist for kernel metric dimensions. Only the enumerated `outcome` and `capture_source` labels are accepted. The displayed series count is a calculated label budget for this bounded resource, not a measured Prometheus series count. Observations are exported as OTLP logs; this version does not export kernel metrics.

## Real delivery experiments

The selected observations become individual OTLP log records. Event bodies carry sequence, syscall duration, outcome and capture origin. Event IDs are attributes on logs and are never metric dimensions.

The telemetry package generates the isolated Collector configuration. Its fault relay returns real HTTP 503s until the workbench restores access. A local Python sink validates event IDs and exact serialized bodies after the Collector forwards them. The workbench requires accepted ingress, measured backlog, rejected exports, a delivered recovery canary and the expected delivery count before passing an experiment.

| Experiment | Action | Required result |
| --- | --- | --- |
| Buffer recovery | Block export, then restore it | All accepted observations arrive |
| Durable crash | Block export, SIGKILL owned Collector, restart with same WAL | All accepted observations arrive |
| Volatile crash | Same failure with an in-memory queue | Originals remain absent; a new canary arrives |

Delivery counts start at Collector ingress. Capture counts start at the owned workload. For example, a synthetic capture with 12 attempted and 9 observed connections can recover all 9 logs from a WAL and still have a capture gap of 3.

Subprocess cleanup executes in `finally`, including cancellation and readiness failures. The workbench uses process handles it created, not PID discovery or broad process termination. Native queue configuration is pinned through the upstream package and tested with Collector 0.160.0.

## State and distribution

The third project has its own `fleet_kernel` namespace and local runtime directory. Per-investigation catalog databases belong to the catalog package. Durable investigation records use the telemetry package's `Experiment` model in a separate database. Neither original repository needs to run.

Gradio maintains the selected result as session state; actions are serialized through one concurrency group. Runtime retention is manual in this learning version. The UI binds only to loopback and refuses to launch as root. A production multiuser deployment needs authentication, authorization and bounded retention before exposing it beyond the local host.

The two Git dependencies are pinned to full commit IDs. Compatibility tests verify their installed distribution metadata. Updating a pin is an explicit package upgrade that must pass the composition and native suites.

