# Extension and scaling design

These are design directions, not implemented fleet capabilities.

| Extension | Why it matters | Evidence required before adoption |
| --- | --- | --- |
| cgroup/container identity | A TGID alone is insufficient across hosts, namespaces and process reuse | Container restarts, PID reuse and ambiguous bindings must resolve or abstain correctly |
| TCP state transitions | Nonblocking connect returns do not establish completion | Match socket lifetime and state transitions without attributing softirq work to an unrelated current PID |
| libbpf CO-RE loader | Reduce runtime compiler and header requirements | Kernel compatibility matrix, verifier failures and reproducible BPF object builds |
| Kernel aggregation | Per-event export becomes expensive at high connection rates | Compare event fidelity and overhead against in-kernel counters and histograms |
| Real catalog connectors | Replace the fictional binding with Kubernetes and infrastructure source records | Freshness, ownership conflicts and missing-resource behavior stay visible |
| Metrics and traces | Logs alone do not offer fleet SLOs or request context | Bounded resource and metric cardinality; valid context association without invented trace relationships |
| Collector load tests | Tiny local queues do not represent fleet ingest | Sustained rate, burst rate, queue saturation, retry exhaustion, disk pressure and restart behavior |

## A possible deployment shape

Run a scoped collector per Linux node, separate from an unprivileged API/UI. Partition events by node and cgroup identity into bounded batches. Keep kernel filtering and aggregation close to the source. Publish capture-loss counters through an independent path so a broken event stream does not erase its own failure signal.

Use a central catalog with versioned source snapshots, cache resolved bindings near collectors, and expire stale mappings. Store ownership as provenance-bearing metadata. Replace SQLite experiment storage with the upstream package's PostgreSQL support; add retention, pagination, indexes and explicit schema migrations before increasing write concurrency.

Configure per-node queue storage and rate limits. A sizing estimate is `queue bytes ≈ event rate × average serialized bytes × tolerated outage seconds`, plus measured storage overhead and headroom. This is a capacity estimate, not a guarantee: retries, enqueue limits, disk failure and pre-queue buffers create other loss boundaries.

The UI should read aggregated results through an authenticated service. Privileged capture should run under a narrowly scoped agent policy, with host-level access review, audited configuration and tenant separation. Do not grant a public Gradio process kernel tracing privileges.

Correctness work comes before fleet rollout: measure tracer overhead, validate cgroup lifetime handling, test backpressure and duplicates, and establish a supported kernel/BCC matrix. The current application is limited to one controlled client and 4–40 connections per run.

