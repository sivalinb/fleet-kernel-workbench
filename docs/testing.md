# Test cases and evidence boundaries

| Layer | Cases | What passing establishes |
| --- | --- | --- |
| Capture validation | Duplicate sequences, mixed TGIDs, invalid durations, impossible counts, extra fields | Malformed envelopes cannot enter analysis |
| Interpretation | Success, refusal, timeout, other errors and pending nonblocking returns | Outcomes have narrow Linux syscall semantics |
| Catalog composition | Current, absent and stale owners; provenance; dependent frontend | Real installed-package reconciliation and graph traversal work |
| Evidence loss | Missing observations with overlapping perf counters | Capture gaps remain separate from reported loss mechanisms |
| Instrumentation | Process IDs, addresses, paths and arbitrary labels rejected | The kernel label allowlist extends the upstream contract |
| Export | Allowlisted aggregate JSON, bounded imports | Reports omit raw host/process identity and source records |
| Package distribution | Immutable Git origins and installed metadata | Both original projects are consumed as packages |
| Workload | Real loopback successes and refused connections | Controlled socket behavior works independently of tracing |
| Native Collector | Outage buffering, WAL crash and memory crash | Real export faults and post-restart delivery agree with assertions |
| Linux eBPF | Probe load, exact scoped event counts, syscall outcomes, WAL recovery | Real kernel observations pass through both packages and the Collector |

The default portable suite excludes native and eBPF tests. Explicit native tests skip if the Collector is absent; that is not verification. Explicit live tests require `KERNEL_LIVE_TEST=1`; after opting in, missing prerequisites or failed attachment fail the test. There is no synthetic fallback.

The GitHub workflow runs portable Python tests, native Collector checks and a separate privileged Linux capture job. Live attachment depends on the runner kernel, BCC, matching headers and host tracing policy. A failure in that job must be investigated before claiming Linux verification.

The native sink checks exact log bodies as well as IDs. A new canary must arrive after recovery so that an intentionally empty memory-queue result cannot pass merely because the receiver is broken. Raw capture files and process output stay local; CI does not upload them as artifacts.

