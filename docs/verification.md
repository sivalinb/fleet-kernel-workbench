# Verification results

The [initial implementation workflow](https://github.com/sivalinb/fleet-kernel-workbench/actions/runs/34882135886) passed all four jobs: Python 3.11, Python 3.12, native Collector and Linux eBPF. The README badge reflects the current branch workflow state.

| Check | Result |
| --- | --- |
| Portable Python suite | 35 tests passed on each Python version |
| Native Collector suite | 3 tests passed: buffering, persistent crash recovery and memory queue loss |
| Live Linux eBPF suite | 2 tests passed: healthy and refusal workloads, followed by persistent Collector recovery |
| Python package build | Wheel built, dependency consistency check passed |
| Local Gradio integration | Session state, replay analysis, actual Collector delivery, missing-owner gate, capture import and aggregate download passed |

For each live Linux case, 12 scoped connect events were captured and 12 observations survived the persistent Collector crash. The refusal workload produced 4 errors; the healthy workload produced none. The test fails if the kernel probe cannot attach or if capture is replaced by replay.

The native loss-boundary suite starts with 12 invented connection attempts and 9 captured observations. Outage buffering and persistent crash recovery delivered all 9; the memory-queue crash delivered none of the original observations, while its new canary arrived. The upstream capture gap remained 3 in every case.

These results establish behavior for the tested bounded workloads and runner environment. They do not establish fleet-scale performance or compatibility with every Linux kernel. Only aggregate results are published; raw capture identities and local process output are excluded.

