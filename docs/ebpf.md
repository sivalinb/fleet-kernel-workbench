# eBPF concepts in this project

| Concept | Concrete implementation | Observation to examine |
| --- | --- | --- |
| Tracepoint | `syscalls:sys_enter_connect`, `syscalls:sys_exit_connect` | Stable named hooks versus kernel-function kprobes |
| Process and thread identity | TGID filter; full `pid_tgid` map key | Why a multithreaded process needs a thread-specific correlation key |
| Map | Bounded hash of entry timestamps | Null checks, correlation misses and cleanup at exit |
| Kernel clock | `bpf_ktime_get_ns` | Duration measured inside a syscall, not end-to-end request latency |
| Event transport | BCC perf output | Kernel submission errors and userspace loss notifications |
| Verifier | BCC loads the compiled probe | Supported helpers, bounded data structures and host policy constraints |
| Userspace integration | Python callback → validated capture | Kernel facts need explicit service metadata to gain operational context |

The probe is intentionally small enough to read in one file. It observes one child started after attachment and detaches on cleanup. This removes much of the deployment complexity while retaining actual Linux tracing semantics.

The owned workload uses blocking IPv4 TCP on loopback. A zero return means the connect syscall succeeded. `ECONNREFUSED` is a refusal; it does not establish why a production dependency would be unavailable. Imported `EINPROGRESS` and `EALREADY` returns are classified as pending, since this probe does not observe their later completion.

The project records neither socket addresses nor payload bytes. It does not claim RTT, TCP retransmission attribution, GPU kernel visibility, or service discovery from network traffic. Those require other hooks and identity models.

Official background: [BCC Python developer tutorial](https://github.com/iovisor/bcc/blob/master/docs/tutorial_bcc_python_developer.md), [BCC reference guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md), [BCC installation](https://github.com/iovisor/bcc/blob/master/INSTALL.md), [Linux tracepoint program type](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/).

