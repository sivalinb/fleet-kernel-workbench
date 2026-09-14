"""Bounded blocking TCP connects inside one owned child, using loopback only."""

import argparse
import json
import socket
import sys
import threading


def exercise(count, profile):
    if not 4 <= count <= 40 or profile not in {"healthy", "connection-failures"}:
        raise ValueError("Unsupported workload")
    with socket.socket() as listener, socket.socket() as reserved:
        listener.bind(("127.0.0.1", 0))
        listener.listen(64)
        listener.settimeout(0.2)
        reserved.bind(("127.0.0.1", 0))  # Bound, not listening: stable refusal target.
        stop = threading.Event()

        def accept():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                    connection.close()
                except TimeoutError:
                    pass

        worker = threading.Thread(target=accept)
        worker.start()
        outcomes = []
        try:
            for i in range(count):
                target = reserved if profile == "connection-failures" and i % 3 == 2 else listener
                with socket.socket() as client:
                    # Blocking loopback calls: return 0 or errno; no application request timing.
                    outcomes.append(client.connect_ex(target.getsockname()))
        finally:
            stop.set()
            worker.join(timeout=1)
        return {
            "attempted": len(outcomes),
            "successes": outcomes.count(0),
            "failures": sum(v != 0 for v in outcomes),
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=12)
    parser.add_argument(
        "--profile", choices=["healthy", "connection-failures"], default="connection-failures"
    )
    args = parser.parse_args()
    if sys.stdin.readline().strip() != "start":
        raise SystemExit("The collector must release the workload after attaching its probe")
    print(json.dumps(exercise(args.count, args.profile)))


if __name__ == "__main__":
    main()
