import argparse
import asyncio
import json
from pathlib import Path

from .analysis import shareable_summary
from .delivery import MODES
from .events import PROFILES
from .probe import capture_live, preflight
from .service import Workbench


def main():
    parser = argparse.ArgumentParser(
        description="Kernel observations, catalog context and delivery evidence"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="Check Linux capture prerequisites without loading a probe")
    sub.add_parser("ui", help="Start the unprivileged Gradio interface")
    capture = sub.add_parser(
        "capture", help="Trace only a newly spawned loopback workload on Linux"
    )
    capture.add_argument("--count", type=int, default=12)
    capture.add_argument(
        "--profile", choices=["healthy", "connection-failures"], default="connection-failures"
    )
    capture.add_argument("--output", type=Path, default=Path(".runtime/owned-capture.json"))
    replay = sub.add_parser(
        "replay", help="Analyze invented events through the real package integrations"
    )
    replay.add_argument("--profile", choices=list(PROFILES), default="connection-failures")
    replay.add_argument("--count", type=int, default=12)
    replay.add_argument("--delivery", choices=sorted(MODES))
    args = parser.parse_args()
    if args.command == "doctor":
        print(json.dumps(preflight(), indent=2))
    elif args.command == "ui":
        from .ui import launch

        launch()
    elif args.command == "capture":
        data = capture_live(args.count, args.profile)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(data.model_dump_json(indent=2) + "\n")
        args.output.chmod(0o600)
        print(
            json.dumps(
                {
                    "source": data.source,
                    "attempted": data.attempted,
                    "observed": len(data.events),
                    "capture_gap": data.gap,
                }
            )
        )
    else:
        workbench = Workbench()
        try:
            result = workbench.investigate(args.profile, args.count)
            if args.delivery:
                result = asyncio.run(workbench.deliver(result, args.delivery))
            print(json.dumps(shareable_summary(result["analysis"], result["delivery"]), indent=2))
            if result["delivery"] and result["delivery"]["state"] != "passed":
                raise SystemExit(1)
        finally:
            workbench.close()


if __name__ == "__main__":
    main()
