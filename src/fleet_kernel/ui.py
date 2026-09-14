"""Unprivileged Gradio UI; Linux captures are imported as bounded data files."""

import html
import os
from importlib.resources import files

import gradio as gr
import plotly.graph_objects as go

from .analysis import shareable_summary
from .events import PROFILES
from .service import Workbench

ASSETS = files("fleet_kernel").joinpath("assets")


def overview(result):
    a = result["analysis"]
    origin = "SYNTHETIC REPLAY · Invented events; real catalog reconciliation"
    if a["source"] == "linux-ebpf":
        origin = "IMPORTED LINUX CAPTURE · File reports eBPF origin; inventory remains fictional"
    cards = [
        (
            "Captured / attempted",
            f"{a['observed']} / {a['attempted']}",
            "Owned workload scope",
            a["capture_gap"] > 0,
        ),
        ("Observed errors", str(a["failures"]), "Connect syscall outcomes", a["failures"] > 0),
        ("Capture gap", str(a["capture_gap"]), "Before Collector ingress", a["capture_gap"] > 0),
        (
            "Ownership",
            a["attribution"].title(),
            "Catalog source confidence",
            a["attribution"] != "current",
        ),
    ]
    cards_html = "".join(
        f'<div class="kernel-stat {"attention" if flag else ""}"><span>{title}</span><strong>{value}</strong><em>{sub}</em></div>'
        for title, value, sub, flag in cards
    )
    findings = "".join("<p>" + html.escape(text) + "</p>" for text in a["findings"])
    return f'<div class="kernel-origin">{origin}</div><div class="kernel-stats">{cards_html}</div><div class="kernel-verdict">{findings}</div>'


def event_plot(result):
    fig = go.Figure()
    colors = {
        "connected": "#238a71",
        "refused": "#cf7948",
        "pending": "#6488bc",
        "timeout": "#c64949",
        "other-error": "#9b6899",
    }
    for outcome, color in colors.items():
        events = [e for e in result["analysis"]["events"] if e["outcome"] == outcome]
        if events:
            fig.add_trace(
                go.Bar(
                    x=[e["sequence"] + 1 for e in events],
                    y=[e["syscall_us"] for e in events],
                    name=outcome,
                    marker_color=color,
                    hovertemplate="Connection %{x}<br>Syscall %{y} µs<extra>%{fullData.name}</extra>",
                )
            )
    fig.update_layout(
        height=320,
        paper_bgcolor="#f4f8f6",
        plot_bgcolor="#f4f8f6",
        font={"family": "system-ui", "color": "#2d5157"},
        margin={"l": 25, "r": 20, "t": 25, "b": 30},
        xaxis_title="Connection sequence",
        yaxis_title="Connect syscall duration (µs)",
        legend={"orientation": "h", "y": 1.13},
        bargap=0.3,
    )
    fig.update_yaxes(gridcolor="#e3ece7")
    return fig


def catalog_markdown(result):
    a = result["analysis"]
    provenance = a["owner_provenance"]
    source = provenance["source"] if provenance else "No ownership source"
    owners = a["owner"] or "Unassigned"
    exposure = result["inventory"]["exposure"]
    services = ", ".join(s["id"] for s in exposure["services"])
    return (
        f"**Recorded owner:** `{owners}` · **Confidence:** {a['attribution']}\n\n"
        f"**Provenance:** `{source}`\n\n"
        "**Process binding:** This tool's owned client → `service:kernel-client` → `node:lab-node`. "
        "All names and relationships belong to a fictional learning inventory.\n\n"
        f"**Dependency exposure:** {services}\n\n{exposure['interpretation']}"
    )


def delivery_markdown(result):
    d = result.get("delivery")
    if not d:
        return "No delivery experiment has run for this capture."
    checks = "\n".join(
        f"- {'Pass' if value else 'Fail'} · {key.replace('_', ' ')}"
        for key, value in d["assertions"].items()
    )
    return (
        f"**{d['state'].title()} · {d['mode']}**\n\n"
        f"{d['received']} / {d['accepted']} accepted observations reached the evidence sink. "
        f"Duplicate records: {d['duplicates']}.\n\n"
        f"The upstream capture gap remains **{result['analysis']['capture_gap']}**.\n\n{checks}"
    )


def build_app(workbench=None):
    workbench = workbench or Workbench()
    initial = workbench.investigate()
    with gr.Blocks(title="Fleet Kernel Workbench", analytics_enabled=False) as app:
        state = gr.State(initial)
        gr.HTML("""<div class="kernel-hero"><div class="kernel-eyebrow">Fleet Kernel Workbench / eBPF learning</div>
            <h1>From kernel signal<br>to service context.</h1>
            <p>Understand connection failures, find the recorded owner, and measure which observations survive a telemetry outage.</p>
            <div class="kernel-strip"><span>Python + Gradio</span><span>Catalog package</span><span>Telemetry reliability package</span><span>Linux eBPF / synthetic replay</span></div></div>""")
        with gr.Row():
            with gr.Column(scale=1, min_width=255):
                gr.Markdown("### Investigation inputs")
                profile = gr.Dropdown(
                    choices=[(v, k) for k, v in PROFILES.items()],
                    value="connection-failures",
                    label="Synthetic scenario",
                )
                count = gr.Slider(
                    minimum=4, maximum=40, step=1, value=12, label="Owned connection attempts"
                )
                analyze_button = gr.Button("Analyze replay", variant="primary")
                gr.Markdown(
                    "Replay uses invented observations. It exercises the same validation, catalog and delivery paths as an imported capture."
                )
                with gr.Accordion("Import a Linux capture", open=False):
                    capture_file = gr.File(
                        label="Capture JSON", type="filepath", file_types=[".json"]
                    )
                    load_button = gr.Button("Analyze capture")
                    gr.Markdown(
                        "Live capture runs through the privileged Linux CLI. This UI stays unprivileged and does not load kernel programs."
                    )
                export_file = gr.File(
                    value=workbench.export(initial), label="Aggregate findings", interactive=False
                )
            with gr.Column(scale=3, min_width=450):
                summary = gr.HTML(overview(initial))
                with gr.Tabs():
                    with gr.Tab("Connection evidence"):
                        chart = gr.Plot(event_plot(initial), show_label=False)
                        gr.Markdown(
                            "Duration covers the **connect syscall**, not request latency or network RTT. Nonblocking pending returns are not failures."
                        )
                        details = gr.JSON(
                            shareable_summary(initial["analysis"]),
                            label="Capture and contract evidence",
                            open=False,
                        )
                    with gr.Tab("Ownership & dependencies"):
                        catalog = gr.Markdown(catalog_markdown(initial))
                        catalog_json = gr.JSON(
                            initial["inventory"]["snapshot"],
                            label="Reconciled catalog and field provenance",
                            open=False,
                        )
                    with gr.Tab("Delivery reliability"):
                        gr.Markdown(
                            "These experiments send the selected observations through a real OpenTelemetry Collector and the telemetry package's fault relay. Each run uses owned processes and a separate queue directory."
                        )
                        mode = gr.Radio(
                            choices=[
                                ("Buffer through an outage", "buffer-recovery"),
                                ("Crash with a persistent queue", "durable-crash"),
                                ("Crash with a memory queue", "volatile-crash"),
                            ],
                            value="durable-crash",
                            label="Delivery experiment",
                        )
                        run_button = gr.Button("Run Collector experiment", variant="primary")
                        delivery = gr.Markdown(delivery_markdown(initial))
                        samples = gr.JSON({}, label="Measured Collector counters", open=False)
                    with gr.Tab("Architecture & learning"):
                        gr.HTML(
                            '<div class="kernel-architecture">'
                            + ASSETS.joinpath("architecture.svg").read_text()
                            + "</div>"
                        )
                        gr.Markdown("""**What this teaches**

- Tracepoint attachment, TGID filtering and per-thread map correlation.
- Kernel-to-Python event transport and explicit loss accounting.
- Service ownership from catalog provenance and dependency traversal.
- Bounded metric labels, OTLP logs, queues, retries and crash recovery.

**Scope:** one owned TCP client and fictional catalog metadata. It does not discover a real fleet, identify root causes automatically, or trace GPU kernels.

**Package composition:** `fleet_catalog.catalog` handles inventory; `fleetlab.contracts`, `fleetlab.isolation`, `fleetlab.relay`, `fleetlab.telemetry` and `fleetlab.runs` supply telemetry primitives.""")

        outputs = [
            state,
            summary,
            chart,
            details,
            catalog,
            catalog_json,
            export_file,
            delivery,
            samples,
        ]

        def render(result):
            return (
                result,
                overview(result),
                event_plot(result),
                shareable_summary(result["analysis"], result["delivery"]),
                catalog_markdown(result),
                result["inventory"]["snapshot"],
                workbench.export(result),
                delivery_markdown(result),
                result["delivery"]["samples"] if result["delivery"] else {},
            )

        def investigate(profile, count):
            return render(workbench.investigate(profile, int(count)))

        def load(path):
            if not path:
                raise gr.Error("Choose a capture JSON file first")
            try:
                return render(workbench.load_capture(path))
            except (ValueError, OSError) as error:
                raise gr.Error(str(error)) from error

        async def deliver(result, mode):
            try:
                return render(await workbench.deliver(result, mode))
            except (ValueError, RuntimeError) as error:
                raise gr.Error(str(error)) from error

        analyze_button.click(
            investigate,
            [profile, count],
            outputs,
            api_name="investigate",
            concurrency_id="workbench",
        )
        load_button.click(
            load, [capture_file], outputs, api_name="import_capture", concurrency_id="workbench"
        )
        run_button.click(
            deliver, [state, mode], outputs, api_name="delivery", concurrency_id="workbench"
        )
    return app


def launch():
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SystemExit(
            "Start the Gradio UI as an unprivileged user; use the capture CLI for eBPF"
        )
    build_app().queue(default_concurrency_limit=1).launch(
        server_name="127.0.0.1",
        server_port=int(os.environ.get("GRADIO_SERVER_PORT", "7862")),
        share=False,
        inbrowser=False,
        css=ASSETS.joinpath("workbench.css").read_text(),
        theme=gr.themes.Soft(primary_hue="teal", neutral_hue="slate"),
    )
