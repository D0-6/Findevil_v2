"""
dashboard.py — Find Evil Hackathon
Live terminal dashboard showing agent execution in real time.
Run alongside agent_loop.py — reads its JSON output and renders live.

Usage (two terminals):
  Terminal 1: python agent_loop.py --image /cases/win10.E01 --output /tmp/findings.json
  Terminal 2: python dashboard.py --watch /tmp/findings.json

Uses only stdlib + rich (already in requirements.txt).
"""

import json
import time
import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    from rich import box
    from rich.columns import Columns
    from rich.align import Align
except ImportError:
    print("Install rich: pip install rich --break-system-packages")
    sys.exit(1)

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "green",
    "confirmed":"bold green",
    "inferred": "yellow",
    "speculative":"dim",
}

PHASE_COLORS = {
    "triage":      "cyan",
    "deep_dive":   "blue",
    "correlation": "magenta",
    "report":      "green",
}

KILL_CHAIN_ICONS = {
    "initial_access":       "🎯",
    "execution":            "⚡",
    "persistence":          "🔒",
    "credential_access":    "🔑",
    "defense_evasion":      "👻",
    "command_and_control":  "📡",
    "lateral_movement":     "↔️",
    "exfiltration":         "📤",
    "impact":               "💥",
    "unknown":              "❓",
}


def load_state(path: str) -> dict:
    """Load agent output JSON, return empty dict if not ready."""
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_tool_log(path: str) -> list:
    """Load tool call log from agent output."""
    state = load_state(path)
    return state.get("tool_call_log", [])


def render_header(state: dict, watch_path: str) -> Panel:
    """Top header bar."""
    phase = state.get("phase", "waiting...")
    iteration = state.get("iterations_used", state.get("iteration", 0))
    corrections = state.get("self_corrections", 0)
    tool_calls = state.get("tool_call_count", 0)
    stop_reason = state.get("stop_reason", "")
    model = os.environ.get("NIM_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")

    phase_color = PHASE_COLORS.get(phase, "white")
    status = f"[bold green]✓ COMPLETE[/]" if stop_reason else f"[{phase_color}]● {phase.upper()}[/]"

    image = state.get("image_path", watch_path)
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    content = (
        f"[bold white]FIND EVIL — SIFT MCP BENCHMARK AGENT[/]  "
        f"[dim]|[/]  {status}  "
        f"[dim]|[/]  [cyan]Iter {iteration}/25[/]  "
        f"[dim]|[/]  [yellow]Tools called: {tool_calls}[/]  "
        f"[dim]|[/]  [red]Self-corrections: {corrections}[/]  "
        f"[dim]|[/]  [dim]{ts}[/]\n"
        f"[dim]Image: {Path(image).name}  |  Model: {model}[/]"
    )
    return Panel(content, style="bold", border_style="bright_blue", padding=(0, 1))


def render_findings_table(state: dict) -> Table:
    """Table of confirmed findings with corroboration scores."""
    confirmed = state.get("confirmed_findings", [])

    table = Table(
        title=f"[bold green]Confirmed Findings ({len(confirmed)})[/]",
        box=box.ROUNDED,
        border_style="green",
        header_style="bold green",
        show_lines=True,
        expand=True,
    )
    table.add_column("#",       width=3,  style="dim")
    table.add_column("Type",    width=14, style="cyan")
    table.add_column("Value",   width=35)
    table.add_column("Tool",    width=20, style="blue")
    table.add_column("Score",   width=8,  justify="center")
    table.add_column("Label",   width=12, justify="center")
    table.add_column("Kill Chain", width=22)

    for i, f in enumerate(confirmed[-20:], 1):  # show latest 20
        val   = str(f.get("value",""))[:33]
        typ   = str(f.get("ioc_type",""))[:12]
        tool  = str(f.get("tool_call",""))[:18]
        desc  = str(f.get("description",""))

        corr  = f.get("corroboration", {})
        score = corr.get("score", 0.0)
        label = corr.get("label", f.get("confidence","inferred").upper())
        kc    = f.get("kill_chain_stage", "")

        score_color = "green" if score >= 0.6 else "yellow" if score >= 0.3 else "red"
        label_color = SEVERITY_COLORS.get(label.lower(), "white")
        kc_icon = KILL_CHAIN_ICONS.get(kc, "")
        kc_display = f"{kc_icon} {kc.replace('_',' ')}" if kc else ""

        table.add_row(
            str(i),
            typ,
            f"[white]{val}[/]",
            tool,
            f"[{score_color}]{score:.2f}[/]",
            f"[{label_color}]{label}[/]",
            f"[dim]{kc_display}[/]",
        )

    if not confirmed:
        table.add_row("—","—","[dim]Waiting for agent...[/]","—","—","—","—")

    return table


def render_rejected_table(state: dict) -> Table:
    """Table of rejected/hallucinated findings."""
    rejected = state.get("rejected_findings", [])

    table = Table(
        title=f"[bold red]Hallucinations Caught ({len(rejected)})[/]",
        box=box.SIMPLE,
        border_style="red",
        header_style="bold red",
        expand=True,
    )
    table.add_column("Value",  width=30)
    table.add_column("Reason", width=50)

    for f in rejected[-8:]:
        val    = str(f.get("value",""))[:28]
        reason = str(f.get("rejection_reason","no tool call backing"))[:48]
        table.add_row(f"[red]{val}[/]", f"[dim]{reason}[/]")

    if not rejected:
        table.add_row("[green]None caught yet[/]","")

    return table


def render_tool_log(tool_log: list) -> Table:
    """Recent tool calls audit trail."""
    table = Table(
        title="[bold blue]Tool Call Log (last 10)[/]",
        box=box.SIMPLE,
        border_style="blue",
        header_style="bold blue",
        expand=True,
    )
    table.add_column("Iter", width=4,  style="dim")
    table.add_column("Phase",width=10, style="cyan")
    table.add_column("Tool", width=24, style="blue")
    table.add_column("Findings", width=8, justify="right")
    table.add_column("ms",  width=6,  justify="right", style="dim")
    table.add_column("↩",   width=3,  justify="center")

    for record in tool_log[-10:]:
        corr = "🔄" if record.get("triggered_correction") else ""
        table.add_row(
            str(record.get("iteration","")),
            str(record.get("phase",""))[:8],
            str(record.get("tool_name",""))[:22],
            str(record.get("findings_produced",0)),
            str(record.get("duration_ms",0)),
            corr,
        )

    if not tool_log:
        table.add_row("—","—","[dim]Waiting...[/]","—","—","")

    return table


def render_iter_diffs(state: dict) -> Table:
    """Iteration diff table — shows agent learning."""
    diffs = state.get("iteration_diffs", [])

    table = Table(
        title="[bold magenta]Agent Learning Trace[/]",
        box=box.SIMPLE,
        border_style="magenta",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("→",     width=4,  justify="right")
    table.add_column("Phase", width=18, style="cyan")
    table.add_column("Δ IOCs",width=6,  justify="center")
    table.add_column("Summary", width=50)

    for d in diffs[-8:]:
        delta = d.get("net_delta", 0)
        delta_str = f"[green]+{delta}[/]" if delta > 0 else f"[red]{delta}[/]" if delta < 0 else "[dim]0[/]"
        corr = d.get("self_corrections", 0)
        corr_str = f" [red][↩x{corr}][/]" if corr else ""
        phase = d.get("phase_change") or "—"
        summary = str(d.get("summary",""))[:48]

        table.add_row(
            str(d.get("to_iter","")),
            f"[cyan]{phase}[/]",
            delta_str,
            f"{summary}{corr_str}",
        )

    if not diffs:
        table.add_row("—","—","—","[dim]Analysis not started[/]")

    return table


def render_stats(state: dict) -> Panel:
    """Summary stats panel."""
    confirmed   = len(state.get("confirmed_findings", []))
    rejected    = len(state.get("rejected_findings", []))
    pending     = len(state.get("pending_review", []))
    corrections = state.get("self_corrections", 0)
    tool_calls  = state.get("tool_call_count", 0)
    budget      = state.get("token_budget", {})
    budget_pct  = budget.get("utilisation_pct", 0)

    budget_color = "green" if budget_pct < 50 else "yellow" if budget_pct < 80 else "red"

    content = (
        f"[bold green]✓ Confirmed[/]   {confirmed:>4}\n"
        f"[yellow]⏳ Pending[/]     {pending:>4}\n"
        f"[red]✗ Rejected[/]    {rejected:>4}\n"
        f"[cyan]🔄 Corrections[/] {corrections:>4}\n"
        f"[blue]🔧 Tool calls[/]  {tool_calls:>4}\n"
        f"[{budget_color}]💾 Token budget[/] {budget_pct:>3.0f}%"
    )
    return Panel(content, title="[bold]Stats[/]", border_style="white", width=24)


def render_sigma(state: dict) -> Panel:
    """Sigma matches summary."""
    # Extract sigma findings from confirmed
    sigma_findings = [
        f for f in state.get("confirmed_findings", [])
        if f.get("tool_call") == "sigma_matcher"
    ]
    lines = []
    for f in sigma_findings[:6]:
        desc = str(f.get("description",""))
        rule = desc.split("Sigma:")[-1][:40] if "Sigma:" in desc else desc[:40]
        lines.append(f"[yellow]▸[/] {rule}")
    if not lines:
        lines = ["[dim]No Sigma matches yet[/]"]

    return Panel(
        "\n".join(lines),
        title=f"[bold yellow]Sigma Matches ({len(sigma_findings)})[/]",
        border_style="yellow",
        width=50,
    )


def build_layout(state: dict, watch_path: str) -> str:
    """Build full dashboard layout."""
    tool_log = state.get("tool_call_log", [])

    layout = Layout()
    layout.split_column(
        Layout(name="header",   size=4),
        Layout(name="middle",   size=30),
        Layout(name="bottom",   size=20),
    )
    layout["middle"].split_row(
        Layout(name="findings", ratio=3),
        Layout(name="right",    ratio=2),
    )
    layout["right"].split_column(
        Layout(name="stats",    size=12),
        Layout(name="sigma",    ratio=1),
    )
    layout["bottom"].split_row(
        Layout(name="toollog",  ratio=2),
        Layout(name="diffs",    ratio=2),
        Layout(name="rejected", ratio=2),
    )

    layout["header"].update(render_header(state, watch_path))
    layout["findings"].update(render_findings_table(state))
    layout["stats"].update(render_stats(state))
    layout["sigma"].update(render_sigma(state))
    layout["toollog"].update(render_tool_log(tool_log))
    layout["diffs"].update(render_iter_diffs(state))
    layout["rejected"].update(render_rejected_table(state))

    return layout


def run_dashboard(watch_path: str, refresh_sec: float = 2.0):
    """Main dashboard loop."""
    console.clear()

    with Live(console=console, refresh_per_second=1, screen=True) as live:
        while True:
            state = load_state(watch_path)
            layout = build_layout(state, watch_path)
            live.update(layout)

            # Stop if analysis complete
            if state.get("stop_reason"):
                time.sleep(2)
                live.update(build_layout(state, watch_path))
                console.print("\n[bold green]✓ Analysis complete. Dashboard frozen.[/]")
                break

            time.sleep(refresh_sec)


def run_static(watch_path: str):
    """Print one static snapshot (for piping / recording)."""
    state = load_state(watch_path)
    layout = build_layout(state, watch_path)
    console.print(layout)


def main():
    parser = argparse.ArgumentParser(description="Find Evil Live Dashboard")
    parser.add_argument("--watch",   required=True, help="Path to agent_loop.py output JSON")
    parser.add_argument("--refresh", type=float, default=2.0, help="Refresh interval in seconds")
    parser.add_argument("--static",  action="store_true", help="Print one snapshot and exit")
    args = parser.parse_args()

    if args.static:
        run_static(args.watch)
    else:
        console.print(f"[dim]Watching: {args.watch} (refresh every {args.refresh}s)[/]")
        console.print(f"[dim]Start agent in another terminal, then this will update live.[/]")
        console.print(f"[dim]Press Ctrl+C to exit.[/]\n")
        time.sleep(1)
        try:
            run_dashboard(args.watch, args.refresh)
        except KeyboardInterrupt:
            console.print("\n[dim]Dashboard closed.[/]")


if __name__ == "__main__":
    main()
