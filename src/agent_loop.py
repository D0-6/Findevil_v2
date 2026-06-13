"""
agent_loop.py — Find Evil Hackathon
Self-correcting triage agent built on LangGraph.
Calls SIFT MCP tools in smart sequence, cross-checks consistency,
re-runs with adjusted parameters on contradiction, stops at max iterations.

Usage:
    python agent_loop.py \
        --image /cases/win10_malware.E01 \
        --output /tmp/your_findings.json \
        --max-iterations 25 \
        --memory-dump /cases/win10.mem   # optional
"""

import argparse
import sys
import json
import time
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict, Annotated, Optional
from dataclasses import dataclass, field, asdict

# LangGraph
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient

# ── Innovations ───────────────────────────────────────────────────────────────
import importlib.util as _ilu, os as _os
_inn_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "innovations.py")
if _os.path.exists(_inn_path):
    _spec = _ilu.spec_from_file_location("innovations", _inn_path)
    _inn = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_inn)
    IterationDiffTracker = _inn.IterationDiffTracker
    TokenBudgetManager   = _inn.TokenBudgetManager
    score_all_findings   = _inn.score_all_findings
    run_sigma_matcher    = _inn.run_sigma_matcher
else:
    IterationDiffTracker = None; TokenBudgetManager = None
    score_all_findings = None; run_sigma_matcher = None

# ── Logging (structured, required for audit trail submission) ────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("agent-loop")

MAX_ITERATIONS  = int(os.environ.get("MAX_ITERATIONS", "25"))

# Module-level innovation singletons (shared across graph nodes)
_diff_tracker  = IterationDiffTracker() if IterationDiffTracker else None
_budget_mgr    = TokenBudgetManager()   if TokenBudgetManager   else None
_last_evtx_result: dict = {}  # store last evtx output for sigma_matcher
NIM_API_KEY     = os.environ.get("NIM_API_KEY", "")
NIM_BASE_URL    = os.environ.get("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
MODEL_NAME      = os.environ.get("NIM_MODEL", "nvidia/nemotron-3-ultra-550b-a55b")
MCP_SERVER_PATH = os.environ.get("MCP_SERVER_PATH", "./mcp_server.py")


# ═══════════════════════════════════════════════════════════════════════════════
# STATE
# ═══════════════════════════════════════════════════════════════════════════════

class AgentState(TypedDict):
    messages:            list
    iteration:           int
    image_path:          str
    memory_path:         Optional[str]
    confirmed_findings:  list           # IOCs we are confident about
    pending_review:      list           # findings flagged by consistency checker
    rejected_findings:   list           # hallucinations caught and discarded
    consistency_flags:   list           # raw flags from check_consistency
    tool_call_log:       list           # full audit trail
    tool_call_count:     int
    self_corrections:    int            # how many times we re-ran after contradiction
    phase:               str            # triage / deep_dive / correlation / report
    stop_reason:         Optional[str]


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT TRAIL
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ToolCallRecord:
    iteration:    int
    phase:        str
    tool_name:    str
    arguments:    dict
    result_summary: str
    findings_produced: int
    duration_ms:  int
    timestamp:    str
    triggered_correction: bool = False  # True if this call led to a re-run


def _log_tool_call(state: AgentState, tool_name: str, args: dict,
                   result_summary: str, findings: int,
                   duration_ms: int, triggered_correction: bool = False) -> ToolCallRecord:
    record = ToolCallRecord(
        iteration=state["iteration"],
        phase=state["phase"],
        tool_name=tool_name,
        arguments=args,
        result_summary=result_summary,
        findings_produced=findings,
        duration_ms=duration_ms,
        timestamp=datetime.now(timezone.utc).isoformat(),
        triggered_correction=triggered_correction,
    )
    log.info(json.dumps({
        "iter": record.iteration,
        "phase": record.phase,
        "tool": tool_name,
        "findings": findings,
        "correction": triggered_correction,
        "ms": duration_ms,
    }))
    return record


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT — teaches the agent to think like a senior analyst
# ═══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are a senior DFIR analyst running an autonomous triage of a forensic disk image.
You have access to a set of typed forensic tools via MCP. Each tool returns structured data — not raw text.

YOUR ANALYSIS PROTOCOL (follow this sequence):

PHASE 1 — TRIAGE (iterations 1-5):
Run fast breadth-first triage. Start with:
1. mft_timeline: find executables in unusual paths (temp, appdata, programdata)
2. prefetch_analysis: find LOLBAS binaries and unusual execution counts
3. evtx_parser channel=Security: find critical event IDs (4697, 4698, 1102, 4688)
4. registry_hive hive=SOFTWARE check_persistence=true: find Run key persistence

After each tool call, note what you found. Do not speculate beyond tool output.

PHASE 2 — DEEP DIVE (iterations 6-15):
Follow the evidence. For each suspicious artifact from Phase 1:
- Confirm with a second tool (e.g. prefetch found certutil.exe → amcache_query to get SHA1)
- Use hash_lookup to verify hashes before claiming them as IOCs
- Use volatility_memory plugin=all_triage if memory dump is available
- Use yara_scan on suspicious files
- Use browser_forensics and lnk_analyzer for user activity context

PHASE 3 — CORRELATION (iterations 16-20):
Before writing any finding as confirmed:
1. ALWAYS call check_consistency on pairs of related findings
2. If check_consistency returns flags with severity=high: REJECT the finding, log the contradiction, re-run with adjusted parameters
3. If check_consistency returns clean: promote finding to confirmed_findings
4. Use network_forensics to correlate any C2 indicators with memory findings
5. ALWAYS call sigma_matcher immediately after every evtx_parser call — it matches Sigma community rules and returns MITRE technique IDs
6. For every confirmed finding, call ioc_pivot to find related artifacts across all collected results and classify kill chain stage
7. Use timeline_anomaly_detector on supertimeline output to find off-hours activity and attack window

PHASE 4 — REPORT (iterations 21-25):
Compile confirmed_findings only. Distinguish:
- CONFIRMED: supported by 2+ independent artifact sources
- INFERRED: supported by 1 source with logical reasoning
- SPECULATIVE: noted but not confirmed
Never include rejected_findings in the final report.

CRITICAL RULES:
- Never state a hash without calling hash_lookup first
- Never claim a process ran without prefetch, amcache, OR shimcache evidence
- Never claim network C2 without network_forensics tool output
- If a finding has no tool_call backing it, it is a hallucination — discard it
- Log every re-run as a self-correction with reason
- Stop analysis if max_iterations reached — report what you have
"""


# ═══════════════════════════════════════════════════════════════════════════════
# GRAPH NODES
# ═══════════════════════════════════════════════════════════════════════════════

def should_continue(state: AgentState) -> str:
    """Router: decide next node based on state."""
    if state["iteration"] >= MAX_ITERATIONS:
        return "write_report"
    if state["stop_reason"]:
        return "write_report"
    if state["phase"] == "report":
        return "write_report"
    return "analyst"


def analyst_node(state: AgentState, tools, llm_with_tools) -> AgentState:
    """Main analyst node — calls LLM which decides which tool to call next."""
    iteration = state["iteration"] + 1
    log.info(json.dumps({"node": "analyst", "iter": iteration, "phase": state["phase"]}))

    # Inject current state summary into context
    context_msg = HumanMessage(content=f"""
Iteration {iteration}/{MAX_ITERATIONS}
Phase: {state['phase']}
Image: {state['image_path']}
Memory dump: {state.get('memory_path', 'not provided')}

Confirmed findings so far: {len(state['confirmed_findings'])}
Pending review: {len(state['pending_review'])}
Rejected (hallucinations caught): {len(state['rejected_findings'])}
Self-corrections made: {state['self_corrections']}
Tool calls so far: {state['tool_call_count']}

Recent consistency flags:
{json.dumps(state['consistency_flags'][-3:], indent=2) if state['consistency_flags'] else 'none'}

Confirmed findings summary:
{json.dumps([f.get('value','') for f in state['confirmed_findings']], indent=2) if state['confirmed_findings'] else 'none yet'}

Continue analysis. Choose the most valuable next tool call based on what you've found so far.
If iteration >= 16, move to PHASE 3 (correlation). If >= 21, move to PHASE 4 (report).
""")

    messages = state["messages"] + [context_msg]
    t0 = time.monotonic()
    response = llm_with_tools.invoke(messages)
    duration_ms = int((time.monotonic() - t0) * 1000)

    new_messages = state["messages"] + [context_msg, response]

    # Determine phase transition
    phase = state["phase"]
    if iteration >= 21:
        phase = "report"
    elif iteration >= 16:
        phase = "correlation"
    elif iteration >= 6:
        phase = "deep_dive"

    new_state = {
        **state,
        "messages": new_messages,
        "iteration": iteration,
        "phase": phase,
        "tool_call_count": state["tool_call_count"] + 1,
    }
    # Innovation 3: snapshot for diff tracking
    if _diff_tracker:
        _diff_tracker.snapshot(new_state)
    return new_state


def tool_executor_node(state: AgentState, mcp_client) -> AgentState:
    """Execute tool calls from the LLM response and process results."""
    last_msg = state["messages"][-1]
    if not hasattr(last_msg, "tool_calls") or not last_msg.tool_calls:
        return state

    new_messages  = list(state["messages"])
    confirmed     = list(state["confirmed_findings"])
    pending       = list(state["pending_review"])
    rejected      = list(state["rejected_findings"])
    c_flags       = list(state["consistency_flags"])
    tool_log      = list(state["tool_call_log"])
    corrections   = state["self_corrections"]

    for tool_call in last_msg.tool_calls:
        tool_name = tool_call["name"]
        tool_args = tool_call["args"]
        t0 = time.monotonic()

        try:
            result = mcp_client.call_tool(tool_name, tool_args)
            result_data = json.loads(result.content[0].text) if result.content else {}
        except Exception as e:
            result_data = {"error": str(e)}

        duration_ms = int((time.monotonic() - t0) * 1000)

        # ── Process check_consistency results ─────────────────────────────────
        triggered_correction = False
        if tool_name == "check_consistency":
            flags = result_data.get("flags", [])
            c_flags.extend(flags)

            high_flags = [f for f in flags if f.get("severity") in ("high", "critical")]
            if high_flags:
                triggered_correction = True
                corrections += 1
                log.info(json.dumps({
                    "event": "self_correction",
                    "reason": high_flags[0].get("finding"),
                    "correction_number": corrections,
                }))
                # Move affected findings to rejected
                for flag in high_flags:
                    detail = flag.get("detail", "")
                    # Find and reject findings matching the flag
                    still_pending = []
                    for f in pending:
                        if f.get("value", "").lower() in detail.lower():
                            f["rejection_reason"] = flag.get("finding")
                            rejected.append(f)
                            log.info(json.dumps({
                                "event": "finding_rejected",
                                "value": f.get("value"),
                                "reason": flag.get("finding"),
                            }))
                        else:
                            still_pending.append(f)
                    pending = still_pending
            else:
                # Consistency check passed — promote pending to confirmed
                for f in pending:
                    if f not in confirmed:
                        f["evidence_status"] = "confirmed_by_consistency_check"
                        confirmed.append(f)
                        log.info(json.dumps({"event": "finding_confirmed", "value": f.get("value")}))
                pending = []

        # ── Extract findings from other tool results ───────────────────────────
        else:
            new_findings = _extract_findings(tool_name, tool_args, result_data)
            for finding in new_findings:
                finding["tool_call"]  = tool_name
                finding["iteration"]  = state["iteration"]
                finding["timestamp"]  = datetime.now(timezone.utc).isoformat()
                # All new findings go to pending until check_consistency validates them
                if finding not in pending and finding not in confirmed:
                    pending.append(finding)

        # ── Auto-call sigma_matcher after evtx_parser ───────────────────────
        if tool_name == "evtx_parser" and result_data.get("entries"):
            try:
                sigma_tool_call = {"name": "sigma_matcher", "args": {"evtx_result": result_data}, "id": f"auto_sigma_{state['iteration']}"}
                sigma_out, _, _ = await call_tool("sigma_matcher", {"evtx_result": result_data}) if False else (None, None, None)
                # Log intent — actual call happens via next LLM turn based on SYSTEM_PROMPT instruction
                log.info(json.dumps({"event": "sigma_matcher_recommended", "iter": state["iteration"]}))
            except Exception:
                pass

        # ── Append tool result to messages ────────────────────────────────────
        result_summary = _summarise_result(tool_name, result_data)
        # Innovation 4: token budget manager — smart truncation instead of hard [:4000]
        if _budget_mgr:
            _budget_mgr.record(tool_name, result_data, state["iteration"])
            safe_content = _budget_mgr.get_safe_content(result_data, tool_name, max_tokens=4000)
        else:
            safe_content = json.dumps(result_data, default=str)[:4000]

        # Store last evtx result for sigma_matcher
        if tool_name == "evtx_parser":
            global _last_evtx_result
            _last_evtx_result = result_data

        new_messages.append(ToolMessage(
            content=safe_content,
            tool_call_id=tool_call["id"],
            name=tool_name,
        ))

        record = _log_tool_call(
            state, tool_name, tool_args,
            result_summary, len(_extract_findings(tool_name, tool_args, result_data)),
            duration_ms, triggered_correction,
        )
        tool_log.append(asdict(record))

    return {
        **state,
        "messages":           new_messages,
        "confirmed_findings": confirmed,
        "pending_review":     pending,
        "rejected_findings":  rejected,
        "consistency_flags":  c_flags,
        "tool_call_log":      tool_log,
        "self_corrections":   corrections,
    }


def write_report_node(state: AgentState) -> AgentState:
    """Compile final structured report from confirmed findings only."""
    log.info(json.dumps({
        "event": "report_generated",
        "confirmed": len(state["confirmed_findings"]),
        "rejected": len(state["rejected_findings"]),
        "corrections": state["self_corrections"],
        "iterations": state["iteration"],
    }))

    return {
        **state,
        "stop_reason": state["stop_reason"] or "analysis_complete",
        "phase": "report",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _extract_findings(tool_name: str, args: dict, result: dict) -> list[dict]:
    """Pull actionable findings out of each tool's typed response."""
    findings = []

    if tool_name == "mft_timeline":
        for flag in result.get("suspicious_flags", []):
            findings.append({"ioc_type": "file_path", "value": flag,
                             "description": f"MFT: {flag}", "confidence": "inferred"})
        for entry in result.get("entries", []):
            if entry.get("is_deleted") and entry.get("full_path","").lower().endswith((".exe",".dll",".ps1")):
                findings.append({"ioc_type": "file_path", "value": entry["full_path"],
                                 "description": f"Deleted executable: {entry['full_path']}",
                                 "confidence": "inferred"})

    elif tool_name == "prefetch_analysis":
        for a in result.get("anomalies", []):
            findings.append({"ioc_type": "process_name", "value": a,
                             "description": f"Prefetch anomaly: {a}", "confidence": "inferred"})

    elif tool_name == "amcache_query":
        for path in result.get("unsigned_binaries", []):
            findings.append({"ioc_type": "file_path", "value": path,
                             "description": f"Unsigned binary: {path}", "confidence": "inferred"})

    elif tool_name == "evtx_parser":
        for eid in result.get("critical_event_ids_found", []):
            findings.append({"ioc_type": "event_id", "value": str(eid),
                             "description": f"Critical event ID {eid} found",
                             "confidence": "confirmed"})

    elif tool_name == "registry_hive":
        for p in result.get("persistence_indicators", []):
            findings.append({"ioc_type": "registry_key", "value": p,
                             "description": f"Persistence: {p}", "confidence": "inferred"})

    elif tool_name == "volatility_memory":
        if result.get("hidden_process_count", 0) > 0:
            findings.append({"ioc_type": "process_name",
                             "value": f"hidden_processes:{result['hidden_process_count']}",
                             "description": f"{result['hidden_process_count']} hidden processes (pslist vs psscan)",
                             "confidence": "confirmed"})
        for name in result.get("injected_process_names", []):
            findings.append({"ioc_type": "process_name", "value": name,
                             "description": f"Injected memory region: {name}", "confidence": "confirmed"})

    elif tool_name == "yara_scan":
        for match in result.get("matches", []):
            findings.append({"ioc_type": "file_path", "value": match.get("file_path",""),
                             "description": f"YARA:{match.get('rule_name')} sev:{match.get('severity')}",
                             "confidence": "confirmed" if match.get("severity") in ("high","critical") else "inferred"})

    elif tool_name == "network_forensics":
        for c in result.get("connections", []):
            if c.get("is_suspicious"):
                findings.append({"ioc_type": "network",
                                 "value": f"{c.get('remote_addr')}:{c.get('remote_port')}",
                                 "description": f"Suspicious connection: {c.get('reason')}",
                                 "confidence": "confirmed"})
        for c2 in result.get("c2_indicators", []):
            findings.append({"ioc_type": "network", "value": c2,
                             "description": f"C2 indicator: {c2}", "confidence": "confirmed"})

    elif tool_name == "browser_forensics":
        for url in result.get("suspicious_urls", []):
            findings.append({"ioc_type": "network", "value": url,
                             "description": f"Suspicious URL in browser history: {url}",
                             "confidence": "inferred"})

    elif tool_name == "file_carve":
        for f in result.get("carved_files", []):
            if f.get("extension") in (".exe",".dll",".ps1",".bat"):
                findings.append({"ioc_type": "file_path", "value": f.get("path",""),
                                 "description": f"Carved deleted file: {f.get('filename')}",
                                 "confidence": "inferred"})

    elif tool_name == "usb_forensics":
        for dev in result.get("devices", []):
            if dev.get("suspicious"):
                findings.append({"ioc_type": "usb_device", "value": dev.get("serial",""),
                                 "description": f"Suspicious USB: {dev.get('friendly_name')}",
                                 "confidence": "inferred"})

    elif tool_name == "scheduled_tasks":
        for t in result.get("suspicious_tasks", []):
            findings.append({"ioc_type": "registry_key", "value": t.get("name",""),
                             "description": f"Suspicious scheduled task: {t.get('action','')}",
                             "confidence": "inferred"})

    elif tool_name == "ads_detector":
        for ads in result.get("streams", []):
            findings.append({"ioc_type": "file_path", "value": ads.get("path",""),
                             "description": f"ADS stream: {ads.get('stream_name')} size:{ads.get('size_bytes')}",
                             "confidence": "inferred"})

    elif tool_name == "ioc_pivot":
        kc = result.get("kill_chain_stage", "unknown")
        pivot_val = result.get("pivot_value", "")
        related_count = len(result.get("related_artifacts", []))
        if related_count >= 2:
            findings.append({
                "ioc_type": "file_path",
                "value": pivot_val,
                "description": f"IOC pivot: {related_count} related artifacts across tools. Kill chain: {kc}",
                "confidence": "confirmed" if related_count >= 3 else "inferred",
            })
        for next_tool in result.get("recommended_next_tools", [])[:2]:
            log.info(json.dumps({"event": "pivot_recommends", "tool": next_tool, "for": pivot_val}))

    elif tool_name == "sigma_matcher":
        for match in result.get("matches", []):
            findings.append({
                "ioc_type": "event_id",
                "value": match.get("rule_id", ""),
                "description": f"Sigma:{match.get('rule_title','')} mitre:{','.join(match.get('mitre_techniques',[]))}",
                "confidence": "confirmed" if match.get("level") in ("high","critical") else "inferred",
            })

    elif tool_name == "timeline_anomaly_detector":
        for anomaly in result.get("anomalies", []):
            if anomaly.get("severity") in ("high","critical"):
                findings.append({
                    "ioc_type": "event_id",
                    "value": f"anomaly:{anomaly.get('anomaly_type','')}:{anomaly.get('timestamp','')}",
                    "description": anomaly.get("detail","")[:200],
                    "confidence": "inferred",
                })

    elif tool_name == "threat_intel_lookup":
        for match in result.get("results", []):
            if match.get("matched_malware_family"):
                findings.append({
                    "ioc_type": "process_name",
                    "value": match.get("ioc_value",""),
                    "description": f"ThreatIntel: {match.get('matched_malware_family','')} actor:{match.get('matched_threat_actor','')}",
                    "confidence": match.get("confidence","low"),
                })

    return findings


def _summarise_result(tool_name: str, result: dict) -> str:
    """One-line summary of tool result for log."""
    if "error" in result:
        return f"ERROR: {result['error']}"
    meta = result.get("meta", {})
    entries = len(result.get("entries", result.get("processes",
              result.get("matches", result.get("connections",
              result.get("keys", result.get("devices", [])))))))
    return f"tool={tool_name} entries={entries} ms={meta.get('duration_ms',0)} truncated={meta.get('truncated',False)}"


# ═══════════════════════════════════════════════════════════════════════════════
# GRAPH BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def build_graph(mcp_client):
    llm = ChatOpenAI(
        model=MODEL_NAME,
        openai_api_key=NIM_API_KEY,
        openai_api_base=NIM_BASE_URL,
        temperature=0.2,
        max_tokens=4096,
        model_kwargs={
            "top_p": 0.95,
        },
    )
    tools = mcp_client.get_tools()
    llm_with_tools = llm.bind_tools(tools)

    graph = StateGraph(AgentState)

    graph.add_node("analyst",      lambda s: analyst_node(s, tools, llm_with_tools))
    graph.add_node("tool_executor",lambda s: tool_executor_node(s, mcp_client))
    graph.add_node("write_report", write_report_node)

    graph.set_entry_point("analyst")
    graph.add_conditional_edges("analyst", should_continue, {
        "analyst":      "tool_executor",
        "write_report": "write_report",
    })
    graph.add_edge("tool_executor", "analyst")
    graph.add_edge("write_report", END)

    return graph.compile()


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT WRITER
# ═══════════════════════════════════════════════════════════════════════════════

def write_output(state: AgentState, output_path: str):
    # Innovation 2: score all confirmed findings before writing
    if score_all_findings and run_sigma_matcher and _last_evtx_result:
        try:
            sigma_res = run_sigma_matcher(_last_evtx_result)
            state["confirmed_findings"] = score_all_findings(
                state["confirmed_findings"],
                state["tool_call_log"],
                state["consistency_flags"],
                sigma_res,
            )
            log.info(json.dumps({"event":"corroboration_scoring_complete",
                                 "findings_scored":len(state["confirmed_findings"])}))
        except Exception as e:
            log.warning(json.dumps({"event":"corroboration_scoring_failed","error":str(e)}))

    output = {
        "run_id": f"agent_{int(time.time())}",
        "image_path": state["image_path"],
        "memory_path": state.get("memory_path"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stop_reason": state.get("stop_reason"),
        "iterations_used": state["iteration"],
        "tool_call_count": state["tool_call_count"],
        "self_corrections": state["self_corrections"],
        "confirmed_findings": state["confirmed_findings"],
        "pending_review": state["pending_review"],
        "rejected_findings": state["rejected_findings"],
        "consistency_flags": state["consistency_flags"],
        "tool_call_log": state["tool_call_log"],
        "summary": {
            "confirmed": len(state["confirmed_findings"]),
            "pending":   len(state["pending_review"]),
            "rejected":  len(state["rejected_findings"]),
            "hallucinations_caught": sum(
                1 for f in state["rejected_findings"]
                if "hallucination" in str(f.get("rejection_reason","")).lower()
            ),
        },
    }

    # Innovation 3 + 4: add diff log and token budget to output
    if _diff_tracker:
        output["iteration_diffs"] = _diff_tracker.export()
    if _budget_mgr:
        output["token_budget"] = _budget_mgr.status()

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\n[agent] ✓ Output written: {output_path}")
    print(f"[agent] Confirmed findings : {output['summary']['confirmed']}")
    print(f"[agent] Self-corrections   : {state['self_corrections']}")
    print(f"[agent] Hallucinations caught: {output['summary']['hallucinations_caught']}")
    print(f"[agent] Iterations used    : {state['iteration']}/{MAX_ITERATIONS}")
    if _diff_tracker:
        _diff_tracker.print_summary()
    if _budget_mgr:
        _budget_mgr.report()


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Find Evil Self-Correcting Agent")
    parser.add_argument("--image",          required=True)
    parser.add_argument("--output",         default="/tmp/your_findings.json")
    parser.add_argument("--max-iterations", type=int, default=MAX_ITERATIONS)
    parser.add_argument("--memory-dump",    default=None)
    args = parser.parse_args()

    global MAX_ITERATIONS
    MAX_ITERATIONS = args.max_iterations

    if not NIM_API_KEY:
        print("[agent] ERROR: NIM_API_KEY not set.")
        print("[agent] Run: export NIM_API_KEY=nvapi-xxxx")
        sys.exit(1)

    print(f"[agent] Starting analysis: {args.image}")
    print(f"[agent] Model: {MODEL_NAME} via {NIM_BASE_URL}")
    print(f"[agent] Max iterations: {MAX_ITERATIONS}")

    # Connect to MCP server
    mcp_client = MultiServerMCPClient({
        "sift": {
            "command": "python3",
            "args": [MCP_SERVER_PATH],
            "env": {
                "SIFT_CASES_DIR": str(Path(args.image).parent),
                "SIFT_MAX_ROWS": "500",
            },
        }
    })

    graph = build_graph(mcp_client)

    initial_state: AgentState = {
        "messages": [SystemMessage(content=SYSTEM_PROMPT)],
        "iteration": 0,
        "image_path": args.image,
        "memory_path": args.memory_dump,
        "confirmed_findings": [],
        "pending_review": [],
        "rejected_findings": [],
        "consistency_flags": [],
        "tool_call_log": [],
        "tool_call_count": 0,
        "self_corrections": 0,
        "phase": "triage",
        "stop_reason": None,
    }

    final_state = graph.invoke(initial_state)
    write_output(final_state, args.output)


if __name__ == "__main__":
    main()
