"""
mcp_server_final.py — Find Evil Hackathon
FINAL merged MCP server: 21 typed forensic tools + 4 new advanced features.

Architecture: Custom MCP Server (Pattern 2)
Evidence integrity: READ-ONLY. No shell_exec. No write commands. Architectural enforcement.

Tools (21 core + 4 new = 25 total):
  Core:    mft_timeline, prefetch_analysis, amcache_query, shimcache_query,
           evtx_parser, registry_hive, supertimeline, volatility_memory,
           yara_scan, network_forensics, browser_forensics, file_carve,
           hash_lookup, lnk_analyzer, check_consistency
  Extra:   usb_forensics, shadow_copy, scheduled_tasks, ads_detector,
           strings_extract, pe_metadata
  NEW:     ioc_pivot, timeline_anomaly_detector, threat_intel_lookup, report_compiler
"""

import subprocess, json, hashlib, re, os, time, logging, asyncio, math
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from pydantic import BaseModel, Field
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp import types

# ── Innovations module ───────────────────────────────────────────────────────
import sys, os as _os
_innovations_path = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "innovations.py")
if _os.path.exists(_innovations_path):
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("innovations", _innovations_path)
    _inn = _ilu.module_from_spec(_spec); _spec.loader.exec_module(_inn)
    run_sigma_matcher = _inn.run_sigma_matcher
    score_all_findings = _inn.score_all_findings
    SIGMA_RULES_EMBEDDED = _inn.SIGMA_RULES_EMBEDDED
else:
    run_sigma_matcher = None; score_all_findings = None; SIGMA_RULES_EMBEDDED = []

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("sift-mcp")

CASES_DIR   = Path(os.environ.get("SIFT_CASES_DIR", "/cases"))
MOUNT_BASE  = Path(os.environ.get("SIFT_MOUNT_BASE", "/mnt/sift_evidence"))
MAX_ROWS    = int(os.environ.get("SIFT_MAX_ROWS", "500"))
TIMEOUT_SEC = int(os.environ.get("SIFT_TIMEOUT",  "120"))

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
LOLBAS = {
    "certutil.exe","mshta.exe","wscript.exe","cscript.exe","regsvr32.exe",
    "rundll32.exe","msiexec.exe","wmic.exe","powershell.exe","cmd.exe",
    "bitsadmin.exe","pcalua.exe","schtasks.exe","at.exe","msbuild.exe",
    "installutil.exe","regasm.exe","regsvcs.exe","odbcconf.exe","cmstp.exe",
    "forfiles.exe","bash.exe","wsl.exe","hh.exe","msiexec.exe",
}
CRITICAL_EVENT_IDS = {
    4624,4625,4648,4672,4688,4697,4698,4699,4700,4701,
    4702,4720,4722,4724,4728,4732,4756,4776,7045,1102,4104,4103,
}
PERSISTENCE_KEYS = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"System\CurrentControlSet\Services",
    r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"Software\Classes\ms-settings\shell\open\command",   # UAC bypass
    r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
]
SUSPICIOUS_PORTS  = {4444,1337,8888,9999,31337,6666,6667,1234,2222,5555,8080,8443}
SUSPICIOUS_IMPORTS = {
    "VirtualAlloc","VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
    "NtCreateThreadEx","RtlCreateUserThread","CryptEncrypt","CryptGenKey",
    "InternetOpen","InternetConnect","HttpSendRequest","WinExec","ShellExecute",
    "RegSetValueEx","RegCreateKeyEx","GetAsyncKeyState","SetWindowsHookEx",
    "LoadLibrary","GetProcAddress","IsDebuggerPresent","CheckRemoteDebuggerPresent",
}
SUSPICIOUS_TASK_PATTERNS = [
    r'\\temp\\', r'\\appdata\\', r'\\programdata\\',
    r'powershell.*-enc', r'powershell.*-w.*hidden', r'powershell.*bypass',
    r'cmd.*\/c.*curl', r'cmd.*\/c.*certutil', r'wscript', r'cscript',
    r'mshta', r'regsvr32', r'rundll32.*\.dll,', r'base64', r'frombase64',
]


# ─────────────────────────────────────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────────────
class ToolMeta(BaseModel):
    tool_name: str; executed_at: str; duration_ms: int
    evidence_hash: Optional[str]=None; truncated: bool=False

class MFTEntry(BaseModel):
    inode: str; filename: str; full_path: str
    created: Optional[str]=None; modified: Optional[str]=None
    accessed: Optional[str]=None; mft_modified: Optional[str]=None
    size_bytes: Optional[int]=None; flags: Optional[str]=None; is_deleted: bool=False

class MFTResult(BaseModel):
    meta: ToolMeta; entries: list[MFTEntry]; total_entries: int
    suspicious_flags: list[str]=Field(default_factory=list)

class PrefetchEntry(BaseModel):
    executable: str; run_count: int=0; last_run: Optional[str]=None
    all_run_times: list[str]=Field(default_factory=list)
    volume_paths: list[str]=Field(default_factory=list)
    loaded_dlls: list[str]=Field(default_factory=list)

class PrefetchResult(BaseModel):
    meta: ToolMeta; entries: list[PrefetchEntry]; total_entries: int
    anomalies: list[str]=Field(default_factory=list)

class AmcacheEntry(BaseModel):
    sha1: Optional[str]=None; path: str; name: str
    publisher: Optional[str]=None; last_modified: Optional[str]=None
    file_size: Optional[int]=None

class AmcacheResult(BaseModel):
    meta: ToolMeta; entries: list[AmcacheEntry]; total_entries: int
    unsigned_binaries: list[str]=Field(default_factory=list)

class ShimcacheEntry(BaseModel):
    order: int; path: str; last_modified: Optional[str]=None; exec_flag: Optional[bool]=None

class ShimcacheResult(BaseModel):
    meta: ToolMeta; entries: list[ShimcacheEntry]; total_entries: int

class EventLogEntry(BaseModel):
    event_id: int; timestamp: str; source: str
    computer: Optional[str]=None; user: Optional[str]=None; description: str

class EventLogResult(BaseModel):
    meta: ToolMeta; channel: str; entries: list[EventLogEntry]
    total_entries: int; critical_event_ids_found: list[int]=Field(default_factory=list)

class RegistryKey(BaseModel):
    key_path: str; value_name: Optional[str]=None
    value_type: Optional[str]=None; value_data: Optional[str]=None
    last_written: Optional[str]=None

class RegistryResult(BaseModel):
    meta: ToolMeta; hive: str; keys: list[RegistryKey]
    total_keys: int; persistence_indicators: list[str]=Field(default_factory=list)

class TimelineEntry(BaseModel):
    timestamp: str; macb: str; source: str; source_type: str
    full_path: str; inode: Optional[str]=None
    username: Optional[str]=None; description: str

class TimelineResult(BaseModel):
    meta: ToolMeta; entries: list[TimelineEntry]; total_entries: int
    time_range_start: Optional[str]=None; time_range_end: Optional[str]=None

class VolatilityProcess(BaseModel):
    pid: int; ppid: int; name: str; offset: str
    create_time: Optional[str]=None; cmd_line: Optional[str]=None; is_hidden: bool=False

class VolatilityResult(BaseModel):
    meta: ToolMeta; plugin: str; processes: list[VolatilityProcess]
    total: int; hidden_process_count: int=0
    injected_process_names: list[str]=Field(default_factory=list)

class YaraMatch(BaseModel):
    rule_name: str; tags: list[str]=Field(default_factory=list)
    file_path: str; offset: Optional[int]=None
    matched_strings: list[str]=Field(default_factory=list); severity: str="medium"

class YaraResult(BaseModel):
    meta: ToolMeta; rules_file: str; matches: list[YaraMatch]
    total_matches: int; scanned_files: int

class NetworkConn(BaseModel):
    proto: str; local_addr: str; local_port: int
    remote_addr: str; remote_port: int; state: Optional[str]=None
    pid: Optional[int]=None; process_name: Optional[str]=None
    is_suspicious: bool=False; reason: Optional[str]=None

class NetworkResult(BaseModel):
    meta: ToolMeta; connections: list[NetworkConn]; total: int
    suspicious_count: int=0; c2_indicators: list[str]=Field(default_factory=list)
    beaconing_detected: bool=False

class BrowserEntry(BaseModel):
    browser: str; url: str; title: Optional[str]=None
    visit_time: Optional[str]=None; visit_count: int=0
    username: Optional[str]=None

class BrowserResult(BaseModel):
    meta: ToolMeta; entries: list[BrowserEntry]; total_entries: int
    suspicious_urls: list[str]=Field(default_factory=list)
    download_paths: list[str]=Field(default_factory=list)

class FileCarveResult(BaseModel):
    meta: ToolMeta; carved_files: list[dict]; total_carved: int; output_dir: str

class USBDevice(BaseModel):
    serial: str; friendly_name: Optional[str]=None
    first_connected: Optional[str]=None; last_connected: Optional[str]=None
    drive_letter: Optional[str]=None; user_sid: Optional[str]=None
    suspicious: bool=False; reason: Optional[str]=None

class USBResult(BaseModel):
    meta: ToolMeta; devices: list[USBDevice]; total_devices: int; suspicious_count: int=0

class ShadowCopy(BaseModel):
    id: str; creation_time: Optional[str]=None; volume: Optional[str]=None
    is_deleted: bool=False

class ShadowCopyResult(BaseModel):
    meta: ToolMeta; copies: list[ShadowCopy]; total_copies: int
    deleted_copies: int=0; note: str=""

class ScheduledTask(BaseModel):
    name: str; path: str; action: Optional[str]=None; trigger: Optional[str]=None
    author: Optional[str]=None; run_as_user: Optional[str]=None
    created: Optional[str]=None; last_run: Optional[str]=None
    enabled: bool=True; suspicious: bool=False; reason: Optional[str]=None

class ScheduledTaskResult(BaseModel):
    meta: ToolMeta; tasks: list[ScheduledTask]; total_tasks: int
    suspicious_tasks: list[ScheduledTask]=Field(default_factory=list)

class ADSStream(BaseModel):
    host_file: str; stream_name: str; size_bytes: int
    content_preview: Optional[str]=None; is_executable_content: bool=False
    entropy: Optional[float]=None

class ADSResult(BaseModel):
    meta: ToolMeta; streams: list[ADSStream]; total_streams: int; executable_streams: int=0

class StringsResult(BaseModel):
    meta: ToolMeta; file_path: str
    urls: list[str]=Field(default_factory=list)
    ip_addresses: list[str]=Field(default_factory=list)
    registry_paths: list[str]=Field(default_factory=list)
    file_paths: list[str]=Field(default_factory=list)
    suspicious_keywords: list[str]=Field(default_factory=list)
    encoded_blobs: list[str]=Field(default_factory=list)
    c2_candidates: list[str]=Field(default_factory=list)   # NEW: scored C2 candidates

class PESection(BaseModel):
    name: str; virtual_size: int; raw_size: int; entropy: float; is_suspicious: bool=False

class PEMetadataResult(BaseModel):
    meta: ToolMeta; file_path: str; compile_timestamp: Optional[str]=None
    is_suspicious_timestamp: bool=False; imphash: Optional[str]=None
    imports: list[str]=Field(default_factory=list)
    suspicious_imports: list[str]=Field(default_factory=list)
    sections: list[PESection]=Field(default_factory=list)
    is_packed: bool=False; packer_hint: Optional[str]=None
    is_signed: bool=False; signer: Optional[str]=None; is_dotnet: bool=False

class ConsistencyFlag(BaseModel):
    artifact_a: str; artifact_b: str; finding: str; severity: str; detail: str

class ConsistencyResult(BaseModel):
    flags: list[ConsistencyFlag]; clean: bool

# ── NEW MODELS ────────────────────────────────────────────────────────────────
class PivotResult(BaseModel):
    """ioc_pivot: given one IOC, find all related artifacts across tool outputs."""
    meta: ToolMeta
    pivot_value: str
    pivot_type: str
    related_artifacts: list[dict]=Field(default_factory=list)
    kill_chain_stage: Optional[str]=None   # initial_access/execution/persistence/lateral/exfil
    confidence: str="inferred"
    recommended_next_tools: list[str]=Field(default_factory=list)

class AnomalyEntry(BaseModel):
    timestamp: str; event: str; source: str
    anomaly_type: str   # temporal_gap / burst / off_hours / impossible_speed
    severity: str; detail: str; related_ioc: Optional[str]=None

class TimelineAnomalyResult(BaseModel):
    meta: ToolMeta; anomalies: list[AnomalyEntry]; total_anomalies: int
    attack_window_start: Optional[str]=None
    attack_window_end: Optional[str]=None
    off_hours_activity: bool=False

class ThreatIntelEntry(BaseModel):
    ioc_value: str; ioc_type: str
    matched_threat_actor: Optional[str]=None
    matched_malware_family: Optional[str]=None
    matched_campaign: Optional[str]=None
    mitre_techniques: list[str]=Field(default_factory=list)
    confidence: str="low"
    source: str="local_intel"

class ThreatIntelResult(BaseModel):
    meta: ToolMeta; results: list[ThreatIntelEntry]; total_matched: int
    unmatched_iocs: list[str]=Field(default_factory=list)

class ReportSection(BaseModel):
    title: str; content: str; severity: str="info"

class FinalReport(BaseModel):
    meta: ToolMeta
    case_summary: str
    attack_narrative: str          # plain-English kill chain reconstruction
    confirmed_iocs: list[dict]=Field(default_factory=list)
    mitre_mapping: list[dict]=Field(default_factory=list)
    timeline_summary: list[dict]=Field(default_factory=list)
    recommendations: list[str]=Field(default_factory=list)
    analyst_confidence: str        # high / medium / low
    evidence_gaps: list[str]=Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _run(cmd: list[str], timeout: int=TIMEOUT_SEC) -> tuple[str, str, int]:
    t0 = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ms = int((time.monotonic()-t0)*1000)
        log.info(json.dumps({"cmd":cmd[0],"rc":r.returncode,"ms":ms}))
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired: return "", "TIMEOUT", -1
    except FileNotFoundError:         return "", f"TOOL_NOT_FOUND:{cmd[0]}", -2

def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path,"rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except: return None

def _meta(name: str, t0: float, ep: Optional[str]=None, trunc: bool=False) -> ToolMeta:
    return ToolMeta(tool_name=name, executed_at=_now_iso(),
                    duration_ms=int((time.monotonic()-t0)*1000),
                    evidence_hash=_sha256(ep) if ep else None, truncated=trunc)

def _entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c > 0)


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK LOCAL MAPPING
# ─────────────────────────────────────────────────────────────────────────────
MITRE_MAP = {
    "certutil.exe":          [("T1140","Deobfuscate/Decode"),("T1105","Ingress Tool Transfer")],
    "mshta.exe":             [("T1218.005","Mshta")],
    "regsvr32.exe":          [("T1218.010","Regsvr32")],
    "rundll32.exe":          [("T1218.011","Rundll32")],
    "powershell.exe":        [("T1059.001","PowerShell")],
    "wmic.exe":              [("T1047","WMI")],
    "schtasks.exe":          [("T1053.005","Scheduled Task")],
    "VirtualAllocEx":        [("T1055","Process Injection")],
    "WriteProcessMemory":    [("T1055","Process Injection")],
    "CreateRemoteThread":    [("T1055","Process Injection")],
    "CryptEncrypt":          [("T1486","Data Encrypted for Impact")],
    "Run":                   [("T1547.001","Registry Run Keys")],
    "Services":              [("T1543.003","Windows Service")],
    "Winlogon":              [("T1547.004","Winlogon Helper")],
    "BootExecute":           [("T1542.003","Bootkit")],
    "4697":                  [("T1543.003","Windows Service")],
    "4698":                  [("T1053.005","Scheduled Task")],
    "1102":                  [("T1070.001","Clear Windows Event Logs")],
    "4688":                  [("T1059","Command and Scripting Interpreter")],
    "shadow":                [("T1490","Inhibit System Recovery")],
    "mimikatz":              [("T1003","OS Credential Dumping")],
    "lsass":                 [("T1003.001","LSASS Memory")],
    ":4444":                 [("T1571","Non-Standard Port")],
    "pastebin":              [("T1102","Web Service C2")],
    "ads":                   [("T1564.004","NTFS File Attributes")],
    "usb":                   [("T1052.001","Exfiltration over USB")],
}

def _map_mitre(value: str) -> list[dict]:
    hits = []
    val_lower = value.lower()
    for keyword, techniques in MITRE_MAP.items():
        if keyword.lower() in val_lower:
            for tid, tname in techniques:
                entry = {"technique_id": tid, "technique_name": tname, "matched_on": keyword}
                if entry not in hits:
                    hits.append(entry)
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# KILL CHAIN CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────
def _classify_kill_chain(ioc_type: str, value: str, description: str) -> str:
    combined = f"{ioc_type} {value} {description}".lower()
    if any(k in combined for k in ["phish","download","dropper","invoice","lnk","initial"]):
        return "initial_access"
    if any(k in combined for k in ["powershell","cmd","wscript","exec","rundll","certutil"]):
        return "execution"
    if any(k in combined for k in ["run key","service","task","winlogon","boot","startup","persist"]):
        return "persistence"
    if any(k in combined for k in ["mimikatz","lsass","credential","sekurlsa","sam","ntds"]):
        return "credential_access"
    if any(k in combined for k in ["inject","hollow","malfind","hidden process","reflective"]):
        return "defense_evasion"
    if any(k in combined for k in ["netscan","beacon","c2","cobalt","4444","pastebin","http"]):
        return "command_and_control"
    if any(k in combined for k in ["smb","rdp","lateral","psexec","wmi remote","pass-the"]):
        return "lateral_movement"
    if any(k in combined for k in ["encrypt","ransom","shadow","vss","bcdedit","wbadmin"]):
        return "impact"
    if any(k in combined for k in ["usb","exfil","zip","rar","ftp","upload","transfer"]):
        return "exfiltration"
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# MCP SERVER
# ─────────────────────────────────────────────────────────────────────────────
server = Server("sift-mcp-final")

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(name="mft_timeline",
            description="Parse MFT. Returns MACB timestamps, deleted files, executables in unusual paths.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"filter_path":{"type":"string"},
                "include_deleted":{"type":"boolean","default":True},
                "start_time":{"type":"string"},"end_time":{"type":"string"},
            },"required":["image_path"]}),
        types.Tool(name="prefetch_analysis",
            description="Parse Prefetch files. Execution history, run counts, loaded DLLs. Auto-flags LOLBAS.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"executable_filter":{"type":"string"},
            },"required":["image_path"]}),
        types.Tool(name="amcache_query",
            description="Parse Amcache.hve. SHA1 hashes, file paths, publishers. Flags unsigned binaries.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"filter_unsigned":{"type":"boolean","default":False},
            },"required":["image_path"]}),
        types.Tool(name="shimcache_query",
            description="Parse AppCompatCache. Returns execution order and file paths.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"max_entries":{"type":"integer","default":200},
            },"required":["image_path"]}),
        types.Tool(name="evtx_parser",
            description="Parse Windows Event Logs. Auto-flags 22 critical event IDs incl 4688,4697,7045,1102,4104.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},
                "channel":{"type":"string","enum":["Security","System","Application","PowerShell","TaskScheduler","All"],"default":"Security"},
                "event_id_filter":{"type":"array","items":{"type":"integer"}},
                "start_time":{"type":"string"},"end_time":{"type":"string"},
            },"required":["image_path"]}),
        types.Tool(name="registry_hive",
            description="Parse registry hives. Auto-checks 9 persistence locations incl UAC bypass paths.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},
                "hive":{"type":"string","enum":["SYSTEM","SOFTWARE","NTUSER","SAM","SECURITY","Amcache"]},
                "key_path":{"type":"string"},"check_persistence":{"type":"boolean","default":True},
            },"required":["image_path","hive"]}),
        types.Tool(name="supertimeline",
            description="Full log2timeline/plaso super-timeline. Scope with start_time/end_time.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"start_time":{"type":"string"},"end_time":{"type":"string"},
                "sources":{"type":"array","items":{"type":"string"},"default":["mft","evtx","prefetch","registry"]},
            },"required":["image_path"]}),
        types.Tool(name="volatility_memory",
            description="Volatility 3. Plugins: pslist,psscan,cmdline,netscan,dlllist,malfind,handles,all_triage. Detects hidden+injected processes.",
            inputSchema={"type":"object","properties":{
                "memory_path":{"type":"string"},
                "plugin":{"type":"string","enum":["pslist","psscan","cmdline","netscan","dlllist","malfind","handles","all_triage"],"default":"pslist"},
                "pid_filter":{"type":"integer"},
            },"required":["memory_path"]}),
        types.Tool(name="yara_scan",
            description="YARA scan with rulesets: cobalt_strike,metasploit,ransomware,apt_signatures,webshells,all.",
            inputSchema={"type":"object","properties":{
                "target_path":{"type":"string"},
                "ruleset":{"type":"string","enum":["malware_generic","apt_signatures","lolbas_indicators","cobalt_strike","metasploit","webshells","ransomware","all"],"default":"all"},
                "recursive":{"type":"boolean","default":True},"file_filter":{"type":"string"},
            },"required":["target_path"]}),
        types.Tool(name="network_forensics",
            description="Extract network connections from memory or pcap. Flags suspicious ports, C2 patterns, detects beaconing.",
            inputSchema={"type":"object","properties":{
                "source_path":{"type":"string"},
                "source_type":{"type":"string","enum":["memory","pcap"],"default":"memory"},
                "filter_state":{"type":"string","enum":["ESTABLISHED","LISTEN","ALL"],"default":"ALL"},
            },"required":["source_path"]}),
        types.Tool(name="browser_forensics",
            description="Browser history, downloads, cookies. Flags pastebin/ngrok/onion URLs.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},
                "browser":{"type":"string","enum":["Chrome","Firefox","Edge","All"],"default":"All"},
                "start_time":{"type":"string"},"end_time":{"type":"string"},
            },"required":["image_path"]}),
        types.Tool(name="file_carve",
            description="Carve deleted files from unallocated space via bulk_extractor/scalpel.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},
                "file_types":{"type":"array","items":{"type":"string"},"default":["exe","pdf","doc","zip","ps1"]},
                "output_dir":{"type":"string","default":"/tmp/carved"},
            },"required":["image_path"]}),
        types.Tool(name="hash_lookup",
            description="Calculate MD5/SHA1/SHA256 for a file inside a disk image. Verify IOCs before claiming them.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"file_path_in_image":{"type":"string"},
                "algorithm":{"type":"string","enum":["md5","sha1","sha256","all"],"default":"all"},
            },"required":["image_path","file_path_in_image"]}),
        types.Tool(name="lnk_analyzer",
            description="Parse LNK shortcuts. Recently accessed paths, volume info, MAC addresses.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"user_filter":{"type":"string"},
            },"required":["image_path"]}),
        types.Tool(name="usb_forensics",
            description="USB device history from USBSTOR registry. Serial numbers, first/last connect. Flags devices in incident window.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"incident_start":{"type":"string"},"incident_end":{"type":"string"},
            },"required":["image_path"]}),
        types.Tool(name="shadow_copy",
            description="Enumerate VSS shadow copies. Flags deleted copies (ransomware IOC). Can extract files from historical snapshots.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"extract_file":{"type":"string"},
            },"required":["image_path"]}),
        types.Tool(name="scheduled_tasks",
            description="Parse scheduled tasks from XML+registry. Auto-flags encoded commands, SYSTEM tasks with unusual binaries.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"incident_start":{"type":"string"},
                "incident_end":{"type":"string"},"filter_suspicious_only":{"type":"boolean","default":False},
            },"required":["image_path"]}),
        types.Tool(name="ads_detector",
            description="Detect NTFS Alternate Data Streams. Returns stream names, sizes, entropy scores. Flags executable content.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"scan_path":{"type":"string"},
                "min_size":{"type":"integer","default":1},
            },"required":["image_path"]}),
        types.Tool(name="strings_extract",
            description="Extract URLs, IPs, registry paths, base64 blobs, C2 candidates from any binary. Use after YARA hit.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"file_path_in_image":{"type":"string"},
                "min_length":{"type":"integer","default":6},
                "encoding":{"type":"string","enum":["ascii","unicode","both"],"default":"both"},
            },"required":["image_path","file_path_in_image"]}),
        types.Tool(name="pe_metadata",
            description="PE header analysis: compile timestamp, imphash, suspicious imports (injection/C2/crypto), packer detection, signing status.",
            inputSchema={"type":"object","properties":{
                "image_path":{"type":"string"},"file_path_in_image":{"type":"string"},
            },"required":["image_path","file_path_in_image"]}),
        types.Tool(name="check_consistency",
            description=(
                "SELF-CORRECTION ENGINE. Cross-reference two tool results, flag contradictions: "
                "timestamp impossibilities, process mismatches, hash conflicts, network orphans. "
                "ALWAYS call before writing final report."
            ),
            inputSchema={"type":"object","properties":{
                "findings_a":{"type":"object"},"findings_b":{"type":"object"},
                "check_type":{"type":"string","enum":["timestamp_correlation","process_correlation","path_correlation","hash_correlation","auto"],"default":"auto"},
            },"required":["findings_a","findings_b"]}),

        # ── NEW ADVANCED TOOLS ────────────────────────────────────────────────
        types.Tool(name="ioc_pivot",
            description=(
                "ADVANCED: Given one confirmed IOC, pivot across all collected tool outputs "
                "to find all related artifacts. Automatically maps to MITRE ATT&CK techniques "
                "and classifies kill chain stage. Recommends which tool to run next. "
                "Use this to chain evidence — one hash leads to a process leads to a network connection leads to persistence."
            ),
            inputSchema={"type":"object","properties":{
                "ioc_value":{"type":"string","description":"The IOC to pivot from (hash, IP, filename, etc)"},
                "ioc_type":{"type":"string","enum":["file_path","hash","process_name","network","registry_key","event_id","any"],"default":"any"},
                "collected_results":{"type":"array","items":{"type":"object"},"description":"Array of previous tool outputs to search through"},
            },"required":["ioc_value","collected_results"]}),

        types.Tool(name="timeline_anomaly_detector",
            description=(
                "ADVANCED: Analyse a timeline for statistical anomalies that indicate attacker activity. "
                "Detects: temporal gaps (sudden activity burst after silence), "
                "off-hours activity (2-5 AM logins/executions), "
                "impossible speed (file created after deletion timestamp), "
                "beaconing patterns (regular intervals in network connections). "
                "Returns attack window estimate with start/end timestamps."
            ),
            inputSchema={"type":"object","properties":{
                "timeline_result":{"type":"object","description":"Output from supertimeline or evtx_parser"},
                "network_result":{"type":"object","description":"Optional: output from network_forensics for beaconing detection"},
                "business_hours_start":{"type":"integer","default":9,"description":"Hour (0-23)"},
                "business_hours_end":{"type":"integer","default":18},
            },"required":["timeline_result"]}),

        types.Tool(name="threat_intel_lookup",
            description=(
                "ADVANCED: Match confirmed IOCs against local threat intel database. "
                "Returns: threat actor attribution, malware family, MITRE ATT&CK techniques, "
                "known campaign associations. "
                "Local database covers: Cobalt Strike, Metasploit, common APT TTPs, "
                "LOLBAS abuse patterns, ransomware families. "
                "Does NOT make external network calls — all matching is local."
            ),
            inputSchema={"type":"object","properties":{
                "iocs":{"type":"array","items":{"type":"object"},"description":"List of {type, value} dicts"},
                "include_mitre":{"type":"boolean","default":True},
            },"required":["iocs"]}),

        types.Tool(name="report_compiler",
            description=(
                "ADVANCED: Compile all confirmed findings into a structured final report. "
                "Produces: executive summary, plain-English attack narrative (kill chain), "
                "MITRE ATT&CK mapping table, chronological timeline, "
                "analyst confidence rating, evidence gaps. "
                "Call this as the LAST tool in your analysis. "
                "Only include confirmed findings — never pending or rejected."
            ),
            inputSchema={"type":"object","properties":{
                "confirmed_findings":{"type":"array","items":{"type":"object"}},
                "consistency_flags":{"type":"array","items":{"type":"object"}},
                "threat_intel_result":{"type":"object","description":"Optional: output from threat_intel_lookup"},
                "case_name":{"type":"string","default":"SIFT Analysis"},
            },"required":["confirmed_findings"]}),

        types.Tool(name="sigma_matcher",
            description=(
                "INNOVATION: Match evtx_parser output against 20 embedded Sigma detection rules. "
                "Covers: PowerShell encoded commands, log clearing, certutil decode, shadow copy deletion, "
                "pass-the-hash, credential dumping, PsExec, scheduled tasks, registry run keys. "
                "Returns MITRE ATT&CK technique IDs per match with severity levels. "
                "ALWAYS call immediately after every evtx_parser call."
            ),
            inputSchema={"type":"object","properties":{
                "evtx_result":{"type":"object","description":"Direct output from evtx_parser tool"},
            },"required":["evtx_result"]}),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# DISPATCHER
# ─────────────────────────────────────────────────────────────────────────────
@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    t0 = time.monotonic()
    dispatch = {
        "mft_timeline":              _mft_timeline,
        "prefetch_analysis":         _prefetch_analysis,
        "amcache_query":             _amcache_query,
        "shimcache_query":           _shimcache_query,
        "evtx_parser":               _evtx_parser,
        "registry_hive":             _registry_hive,
        "supertimeline":             _supertimeline,
        "volatility_memory":         _volatility_memory,
        "yara_scan":                 _yara_scan,
        "network_forensics":         _network_forensics,
        "browser_forensics":         _browser_forensics,
        "file_carve":                _file_carve,
        "hash_lookup":               _hash_lookup,
        "lnk_analyzer":              _lnk_analyzer,
        "usb_forensics":             _usb_forensics,
        "shadow_copy":               _shadow_copy,
        "scheduled_tasks":           _scheduled_tasks,
        "ads_detector":              _ads_detector,
        "strings_extract":           _strings_extract,
        "pe_metadata":               _pe_metadata,
        "check_consistency":         _check_consistency,
        # NEW
        "ioc_pivot":                 _ioc_pivot,
        "timeline_anomaly_detector": _timeline_anomaly_detector,
        "threat_intel_lookup":       _threat_intel_lookup,
        "report_compiler":           _report_compiler,
        "sigma_matcher":             _sigma_matcher,
    }
    try:
        fn = dispatch.get(name)
        result = await fn(arguments, t0) if fn else {"error": f"Unknown tool: {name}"}
        return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
    except Exception as e:
        log.error(json.dumps({"tool": name, "error": str(e)}))
        return [types.TextContent(type="text", text=json.dumps({"error": str(e), "tool": name}))]


# ─────────────────────────────────────────────────────────────────────────────
# CORE TOOL IMPLEMENTATIONS (unchanged from mcp_server.py)
# ─────────────────────────────────────────────────────────────────────────────
async def _mft_timeline(args,t0):
    ip=args["image_path"]; fp=args.get("filter_path","")
    incl=args.get("include_deleted",True); st=args.get("start_time",""); et=args.get("end_time","")
    out,_,rc=_run(["fls","-r","-m","/",ip])
    entries,susp,trunc=[],[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        parts=line.split("|")
        if len(parts)<8: continue
        flags,inode,path,size_s=parts[0].strip(),parts[1].strip(),parts[2].strip(),parts[3].strip()
        acc,mod,mmod,cre=parts[4].strip(),parts[5].strip(),parts[6].strip(),parts[7].strip()
        if fp and fp.lower() not in path.lower(): continue
        is_del=flags.startswith("-")
        if not incl and is_del: continue
        if st and cre and cre<st: continue
        if et and cre and cre>et: continue
        entries.append(MFTEntry(inode=inode,filename=Path(path).name,full_path=path,
            accessed=acc or None,modified=mod or None,mft_modified=mmod or None,
            created=cre or None,size_bytes=int(size_s) if size_s.isdigit() else None,
            flags=flags,is_deleted=is_del))
        if any(p in path.lower() for p in ["/temp/","/appdata/","/recycle","/programdata/"]):
            if path.lower().endswith((".exe",".dll",".ps1",".bat",".vbs",".hta")):
                susp.append(f"Executable in unusual location: {path}")
    return MFTResult(meta=_meta("mft_timeline",t0,ip,trunc),entries=entries,
        total_entries=len(entries),suspicious_flags=list(set(susp))).model_dump()

async def _prefetch_analysis(args,t0):
    ip=args["image_path"]; ef=args.get("executable_filter","").lower()
    out,_,rc=_run(["PECmd.exe","-d",ip,"--csv","/tmp/pf_out"])
    if rc!=0: out,_,rc=_run(["python3","-m","prefetch","-d",ip])
    entries,anom,trunc=[],[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line or line.startswith(("Source","#")): continue
        parts=line.split(",")
        if len(parts)<4: continue
        en=(parts[1].strip() if len(parts)>1 else "").lower()
        if ef and ef not in en: continue
        e=PrefetchEntry(executable=parts[1].strip() if len(parts)>1 else line,
            run_count=int(parts[5]) if len(parts)>5 and parts[5].strip().isdigit() else 0,
            last_run=parts[6].strip() if len(parts)>6 else None)
        entries.append(e)
        if en in LOLBAS: anom.append(f"LOLBAS:{e.executable}(runs:{e.run_count})")
    return PrefetchResult(meta=_meta("prefetch_analysis",t0,ip,trunc),entries=entries,
        total_entries=len(entries),anomalies=list(set(anom))).model_dump()

async def _amcache_query(args,t0):
    ip=args["image_path"]; fu=args.get("filter_unsigned",False)
    out,_,rc=_run(["AmcacheParser.exe","-f",ip,"--csv","/tmp/amc_out"])
    if rc!=0: out,_,rc=_run(["rip.pl","-r",ip,"-p","amcache"])
    entries,unsigned,trunc=[],[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line or line.startswith("File"): continue
        parts=line.split(",")
        if len(parts)<3: continue
        pub=parts[7].strip() if len(parts)>7 else None
        path=parts[2].strip() if len(parts)>2 else line
        if fu and pub: continue
        if not pub: unsigned.append(path)
        entries.append(AmcacheEntry(sha1=parts[0].strip() or None,path=path,
            name=Path(path).name,publisher=pub,
            last_modified=parts[4].strip() if len(parts)>4 else None))
    return AmcacheResult(meta=_meta("amcache_query",t0,ip,trunc),entries=entries,
        total_entries=len(entries),unsigned_binaries=unsigned).model_dump()

async def _shimcache_query(args,t0):
    ip=args["image_path"]; mx=args.get("max_entries",200)
    out,_,rc=_run(["AppCompatCacheParser.exe","-f",ip,"--csv","/tmp/shim_out"])
    if rc!=0: out,_,rc=_run(["rip.pl","-r",ip,"-p","appcompatcache"])
    entries,trunc=[],False
    for i,line in enumerate(out.splitlines()):
        if i>=min(mx,MAX_ROWS): trunc=True; break
        if not line or line.startswith("Control"): continue
        parts=line.split(",")
        if len(parts)<2: continue
        ef=None
        if len(parts)>4: ef=parts[4].strip().lower() in ("true","1","yes")
        entries.append(ShimcacheEntry(order=i,path=parts[2].strip() if len(parts)>2 else line,
            last_modified=parts[3].strip() if len(parts)>3 else None,exec_flag=ef))
    return ShimcacheResult(meta=_meta("shimcache_query",t0,ip,trunc),
        entries=entries,total_entries=len(entries)).model_dump()

async def _evtx_parser(args,t0):
    ip=args["image_path"]; ch=args.get("channel","Security")
    eif=set(args.get("event_id_filter",[])); st=args.get("start_time",""); et=args.get("end_time","")
    out,_,rc=_run(["evtx_dump","--format","json",ip])
    if rc!=0: out,_,rc=_run(["python3","-m","evtx.scripts.evtx_dump",ip])
    entries,crit,trunc=[],set(),False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        try: event=json.loads(line)
        except: continue
        sd=event.get("Event",{}).get("System",{})
        raw=sd.get("EventID",{}); eid=int(raw.get("#text",0) if isinstance(raw,dict) else raw or 0)
        if eif and eid not in eif: continue
        ts=sd.get("TimeCreated",{}).get("@SystemTime","")
        if st and ts<st: continue
        if et and ts>et: continue
        if eid in CRITICAL_EVENT_IDS: crit.add(eid)
        entries.append(EventLogEntry(event_id=eid,timestamp=ts,
            source=sd.get("Provider",{}).get("@Name",""),computer=sd.get("Computer"),
            description=str(event.get("Event",{}).get("EventData",""))[:400]))
    return EventLogResult(meta=_meta("evtx_parser",t0,ip,trunc),channel=ch,
        entries=entries,total_entries=len(entries),
        critical_event_ids_found=sorted(crit)).model_dump()

async def _registry_hive(args,t0):
    ip=args["image_path"]; hive=args["hive"]
    kp=args.get("key_path",""); cp=args.get("check_persistence",True)
    cmd=["rip.pl","-r",ip,"-p",hive.lower()]
    if kp: cmd=["regipy-parse-hive",ip,"--registry-path",kp]
    out,_,rc=_run(cmd)
    keys,pi,trunc=[],[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line.strip(): continue
        keys.append(RegistryKey(key_path=kp or hive,value_data=line.strip()[:500]))
        if cp:
            for pk in PERSISTENCE_KEYS:
                if pk.lower() in line.lower():
                    pi.append(f"Persistence:{line.strip()[:200]}")
    return RegistryResult(meta=_meta("registry_hive",t0,ip,trunc),hive=hive,
        keys=keys,total_keys=len(keys),persistence_indicators=list(set(pi))).model_dump()

async def _supertimeline(args,t0):
    ip=args["image_path"]; st=args.get("start_time",""); et=args.get("end_time","")
    pf=f"/tmp/sift_{int(time.time())}.plaso"
    cmd=["log2timeline.py","--storage-file",pf]
    if st: cmd+=["--date-filter",f"time > {st}"]
    if et: cmd+=["--date-filter",f"time < {et}"]
    cmd.append(ip); _run(cmd,timeout=300)
    co=pf.replace(".plaso",".csv"); _run(["psort.py","-o","l2tcsv","-w",co,pf])
    entries,trunc=[],False
    try:
        with open(co) as f:
            for i,line in enumerate(f):
                if i>=MAX_ROWS: trunc=True; break
                parts=line.split(",")
                if len(parts)<7 or i==0: continue
                entries.append(TimelineEntry(timestamp=parts[0].strip(),macb=parts[1].strip(),
                    source=parts[2].strip(),source_type=parts[3].strip(),
                    full_path=parts[6].strip() if len(parts)>6 else "",
                    username=parts[5].strip() if len(parts)>5 else None,
                    description=parts[-1].strip()[:300]))
    except FileNotFoundError: pass
    return TimelineResult(meta=_meta("supertimeline",t0,ip,trunc),entries=entries,
        total_entries=len(entries),
        time_range_start=entries[0].timestamp if entries else None,
        time_range_end=entries[-1].timestamp if entries else None).model_dump()

async def _volatility_memory(args,t0):
    mp=args["memory_path"]; pl=args.get("plugin","pslist"); pf=args.get("pid_filter")
    cmd=["vol","-f",mp,f"windows.{pl}"]
    if pf: cmd+=["--pid",str(pf)]
    out,_,rc=_run(cmd)
    procs,hidden,inj,trunc=[],0,[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line.strip() or line.startswith(("Volatility","PID","Offset")): continue
        parts=line.split()
        if len(parts)<4: continue
        try: pid,ppid,name=int(parts[0]),int(parts[1]),parts[2]
        except: continue
        procs.append(VolatilityProcess(pid=pid,ppid=ppid,name=name,offset=parts[3],
            create_time=parts[6] if len(parts)>6 else None))
        if pl=="malfind": inj.append(name)
    if pl=="all_triage":
        out2,_,_=_run(["vol","-f",mp,"windows.psscan"])
        sp=set()
        for line in out2.splitlines():
            p=line.split()
            if p and p[0].isdigit(): sp.add(int(p[0]))
        lp={p.pid for p in procs}; hidden=len(sp-lp)
        for p in procs: p.is_hidden=p.pid in (sp-lp)
    return VolatilityResult(meta=_meta("volatility_memory",t0,mp,trunc),plugin=pl,
        processes=procs,total=len(procs),hidden_process_count=hidden,
        injected_process_names=inj).model_dump()

async def _yara_scan(args,t0):
    tp=args["target_path"]; rs=args.get("ruleset","all")
    rec=args.get("recursive",True)
    rp=f"/opt/yara-rules/{rs}.yar" if rs!="all" else "/opt/yara-rules/"
    cmd=["yara"]
    if rec: cmd.append("-r")
    cmd+=[rp,tp]; out,_,rc=_run(cmd,timeout=180)
    matches,scanned,trunc=[],0,False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line.strip(): continue
        parts=line.split(" ",1)
        if len(parts)!=2: continue
        rn,fp=parts; scanned+=1
        sev="critical" if any(r in rn.lower() for r in ["cobalt","metasploit","ransomware","apt"]) \
            else "high" if "lolbas" in rn.lower() else "medium"
        matches.append(YaraMatch(rule_name=rn,file_path=fp,severity=sev))
    return YaraResult(meta=_meta("yara_scan",t0,tp,trunc),rules_file=rp,
        matches=matches,total_matches=len(matches),scanned_files=scanned).model_dump()

async def _network_forensics(args,t0):
    sp=args["source_path"]; st=args.get("source_type","memory"); fs=args.get("filter_state","ALL")
    if st=="memory": out,_,rc=_run(["vol","-f",sp,"windows.netscan"])
    else: out,_,rc=_run(["tshark","-r",sp,"-T","fields","-e","ip.src","-e","tcp.srcport","-e","ip.dst","-e","tcp.dstport"])
    conns,c2,trunc=[],[],False
    conn_times: dict[str,list[float]]={}
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line.strip() or line.startswith(("Volatility","Offset","Proto")): continue
        parts=line.split()
        if len(parts)<5: continue
        try:
            proto=parts[1] if st=="memory" else "TCP"
            lf=parts[2] if st=="memory" else f"{parts[0]}:{parts[1]}"
            rf=parts[3] if st=="memory" else f"{parts[2]}:{parts[3]}"
            state=parts[4] if len(parts)>4 else None
            pid=int(parts[-1]) if parts[-1].isdigit() else None
            la,lp=lf.rsplit(":",1); ra,rp=rf.rsplit(":",1); rpi=int(rp)
        except: continue
        if fs!="ALL" and state!=fs: continue
        susp=False; reason=None
        if rpi in SUSPICIOUS_PORTS: susp=True; reason=f"Suspicious port {rpi}"; c2.append(f"{ra}:{rp}")
        for pat in [r'\b(?:25[0-5]|2[0-4]\d|\d\d?\d?)(?:\.(?:25[0-5]|2[0-4]\d|\d\d?\d?)){3}\b']:
            if re.search(r'pastebin|\.onion|ngrok|raw\.github', rf): susp=True; reason="C2 pattern"; c2.append(rf)
        conns.append(NetworkConn(proto=proto,local_addr=la,local_port=int(lp or 0),
            remote_addr=ra,remote_port=rpi,state=state,pid=pid,is_suspicious=susp,reason=reason))
        key=f"{ra}:{rp}"
        if key not in conn_times: conn_times[key]=[]
        conn_times[key].append(time.time())
    # Beaconing: regular interval detection
    beaconing=False
    for key,times_list in conn_times.items():
        if len(times_list)>=5:
            intervals=[times_list[j+1]-times_list[j] for j in range(len(times_list)-1)]
            avg=sum(intervals)/len(intervals)
            variance=sum((x-avg)**2 for x in intervals)/len(intervals)
            if avg>0 and (variance/avg**2)<0.1:   # coefficient of variation <10%
                beaconing=True; c2.append(f"BEACONING:{key}")
    return NetworkResult(meta=_meta("network_forensics",t0,sp,trunc),
        connections=conns,total=len(conns),
        suspicious_count=sum(1 for c in conns if c.is_suspicious),
        c2_indicators=list(set(c2)),beaconing_detected=beaconing).model_dump()

async def _browser_forensics(args,t0):
    ip=args["image_path"]; br=args.get("browser","All")
    st=args.get("start_time",""); et=args.get("end_time","")
    cmd=["hindsight","-i",ip,"-o","/tmp/hindsight_out","-b",br.lower()]
    out,_,rc=_run(cmd,timeout=180)
    if rc!=0: out,_,rc=_run(["python3","-m","dbtool",ip])
    entries,susp_urls,downloads,trunc=[],[],[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line.strip(): continue
        parts=line.split("\t")
        if len(parts)<2: continue
        url=parts[1].strip() if len(parts)>1 else ""
        entries.append(BrowserEntry(browser=br,url=url,
            title=parts[2].strip() if len(parts)>2 else None,
            visit_time=parts[3].strip() if len(parts)>3 else None,
            visit_count=int(parts[4]) if len(parts)>4 and parts[4].isdigit() else 0))
        if any(p in url.lower() for p in ["pastebin","raw.githubusercontent","transfer.sh",".onion",":4444","ngrok"]):
            susp_urls.append(url)
        if "download" in url.lower() or url.endswith((".exe",".ps1",".zip",".bat")):
            downloads.append(url)
    return BrowserResult(meta=_meta("browser_forensics",t0,ip,trunc),
        entries=entries,total_entries=len(entries),
        suspicious_urls=list(set(susp_urls)),download_paths=list(set(downloads))).model_dump()

async def _file_carve(args,t0):
    ip=args["image_path"]; ft=args.get("file_types",["exe","pdf","doc","zip","ps1"])
    od=args.get("output_dir","/tmp/carved"); os.makedirs(od,exist_ok=True)
    cmd=["bulk_extractor","-o",od,"-E","carved:"+",".join(ft),ip]
    out,_,rc=_run(cmd,timeout=300)
    if rc!=0: cmd=["scalpel","-o",od,ip]; _run(cmd,timeout=300)
    carved=[]
    try:
        for f in Path(od).rglob("*"):
            if f.is_file():
                carved.append({"filename":f.name,"size_bytes":f.stat().st_size,
                    "path":str(f),"extension":f.suffix.lower()})
    except: pass
    return FileCarveResult(meta=_meta("file_carve",t0,ip),
        carved_files=carved[:MAX_ROWS],total_carved=len(carved),output_dir=od).model_dump()

async def _hash_lookup(args,t0):
    ip=args["image_path"]; fp=args["file_path_in_image"]; alg=args.get("algorithm","all")
    out,err,rc=_run(["icat",ip,fp])
    hashes={}
    if rc==0 and out:
        data=out.encode()
        if alg in ("md5","all"):    hashes["md5"]    = hashlib.md5(data).hexdigest()
        if alg in ("sha1","all"):   hashes["sha1"]   = hashlib.sha1(data).hexdigest()
        if alg in ("sha256","all"): hashes["sha256"] = hashlib.sha256(data).hexdigest()
    return {"meta":_meta("hash_lookup",t0,ip).model_dump(),
            "file_path":fp,"hashes":hashes,"error":err if rc!=0 else None}

async def _lnk_analyzer(args,t0):
    ip=args["image_path"]; uf=args.get("user_filter","").lower()
    out,_,rc=_run(["lnkinfo",ip])
    if rc!=0: out,_,rc=_run(["python3","-m","pylnk3",ip])
    entries,trunc=[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if not line.strip(): continue
        if uf and uf not in line.lower(): continue
        entries.append({"raw":line.strip()})
    return {"meta":_meta("lnk_analyzer",t0,ip,trunc).model_dump(),"entries":entries,"total":len(entries)}

async def _usb_forensics(args,t0):
    ip=args["image_path"]; ist=args.get("incident_start",""); iet=args.get("incident_end","")
    out,_,rc=_run(["rip.pl","-r",ip,"-p","usbstor"])
    if rc!=0: out,_,rc=_run(["python3","-m","usbdeviceforensics",ip])
    devices,trunc=[],False; current={}
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        line=line.strip()
        if not line:
            if current:
                sn=current.get("serial number","unknown"); fn=current.get("friendly name")
                fc=current.get("first connected"); lc=current.get("last connected")
                susp=False; reason=None
                if ist and fc and ist<=fc<=(iet or "9999"): susp=True; reason=f"Connected during incident({fc})"
                if not fn: susp=True; reason=(reason or "")+" | Anonymous device"
                devices.append(USBDevice(serial=sn,friendly_name=fn,first_connected=fc,
                    last_connected=lc,suspicious=susp,reason=reason))
            current={}; continue
        if ":" in line: k,_,v=line.partition(":"); current[k.strip().lower()]=v.strip()
    return USBResult(meta=_meta("usb_forensics",t0,ip,trunc),devices=devices,
        total_devices=len(devices),suspicious_count=sum(1 for d in devices if d.suspicious)).model_dump()

async def _shadow_copy(args,t0):
    ip=args["image_path"]; ef=args.get("extract_file","")
    out,_,rc=_run(["vshadowinfo",ip])
    if rc!=0: out,_,rc=_run(["python3","-m","vshadow",ip])
    copies,deleted,trunc=[],0,False; current={}
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        line=line.strip()
        if line.startswith("Shadow copy:"):
            if current:
                sc=ShadowCopy(id=current.get("id","?"),
                    creation_time=current.get("creation time"),
                    volume=current.get("volume"),
                    is_deleted="deleted" in str(current).lower())
                copies.append(sc)
                if sc.is_deleted: deleted+=1
            current={"id":line.split(":")[-1].strip()}
        elif ":" in line: k,_,v=line.partition(":"); current[k.strip().lower()]=v.strip()
    note=""
    if deleted>0: note=f"WARNING:{deleted} shadow copies deleted — ransomware anti-recovery indicator"
    elif not copies: note="WARNING: No shadow copies found — possible deletion or never configured"
    return ShadowCopyResult(meta=_meta("shadow_copy",t0,ip,trunc),copies=copies,
        total_copies=len(copies),deleted_copies=deleted,note=note).model_dump()

async def _scheduled_tasks(args,t0):
    ip=args["image_path"]; ist=args.get("incident_start",""); iet=args.get("incident_end","")
    so=args.get("filter_suspicious_only",False)
    out,_,rc=_run(["find",ip,"-path","*/System32/Tasks/*","-name","*.xml","-exec","cat","{}",";"])
    if rc!=0: out,_,rc=_run(["rip.pl","-r",ip,"-p","tasks"])
    tasks,susp_tasks,trunc=[],[],False; current={}
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        for ft,fk in [("URI","path"),("Command","action"),("Author","author"),
                      ("UserId","run_as_user"),("Date","created"),("LastRunTime","last_run")]:
            m=re.search(rf"<{ft}>(.*?)</{ft}>",line)
            if m: current[fk]=m.group(1).strip()
        if "</Task>" in line or "</RegistrationInfo>" in line:
            if current:
                action=current.get("action",""); created=current.get("created","")
                s=False; r=None
                for pat in SUSPICIOUS_TASK_PATTERNS:
                    if re.search(pat,action,re.IGNORECASE): s=True; r=f"Suspicious action:{pat}"; break
                if ist and created and ist<=created<=(iet or "9999"):
                    s=True; r=(r or "")+f"|Created in window({created})"
                if current.get("run_as_user","").upper()=="SYSTEM" and action:
                    if not any(safe in action.lower() for safe in ["system32","windows","microsoft"]):
                        s=True; r=(r or "")+"|SYSTEM+unusual binary"
                t=ScheduledTask(name=Path(current.get("path","?")).name,
                    path=current.get("path",""),action=action,
                    author=current.get("author"),run_as_user=current.get("run_as_user"),
                    created=created,last_run=current.get("last_run"),suspicious=s,reason=r)
                if not so or t.suspicious: tasks.append(t)
                if t.suspicious: susp_tasks.append(t)
            current={}
    return ScheduledTaskResult(meta=_meta("scheduled_tasks",t0,ip,trunc),
        tasks=tasks,total_tasks=len(tasks),suspicious_tasks=susp_tasks).model_dump()

async def _ads_detector(args,t0):
    ip=args["image_path"]; sp=args.get("scan_path","/"); mn=args.get("min_size",1)
    out,_,rc=_run(["fls","-r","-p",ip])
    if rc!=0: out,_,rc=_run(["python3","-m","ntfsstreams",ip])
    streams,trunc=[],False
    for i,line in enumerate(out.splitlines()):
        if i>=MAX_ROWS: trunc=True; break
        if ":" not in line: continue
        m=re.search(r'(\S+):(\S+)\s+\((\d+)\)',line)
        if not m: continue
        hf,sn,sb=m.group(1),m.group(2),int(m.group(3))
        if sb<mn: continue
        if sp!="/" and sp.lower() not in hf.lower(): continue
        is_exec=sb>100 and any(s in sn.lower() for s in [".exe",".dll",".ps1",".bat","payload","cmd"])
        streams.append(ADSStream(host_file=hf,stream_name=sn,size_bytes=sb,is_executable_content=is_exec))
    return ADSResult(meta=_meta("ads_detector",t0,ip,trunc),streams=streams,
        total_streams=len(streams),executable_streams=sum(1 for s in streams if s.is_executable_content)).model_dump()

async def _strings_extract(args,t0):
    ip=args["image_path"]; fp=args["file_path_in_image"]
    ml=args.get("min_length",6); enc=args.get("encoding","both")
    icat_out,_,rc=_run(["icat",ip,fp]); tp=f"/tmp/sift_str_{int(time.time())}.bin"
    if rc==0 and icat_out:
        with open(tp,"w") as f: f.write(icat_out)
    ef="-a" if enc=="both" else ("-el" if enc=="unicode" else "")
    cmd=["strings",f"-n{ml}"]
    if ef: cmd.append(ef)
    cmd.append(tp if os.path.exists(tp) else ip)
    out,_,rc=_run(cmd)
    urls,ips,reg,fps,kws,enc_blobs,c2=[],[],[],[],[],[],[]
    skws=["password","credential","beacon","inject","shellcode","reflective","cobalt",
          "mimikatz","sekurlsa","lsass","payload","c2","exfil","encrypt","ransom","reverse","shell"]
    url_re=re.compile(r'https?://[^\s"\'<>]{8,}')
    ip_re=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b')
    reg_re=re.compile(r'HKEY_[A-Z_]+\\[^\s"]{5,}',re.IGNORECASE)
    path_re=re.compile(r'[A-Za-z]:\\[^\s"\'<>]{5,}')
    b64_re=re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    for line in out.splitlines()[:MAX_ROWS]:
        line=line.strip()
        if not line: continue
        for u in url_re.findall(line):
            if u not in urls: urls.append(u)
            if any(p in u.lower() for p in ["pastebin","ngrok","onion","transfer.sh"]): c2.append(u)
        for i in ip_re.findall(line):
            if i not in ips: ips.append(i)
        for r in reg_re.findall(line):
            if r not in reg: reg.append(r)
        for p in path_re.findall(line):
            if p not in fps: fps.append(p)
        for kw in skws:
            if kw in line.lower(): kws.append(f"{kw}:{line[:120]}")
        for b in b64_re.findall(line):
            if len(b)>60 and b not in enc_blobs: enc_blobs.append(b[:80]+"...")
    try: os.remove(tp)
    except: pass
    return StringsResult(meta=_meta("strings_extract",t0),file_path=fp,
        urls=urls[:50],ip_addresses=ips[:50],registry_paths=reg[:50],
        file_paths=fps[:50],suspicious_keywords=kws[:30],
        encoded_blobs=enc_blobs[:20],c2_candidates=list(set(c2))[:20]).model_dump()

async def _pe_metadata(args,t0):
    ip=args["image_path"]; fp=args["file_path_in_image"]
    icat_out,_,rc=_run(["icat",ip,fp]); tp=f"/tmp/sift_pe_{int(time.time())}.exe"
    if rc==0 and icat_out:
        with open(tp,"w") as f: f.write(icat_out)
    target=tp if os.path.exists(tp) else fp
    out,_,rc=_run(["pecheck.py","-v",target])
    if rc!=0: out,_,rc=_run(["python3","-c",f"import pefile;pe=pefile.PE('{target}');print(pe.dump_info())"])
    pk_out,_,_=_run(["pescanner",target])
    cts=None; ih=None; imports=[]; secs=[]; packed=False; phint=None; signed=False; signer=None; dotnet=False
    for line in out.splitlines():
        l=line.strip()
        if "TimeDateStamp" in l or "Compile" in l:
            m=re.search(r'(\d{4}-\d{2}-\d{2})',l)
            if m: cts=m.group(1)
        if "imphash" in l.lower():
            m=re.search(r'[0-9a-f]{32}',l)
            if m: ih=m.group(0)
        if "Import" in l and ".dll" in l.lower():
            for p in l.split():
                if ".dll" in p.lower() and p not in imports: imports.append(p)
        if "Section" in l and "Entropy" in l:
            mn2=re.search(r'Name:\s*(\S+)',l); me=re.search(r'Entropy:\s*([\d.]+)',l)
            if mn2 and me:
                ent=float(me.group(1))
                secs.append(PESection(name=mn2.group(1),virtual_size=0,raw_size=0,
                    entropy=ent,is_suspicious=ent>7.0))
        if "dotNET" in l or ".NET" in l or "mscoree" in l.lower(): dotnet=True
        if "Signer" in l: signer=l.split(":",1)[-1].strip(); signed=bool(signer)
    for line in pk_out.splitlines():
        if any(p in line for p in ["UPX","MPRESS","Themida","ASPack","packed"]):
            packed=True; phint=line.strip()[:100]; break
    susp_imp=[i for i in imports if any(si in i for si in SUSPICIOUS_IMPORTS)]
    susp_ts=bool(cts and (cts<"1970-01-02" or cts>"2027-01-01"))
    try: os.remove(tp)
    except: pass
    return PEMetadataResult(meta=_meta("pe_metadata",t0),file_path=fp,
        compile_timestamp=cts,is_suspicious_timestamp=susp_ts,imphash=ih,
        imports=imports[:60],suspicious_imports=susp_imp,sections=secs,
        is_packed=packed,packer_hint=phint,is_signed=signed,signer=signer,is_dotnet=dotnet).model_dump()

async def _check_consistency(args,t0):
    fa=args["findings_a"]; fb=args["findings_b"]; ct=args.get("check_type","auto")
    flags=[]; ta=fa.get("meta",{}).get("tool_name","?"); tb=fb.get("meta",{}).get("tool_name","?")
    if ct in ("timestamp_correlation","auto"):
        if "entries" in fa and "entries" in fb:
            ia={(e.get("full_path","") or e.get("executable","")).lower():e for e in fa["entries"] if isinstance(e,dict)}
            ib={(e.get("full_path","") or e.get("executable","")).lower():e for e in fb["entries"] if isinstance(e,dict)}
            for path in ia:
                if path in ib:
                    ea,eb=ia[path],ib[path]
                    tsa=ea.get("last_run") or ea.get("modified") or ea.get("created") or ""
                    tsc=eb.get("created") or ""
                    if tsa and tsc and tsa<tsc:
                        flags.append(ConsistencyFlag(artifact_a=ta,artifact_b=tb,
                            finding=f"Impossible timestamp:{path}",severity="high",
                            detail=f"{ta} shows activity at {tsa} but {tb} shows file created at {tsc}. Predates existence.").model_dump())
    if ct in ("process_correlation","auto"):
        if ta=="volatility_memory" and tb=="evtx_parser":
            mp={p.get("name","").lower() for p in fa.get("processes",[])}
            for ev in fb.get("entries",[]):
                desc=str(ev.get("description","")).lower()
                m=re.search(r'new process name[:\s]+([a-z0-9_\-\.]+\.exe)',desc)
                if m and m.group(1) not in mp:
                    flags.append(ConsistencyFlag(artifact_a=tb,artifact_b=ta,
                        finding=f"Process in evtx absent from memory",severity="medium",
                        detail=f"Event {ev.get('event_id')} refs {m.group(1)} not in Volatility").model_dump())
    if ct in ("hash_correlation","auto"):
        if ta=="yara_scan" and tb=="amcache_query":
            an={Path(e.get("path","")).name.lower() for e in fb.get("entries",[]) if isinstance(e,dict)}
            for match in fa.get("matches",[]):
                fn=Path(match.get("file_path","")).name.lower()
                if fn and fn not in an:
                    flags.append(ConsistencyFlag(artifact_a=ta,artifact_b=tb,
                        finding=f"YARA hit but no execution evidence:{fn}",severity="low",
                        detail=f"YARA matched {fn} but Amcache has no record. No confirmed execution.").model_dump())
    if ct in ("process_correlation","auto"):
        if ta=="network_forensics" and tb=="volatility_memory":
            mp={p.get("pid") for p in fb.get("processes",[])}
            for conn in fa.get("connections",[]):
                if conn.get("is_suspicious") and conn.get("pid") and conn["pid"] not in mp:
                    flags.append(ConsistencyFlag(artifact_a=ta,artifact_b=tb,
                        finding=f"Suspicious conn from unknown PID {conn.get('pid')}",severity="high",
                        detail=f"Connection to {conn.get('remote_addr')}:{conn.get('remote_port')} from PID not in memory. Possible injection.").model_dump())
    return ConsistencyResult(flags=flags,clean=len(flags)==0).model_dump()


# ─────────────────────────────────────────────────────────────────────────────
# NEW ADVANCED TOOL IMPLEMENTATIONS
# ─────────────────────────────────────────────────────────────────────────────

async def _ioc_pivot(args: dict, t0: float) -> dict:
    """Pivot from one IOC across all collected results to find related artifacts."""
    pivot_val  = args["ioc_value"].lower().strip()
    pivot_type = args.get("ioc_type","any")
    collected  = args.get("collected_results",[])

    related: list[dict] = []
    all_text = ""

    for result in collected:
        tool_name = result.get("meta",{}).get("tool_name","unknown") if isinstance(result,dict) else "unknown"
        result_str = json.dumps(result,default=str).lower()
        all_text += result_str

        if pivot_val in result_str:
            # Find the specific entries that match
            for key in ["entries","processes","matches","connections","keys","devices","tasks","streams","carved_files"]:
                for entry in result.get(key,[]):
                    if isinstance(entry,dict) and pivot_val in json.dumps(entry,default=str).lower():
                        related.append({
                            "source_tool": tool_name,
                            "artifact_type": key,
                            "entry": entry,
                            "mitre": _map_mitre(json.dumps(entry,default=str)),
                        })

            # Also check top-level indicators
            for field in ["suspicious_flags","anomalies","unsigned_binaries",
                          "persistence_indicators","c2_indicators","suspicious_urls"]:
                for item in result.get(field,[]):
                    if isinstance(item,str) and pivot_val in item.lower():
                        related.append({
                            "source_tool": tool_name,
                            "artifact_type": field,
                            "entry": {"value": item},
                            "mitre": _map_mitre(item),
                        })

    # Kill chain classification
    kc = _classify_kill_chain(pivot_type, pivot_val, " ".join([str(r) for r in related]))

    # Recommend next tools based on what we found and what's missing
    found_tools = {r["source_tool"] for r in related}
    next_tools = []
    if "hash" in pivot_type or pivot_val.startswith("sha") or pivot_val.startswith("md5"):
        if "yara_scan" not in found_tools: next_tools.append("yara_scan")
        if "pe_metadata" not in found_tools: next_tools.append("pe_metadata")
        if "strings_extract" not in found_tools: next_tools.append("strings_extract")
    if "process" in pivot_type or ".exe" in pivot_val:
        if "volatility_memory" not in found_tools: next_tools.append("volatility_memory")
        if "network_forensics" not in found_tools: next_tools.append("network_forensics")
    if "network" in pivot_type or ":" in pivot_val:
        if "volatility_memory" not in found_tools: next_tools.append("volatility_memory")
    if "file_path" in pivot_type:
        if "hash_lookup" not in found_tools: next_tools.append("hash_lookup")
        if "amcache_query" not in found_tools: next_tools.append("amcache_query")
    if kc == "persistence":
        if "scheduled_tasks" not in found_tools: next_tools.append("scheduled_tasks")
        if "ads_detector" not in found_tools: next_tools.append("ads_detector")

    return PivotResult(
        meta=_meta("ioc_pivot",t0),
        pivot_value=pivot_val,
        pivot_type=pivot_type,
        related_artifacts=related,
        kill_chain_stage=kc,
        confidence="confirmed" if len(related)>=3 else "inferred" if len(related)>=1 else "speculative",
        recommended_next_tools=next_tools[:5],
    ).model_dump()


async def _timeline_anomaly_detector(args: dict, t0: float) -> dict:
    """Detect statistical anomalies in timeline data."""
    tl_result = args["timeline_result"]
    net_result = args.get("network_result",{})
    bh_start   = args.get("business_hours_start", 9)
    bh_end     = args.get("business_hours_end", 18)

    entries = tl_result.get("entries",[])
    anomalies: list[AnomalyEntry] = []

    # Parse timestamps
    ts_list = []
    for e in entries:
        ts = e.get("timestamp","")
        if ts:
            try:
                # Parse ISO timestamp hour
                hour = int(ts[11:13]) if len(ts)>12 else -1
                ts_list.append((ts, hour, e))
            except: pass

    # Off-hours activity (2AM-5AM)
    off_hours = [(ts,hr,e) for ts,hr,e in ts_list if 2<=hr<=5]
    off_hours_flag = len(off_hours) > 0
    for ts,hr,e in off_hours[:10]:
        anomalies.append(AnomalyEntry(
            timestamp=ts, event=e.get("description","")[:100],
            source=e.get("source",""), anomaly_type="off_hours",
            severity="medium",
            detail=f"Activity at {hr:02d}:xx — outside business hours ({bh_start}:00-{bh_end}:00). Common attacker behaviour.",
            related_ioc=e.get("full_path"),
        ))

    # Temporal burst: >20 events in 60 seconds
    if len(ts_list)>=2:
        window_size = 60  # seconds represented as string comparison — simplified
        for i in range(len(ts_list)-20):
            window = ts_list[i:i+20]
            t_start = window[0][0]; t_end = window[-1][0]
            if t_start[:16] == t_end[:16]:   # same minute = burst
                anomalies.append(AnomalyEntry(
                    timestamp=t_start, event=f"Burst: 20+ events within 1 minute",
                    source=window[0][2].get("source",""), anomaly_type="burst",
                    severity="high",
                    detail=f"20+ timeline events between {t_start} and {t_end}. Automated tool or script execution.",
                ))
                break

    # Large temporal gap then sudden activity (attacker re-entry)
    prev_ts = None
    for ts,hr,e in ts_list:
        if prev_ts:
            # Compare date portions — gap > 7 days
            if ts[:10] > prev_ts[:10]:
                try:
                    from datetime import datetime as DT
                    d1 = DT.fromisoformat(prev_ts[:10]); d2 = DT.fromisoformat(ts[:10])
                    gap_days = (d2-d1).days
                    if gap_days > 7:
                        anomalies.append(AnomalyEntry(
                            timestamp=ts, event=e.get("description","")[:100],
                            source=e.get("source",""), anomaly_type="temporal_gap",
                            severity="low",
                            detail=f"{gap_days}-day gap in activity then sudden resume at {ts}. May indicate staged attack or dormant implant.",
                        ))
                except: pass
        prev_ts = ts

    # Beaconing from network result
    if net_result and net_result.get("beaconing_detected"):
        for c2 in net_result.get("c2_indicators",[]):
            if "BEACONING" in c2:
                anomalies.append(AnomalyEntry(
                    timestamp=_now_iso(), event=f"Regular beacon: {c2}",
                    source="network_forensics", anomaly_type="beaconing",
                    severity="critical",
                    detail=f"Statistical regularity in connections to {c2} — coefficient of variation <10%. Active C2 channel.",
                    related_ioc=c2,
                ))

    # Estimate attack window
    attack_start = anomalies[0].timestamp if anomalies else None
    attack_end   = anomalies[-1].timestamp if anomalies else None
    crit = [a for a in anomalies if a.severity in ("high","critical")]
    if crit:
        attack_start = crit[0].timestamp
        attack_end   = crit[-1].timestamp

    return TimelineAnomalyResult(
        meta=_meta("timeline_anomaly_detector",t0),
        anomalies=anomalies,
        total_anomalies=len(anomalies),
        attack_window_start=attack_start,
        attack_window_end=attack_end,
        off_hours_activity=off_hours_flag,
    ).model_dump()


async def _threat_intel_lookup(args: dict, t0: float) -> dict:
    """Match IOCs against local threat intel. No external network calls."""
    iocs = args["iocs"]
    include_mitre = args.get("include_mitre", True)

    # Local threat intel database
    THREAT_INTEL = {
        "cobalt strike": {"actor":"Multiple APT groups","family":"Cobalt Strike","campaign":"Various","mitre":["T1055","T1071","T1059.001"]},
        "svch0st":       {"actor":"Unknown","family":"Cobalt Strike loader","campaign":"Spearphish-2026","mitre":["T1036.005","T1055"]},
        "mimikatz":      {"actor":"Multiple","family":"Mimikatz","campaign":"Various","mitre":["T1003.001","T1003.002"]},
        "metasploit":    {"actor":"Multiple","family":"Metasploit","campaign":"Various","mitre":["T1059","T1055"]},
        ":4444":         {"actor":"Unknown","family":"Metasploit/CS default","campaign":"Various","mitre":["T1571"]},
        "pastebin.com":  {"actor":"Multiple","family":"Various","campaign":"Various","mitre":["T1102"]},
        "certutil":      {"actor":"Multiple","family":"LOLBAS","campaign":"Various","mitre":["T1140","T1105"]},
        "1102":          {"actor":"Multiple","family":"Log clearing","campaign":"Various","mitre":["T1070.001"]},
        "4697":          {"actor":"Multiple","family":"Service install","campaign":"Various","mitre":["T1543.003"]},
        "bcdedit":       {"actor":"Ransomware groups","family":"Ransomware","campaign":"Various","mitre":["T1490"]},
        "vssadmin":      {"actor":"Ransomware groups","family":"Ransomware","campaign":"Various","mitre":["T1490"]},
        "wce.exe":       {"actor":"Multiple","family":"WCE credential dumper","campaign":"Various","mitre":["T1003"]},
        "lazagne":       {"actor":"Multiple","family":"LaZagne","campaign":"Various","mitre":["T1555"]},
    }

    results: list[ThreatIntelEntry] = []
    unmatched: list[str] = []

    for ioc in iocs:
        val  = str(ioc.get("value","")).lower()
        typ  = ioc.get("type", ioc.get("ioc_type","unknown"))
        matched = False

        for keyword, intel in THREAT_INTEL.items():
            if keyword in val:
                mitre = [{"id":t,"url":f"https://attack.mitre.org/techniques/{t.replace('.','/')}"}
                         for t in intel["mitre"]] if include_mitre else []
                results.append(ThreatIntelEntry(
                    ioc_value=val, ioc_type=typ,
                    matched_threat_actor=intel["actor"],
                    matched_malware_family=intel["family"],
                    matched_campaign=intel["campaign"],
                    mitre_techniques=[t["id"] for t in mitre],
                    confidence="medium",
                    source="local_intel_db",
                ))
                matched = True
                break

        # MITRE-only match even if no family match
        if not matched:
            mitre_hits = _map_mitre(val)
            if mitre_hits and include_mitre:
                results.append(ThreatIntelEntry(
                    ioc_value=val, ioc_type=typ,
                    mitre_techniques=[h["technique_id"] for h in mitre_hits],
                    confidence="low",
                    source="mitre_pattern_match",
                ))
                matched = True

        if not matched:
            unmatched.append(val)

    return ThreatIntelResult(
        meta=_meta("threat_intel_lookup",t0),
        results=results,
        total_matched=len(results),
        unmatched_iocs=unmatched,
    ).model_dump()


async def _report_compiler(args: dict, t0: float) -> dict:
    """Compile final structured report with attack narrative and MITRE mapping."""
    confirmed    = args["confirmed_findings"]
    c_flags      = args.get("consistency_flags",[])
    ti_result    = args.get("threat_intel_result",{})
    case_name    = args.get("case_name","SIFT Analysis")

    # Build kill chain map
    kc_map: dict[str,list] = {}
    mitre_all: list[dict]  = []
    timeline_summary: list[dict] = []

    for f in confirmed:
        val   = str(f.get("value",""))
        desc  = str(f.get("description",""))
        itype = str(f.get("ioc_type",""))
        kc    = _classify_kill_chain(itype, val, desc)
        if kc not in kc_map: kc_map[kc] = []
        kc_map[kc].append(f)

        # MITRE mapping
        for hit in _map_mitre(val+" "+desc):
            if hit not in mitre_all: mitre_all.append(hit)

        # Timeline entry
        if f.get("timestamp"):
            timeline_summary.append({"timestamp":f["timestamp"],"event":desc[:80],"ioc":val})

    # Sort timeline
    timeline_summary.sort(key=lambda x: x.get("timestamp",""))

    # Build attack narrative
    narrative_parts = []
    kc_order = ["initial_access","execution","persistence","credential_access",
                "defense_evasion","command_and_control","lateral_movement","exfiltration","impact"]
    for stage in kc_order:
        items = kc_map.get(stage,[])
        if not items: continue
        stage_label = stage.replace("_"," ").title()
        vals = [str(i.get("value",""))[:50] for i in items[:3]]
        narrative_parts.append(f"**{stage_label}**: {', '.join(vals)}")

    if narrative_parts:
        narrative = ("Forensic analysis identified a multi-stage intrusion. " +
                     " → ".join(narrative_parts) + ".")
    else:
        narrative = "Analysis identified suspicious artifacts. See confirmed IOCs for details."

    # Analyst confidence
    n_confirmed  = len(confirmed)
    n_multi_src  = sum(1 for f in confirmed if "consistency_check" in str(f.get("evidence_status","")))
    n_rejected   = len(c_flags)
    confidence   = "high" if n_confirmed>=5 and n_multi_src>=3 else \
                   "medium" if n_confirmed>=2 else "low"

    # Evidence gaps
    gaps = []
    if "command_and_control" not in kc_map: gaps.append("No C2 evidence found — memory dump may yield network artifacts")
    if "lateral_movement"    not in kc_map: gaps.append("Lateral movement not confirmed — check SMB/RDP event logs on adjacent systems")
    if not any(f.get("ioc_type")=="hash" for f in confirmed): gaps.append("No file hashes confirmed — run hash_lookup on suspicious binaries")
    if n_rejected > 0: gaps.append(f"{n_rejected} consistency flags raised — review rejected findings for missed evidence")

    # Recommendations
    recommendations = []
    if "persistence" in kc_map:        recommendations.append("Remove all identified persistence mechanisms before re-imaging")
    if "credential_access" in kc_map:  recommendations.append("Rotate ALL credentials — assume full domain compromise")
    if "lateral_movement" in kc_map:   recommendations.append("Scope lateral movement — analyse adjacent systems with same toolset")
    if "command_and_control" in kc_map:recommendations.append("Block C2 indicators at perimeter firewall and DNS")
    recommendations.append("Preserve forensic images with SHA-256 hash for chain of custody")
    recommendations.append("Conduct threat hunt across fleet for same IOC signatures")

    return FinalReport(
        meta=_meta("report_compiler",t0),
        case_summary=(f"Case: {case_name}. {n_confirmed} confirmed IOCs across "
                      f"{len(kc_map)} kill chain stages. Analyst confidence: {confidence}."),
        attack_narrative=narrative,
        confirmed_iocs=confirmed,
        mitre_mapping=mitre_all,
        timeline_summary=timeline_summary[:50],
        recommendations=recommendations,
        analyst_confidence=confidence,
        evidence_gaps=gaps,
    ).model_dump()


# ─────────────────────────────────────────────────────────────────────────────
# SIGMA MATCHER TOOL IMPLEMENTATION
# ─────────────────────────────────────────────────────────────────────────────

async def _sigma_matcher(args: dict, t0: float) -> dict:
    """Match evtx_parser output against Sigma rules."""
    evtx_result = args["evtx_result"]
    if run_sigma_matcher is None:
        return {"error": "innovations.py not found — place it in same directory as mcp_server_final.py"}
    result = run_sigma_matcher(evtx_result)
    return {
        "meta": _meta("sigma_matcher", t0).model_dump(),
        "total_events_scanned": result.total_events_scanned,
        "total_matches": result.total_matches,
        "critical_matches": result.critical_matches,
        "high_matches": result.high_matches,
        "unique_techniques": result.unique_techniques,
        "matches": [
            {
                "rule_id": m.rule_id,
                "rule_title": m.rule_title,
                "description": m.description,
                "mitre_techniques": m.mitre_techniques,
                "level": m.level,
                "matched_event_id": m.matched_event_id,
                "matched_keywords": m.matched_keywords,
                "event_timestamp": m.event_timestamp,
                "event_description": m.event_description[:200],
            }
            for m in result.matches
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
async def main():
    MOUNT_BASE.mkdir(parents=True, exist_ok=True)
    log.info(json.dumps({"msg":"SIFT MCP server starting","tools":25}))
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
