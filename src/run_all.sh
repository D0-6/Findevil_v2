#!/usr/bin/env bash
# run_all.sh — Find Evil Hackathon
# Full pipeline: agent → benchmark → accuracy report
# Usage: ./run_all.sh /cases/win10_malware.E01 /cases/ground_truth.json

set -euo pipefail

# ── NIM API key check ─────────────────────────────────────────────────────────
if [ -z "${NIM_API_KEY:-}" ]; then
  echo "ERROR: NIM_API_KEY not set."
  echo "Run: export NIM_API_KEY=nvapi-your_key_here"
  exit 1
fi
export NIM_MODEL="${NIM_MODEL:-nvidia/nemotron-3-ultra-550b-a55b}"
export NIM_BASE_URL="${NIM_BASE_URL:-https://integrate.api.nvidia.com/v1}"
echo "Model : $NIM_MODEL"
echo "Endpoint: $NIM_BASE_URL"

IMAGE="${1:-/cases/win10_malware.E01}"
GROUND_TRUTH="${2:-/cases/ground_truth_win10_malware.json}"
MEMORY_DUMP="${3:-}"          # optional
MAX_ITER="${MAX_ITER:-25}"
OUT_DIR="/tmp/sift_bench_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUT_DIR"

echo "╔══════════════════════════════════════════╗"
echo "║   FIND EVIL — Full Pipeline Run          ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "  Image         : $IMAGE"
echo "  Ground truth  : $GROUND_TRUTH"
echo "  Memory dump   : ${MEMORY_DUMP:-none}"
echo "  Max iterations: $MAX_ITER"
echo "  Output dir    : $OUT_DIR"
echo ""

# ── Step 1: Your agent ────────────────────────────────────────────────────────
echo "[1/4] Running your agent (25 tools + 4 innovations)..."
AGENT_OUT="$OUT_DIR/your_findings.json"
MEMORY_FLAG=""
if [ -n "$MEMORY_DUMP" ]; then
  MEMORY_FLAG="--memory-dump $MEMORY_DUMP"
fi

python3 agent_loop.py \
    --image        "$IMAGE" \
    --output       "$AGENT_OUT" \
    --max-iterations "$MAX_ITER" \
    $MEMORY_FLAG

echo "      ✓ Agent output: $AGENT_OUT"

# ── Step 2: Benchmark ─────────────────────────────────────────────────────────
echo "[2/4] Running benchmark (baseline + your agent)..."
BENCH_OUT="$OUT_DIR/bench_report.json"

python3 bench.py \
    --image        "$IMAGE" \
    --ground-truth "$GROUND_TRUTH" \
    --agents       "baseline,yours" \
    --output       "$BENCH_OUT"

echo "      ✓ Benchmark report: $BENCH_OUT"

# ── Step 3: Accuracy report ───────────────────────────────────────────────────
echo "[3/4] Generating accuracy report..."
ACCURACY_OUT="$OUT_DIR/accuracy_report.md"

python3 accuracy_report.py \
    --bench-report "$BENCH_OUT" \
    --agent-output "$AGENT_OUT" \
    --output       "$ACCURACY_OUT"

echo "      ✓ Accuracy report: $ACCURACY_OUT"

# ── Step 4: Summary ───────────────────────────────────────────────────────────
echo "[4/4] Done."
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   Submission Files                       ║"
echo "╠══════════════════════════════════════════╣"
echo "║  Agent findings  : $AGENT_OUT"
echo "║  Bench report    : $BENCH_OUT"
echo "║  Accuracy report : $ACCURACY_OUT"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  0. OPTIONAL: open second terminal and run:"
echo "     python dashboard.py --watch $AGENT_OUT"
echo "     (live dashboard updates as agent runs)"
echo "  1. Record 5-min demo video showing output above"
echo "     - Show iteration diff table (agent learning trace)"
echo "     - Show sigma_matcher firing after evtx_parser"
echo "     - Show corroboration scores in confirmed findings"
echo "     - Show token budget utilisation"
echo "     - Show baseline vs your agent score delta"
echo "  2. Copy $ACCURACY_OUT into Devpost accuracy report field"
echo "  3. Upload $OUT_DIR/ as execution logs (required submission component)"
echo "  4. Push to GitHub with MIT license"
echo ""
echo "Submission checklist:"
echo "  [x] Code repository   -> push to github"
echo "  [ ] Demo video        -> record now"
echo "  [x] Architecture diagram -> in README.md"
echo "  [x] Project description  -> in README.md"
echo "  [x] Dataset docs         -> ground_truth_win10_malware.json"
echo "  [x] Accuracy report      -> $ACCURACY_OUT"
echo "  [x] Try-it-out           -> README quick start"
echo "  [x] Execution logs       -> $AGENT_OUT (tool_call_log field)"
