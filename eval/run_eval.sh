#!/usr/bin/env bash
# Reproduces eval/results/ (summary.md and CSVs), the source of every number
# in the README.
#
#   eval/run_eval.sh              # full run (needs network for the top 500)
#   EVAL_LIMIT=50 eval/run_eval.sh   # quick run on the first 50 packages
#
# Requires: Linux (GNU date), cargo, Node 22.18+. Scratch files go to
# eval/work/ (git-ignored). Nothing is installed or executed from any
# package: lockwatch only downloads, unpacks and reads them.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=${EVAL_WORK:-$ROOT/eval/work}
RESULTS=${EVAL_RESULTS:-$ROOT/eval/results}
LIMIT=${EVAL_LIMIT:-500}
BIN=$ROOT/target/release/lockwatch
FIXTURE_NOW=2026-10-20T00:00:00Z
# Time-based rules (LW009) for real packages are evaluated as of the start
# of the run, which is recorded in the summary.
EVAL_NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

ms() { date +%s%3N; }

echo "== building lockwatch (release)"
cargo build --release -q -p lockwatch-cli --manifest-path "$ROOT/Cargo.toml"

rm -rf "$WORK"
mkdir -p "$WORK"/{synthetic,top500-cold,top500-warm,bench} "$RESULTS"
echo "$EVAL_NOW" > "$WORK/eval_now.txt"

echo "== 1. synthetic fixtures (offline)"
for set in malicious benign; do
  "$BIN" scan "$ROOT/fixtures/lockfiles/$set.json" --offline \
    --cache-dir "$ROOT/fixtures/cache" --now "$FIXTURE_NOW" \
    --format json --fail-on none > "$WORK/synthetic/$set.json"
done

echo "== 2. top $LIMIT packages, one process per package (cold, then warm cache)"
CACHE=$WORK/cache-top500
for phase in cold warm; do
  out=$WORK/top500-$phase
  echo "index,spec,exit_code,wall_ms" > "$out/times.csv"
  i=0
  grep -v '^#' "$ROOT/eval/benign_top500.txt" | head -n "$LIMIT" | while read -r spec; do
    i=$((i + 1))
    f=$(printf '%03d' "$i")
    start=$(ms)
    code=0
    "$BIN" scan-package "$spec" --cache-dir "$CACHE" --now "$EVAL_NOW" \
      --format json --fail-on none > "$out/$f.json" 2> "$out/$f.err" || code=$?
    end=$(ms)
    echo "$f,$spec,$code,$((end - start))" >> "$out/times.csv"
    if (( i % 50 == 0 )); then echo "   $phase: $i done"; fi
  done
done

echo "== 3. a real 401-package lockfile (eval/bench), cold then warm cache"
for phase in cold warm; do
  start=$(ms)
  code=0
  "$BIN" scan "$ROOT/eval/bench/package-lock.json" --cache-dir "$WORK/cache-bench" \
    --now "$EVAL_NOW" --format json --fail-on none > "$WORK/bench/$phase.json" || code=$?
  end=$(ms)
  echo "$phase,$code,$((end - start))" >> "$WORK/bench/times.csv"
done

echo "== 4. machine"
{
  echo "date: $EVAL_NOW"
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs) ($(nproc) logical CPUs)"
  echo "memory: $(free -g | awk '/Mem:/ {print $2}') GB"
  echo "os: $(uname -sr)"
  echo "rustc: $(rustc --version)"
  echo "lockwatch: $("$BIN" --version)"
} > "$WORK/machine.txt"
cat "$WORK/machine.txt"

echo "== 5. summary"
node "$ROOT/eval/summarize.ts" "$WORK" "$RESULTS" "$ROOT"
echo "done: see $RESULTS/summary.md"
