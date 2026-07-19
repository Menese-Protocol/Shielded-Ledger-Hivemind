#!/usr/bin/env bash
# Resumable watchdog for long soak tiers (v2).
#
# The run writes durable ATOMIC checkpoint pairs (state snapshot + model at the same op);
# on an environmental interruption the watchdog restarts the binary and the run resumes
# from the newest pair. v2 fixes two v1 defects observed in the Jul-18 full-tier run:
#   1. FAIL-FAST: v1 burned 15 blind attempts against a resource-starved box, then looped
#      forever on a deterministic resume panic. v2 aborts after MAX_FAST_FAILS consecutive
#      attempts that die within STARTUP_WINDOW seconds — a fast repeat failure is a bug or
#      a sick box, and restarting cannot fix either. It leaves a RED line for the operator.
#   2. SCOPED CLEANUP: v1 pkill'd every pocket-ic and canister_sandbox on the box — this is
#      a shared machine and that kills other lanes' replicas. v2 kills only servers spawned
#      by the soak binary (their cmdline carries the soak_pocket_ic_ port-file marker) and
#      only ORPHANED sandbox processes (reparented to PID 1).
#
# Required env (no defaults on purpose — a watchdog with wrong paths is worse than none):
#   SOAK_SCRATCH        working dir for logs/state/checkpoints
#   SOAK_LABEL SOAK_ACCOUNTS SOAK_OPS SOAK_BATCH SOAK_CHECK_INTERVAL SOAK_CHECKPOINT_OPS
# Optional:
#   MAX_ATTEMPTS (200) STARTUP_WINDOW (300) MAX_FAST_FAILS (3) MIN_FREE_MB (8000)
set -u
cd "$(dirname "$0")"
: "${SOAK_SCRATCH:?set SOAK_SCRATCH}" "${SOAK_LABEL:?set SOAK_LABEL}"
: "${SOAK_ACCOUNTS:?}" "${SOAK_OPS:?}" "${SOAK_BATCH:?}" "${SOAK_CHECK_INTERVAL:?}" "${SOAK_CHECKPOINT_OPS:?}"
MAX_ATTEMPTS=${MAX_ATTEMPTS:-200}
STARTUP_WINDOW=${STARTUP_WINDOW:-300}
MAX_FAST_FAILS=${MAX_FAST_FAILS:-3}
MIN_FREE_MB=${MIN_FREE_MB:-8000}

export SOAK_PROGRESS_LOG="$SOAK_SCRATCH/$SOAK_LABEL-progress.log"
export SOAK_STATE_DIR="$SOAK_SCRATCH/$SOAK_LABEL-state"
export SOAK_CHECKPOINT_FILE="$SOAK_SCRATCH/$SOAK_LABEL-model.ckpt"
RUN_LOG="$SOAK_SCRATCH/$SOAK_LABEL-run.log"
mkdir -p "$SOAK_SCRATCH"

note() { echo "=== $* ===" >> "$SOAK_PROGRESS_LOG"; }

cleanup_ours() {
  # only servers the soak binary spawned (port-file marker in cmdline)
  pkill -9 -f "soak_pocket_ic_" 2>/dev/null
  sleep 2
  # only sandboxes orphaned by that kill (reparented to init) — never other lanes' sandboxes
  for pat in canister_sandbox compiler_sandbox sandbox_launcher; do
    for p in $(pgrep -f "$pat" 2>/dev/null); do
      [ "$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')" = "1" ] && kill -9 "$p" 2>/dev/null
    done
  done
}

attempt=1 fast_fails=0
while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  note "$SOAK_LABEL TIER attempt $attempt at $(date -u +%H:%M:%S) (free $(free -m | awk '/Mem:/{print $7}')MB)"
  start=$(date +%s)
  ./target/release/soak run >> "$RUN_LOG" 2>&1
  code=$?
  elapsed=$(( $(date +%s) - start ))
  if [ "$code" -eq 0 ]; then
    note "$SOAK_LABEL TIER COMPLETE (attempt $attempt, exit 0)"
    exit 0
  fi
  if [ "$elapsed" -lt "$STARTUP_WINDOW" ]; then
    fast_fails=$((fast_fails + 1))
  else
    fast_fails=0
  fi
  note "$SOAK_LABEL TIER attempt $attempt exited $code after ${elapsed}s (fast-fail streak $fast_fails/$MAX_FAST_FAILS); last panic: $(grep -a 'panicked at' "$RUN_LOG" | tail -1 | cut -c1-160)"
  cleanup_ours
  if [ "$fast_fails" -ge "$MAX_FAST_FAILS" ]; then
    note "$SOAK_LABEL TIER RED: $MAX_FAST_FAILS consecutive sub-${STARTUP_WINDOW}s failures — deterministic bug or sick box. STOPPING for operator/diagnosis (restarting cannot fix this)."
    exit 2
  fi
  sleep 60
  for _ in $(seq 1 20); do
    freemb=$(free -m | awk '/Mem:/{print $7}')
    [ "${freemb:-0}" -gt "$MIN_FREE_MB" ] && break
    sleep 30
  done
  attempt=$((attempt + 1))
done
note "$SOAK_LABEL TIER gave up after $((attempt - 1)) attempts"
exit 1
