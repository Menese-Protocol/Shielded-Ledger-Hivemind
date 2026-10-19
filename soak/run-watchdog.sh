#!/usr/bin/env bash
# Resumable watchdog for long soak tiers (v2).
#
# The run writes durable ATOMIC checkpoint pairs (state snapshot + model at the same op);
# on an environmental interruption the watchdog restarts the binary and the run resumes
# from the newest pair. v2 fixes two v1 defects observed in the Jul-18 full-tier run:
#   1. FAIL-FAST: v1 burned 15 blind attempts against a resource-starved box, then looped
#      forever on a deterministic resume panic. v2 aborts after MAX_FAST_FAILS consecutive
#      attempts that die within STARTUP_WINDOW seconds — a fast repeat failure is a bug or
#      a sick box, and restarting cannot fix either. It leaves a RED line for whoever is watching the run.
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
#   MIN_FREE_PIDS (500): threads the container's pids cgroup must still allow before an attempt
#     starts. A PocketIC server that cannot spawn a thread panics, and the soak sees a dropped
#     connection; on a box near pids.max that repeats until other work releases threads, so the
#     watchdog waits for headroom instead of spending attempts. Attempts that end while the box is
#     short of threads do not count toward the fast-fail streak. (Measured Oct-16: a soak run,
#     its PocketIC server with two subnets and an 8-thread prover pool, holds about 110 threads.)
set -u
cd "$(dirname "$0")"
: "${SOAK_SCRATCH:?set SOAK_SCRATCH}" "${SOAK_LABEL:?set SOAK_LABEL}"
: "${SOAK_ACCOUNTS:?}" "${SOAK_OPS:?}" "${SOAK_BATCH:?}" "${SOAK_CHECK_INTERVAL:?}" "${SOAK_CHECKPOINT_OPS:?}"
MAX_ATTEMPTS=${MAX_ATTEMPTS:-200}
STARTUP_WINDOW=${STARTUP_WINDOW:-300}
MAX_FAST_FAILS=${MAX_FAST_FAILS:-3}
MIN_FREE_MB=${MIN_FREE_MB:-8000}
MIN_FREE_PIDS=${MIN_FREE_PIDS:-500}

free_pids() {
  local max cur
  max=$(cat /sys/fs/cgroup/pids.max 2>/dev/null)
  cur=$(cat /sys/fs/cgroup/pids.current 2>/dev/null)
  if [ -z "$max" ] || [ -z "$cur" ] || [ "$max" = "max" ]; then echo 999999; return; fi
  echo $((max - cur))
}

wait_for_threads() {
  local waited=0
  while [ "$(free_pids)" -lt "$MIN_FREE_PIDS" ]; do
    [ "$waited" -eq 0 ] && note "$SOAK_LABEL waiting for thread headroom: $(free_pids) free under pids.max, need $MIN_FREE_PIDS"
    waited=$((waited + 30))
    sleep 30
  done
  [ "$waited" -gt 0 ] && note "$SOAK_LABEL thread headroom back after ${waited}s ($(free_pids) free)"
  return 0
}

export SOAK_PROGRESS_LOG="$SOAK_SCRATCH/$SOAK_LABEL-progress.log"
export SOAK_STATE_DIR="$SOAK_SCRATCH/$SOAK_LABEL-state"
export SOAK_CHECKPOINT_FILE="$SOAK_SCRATCH/$SOAK_LABEL-model.ckpt"
RUN_LOG="$SOAK_SCRATCH/$SOAK_LABEL-run.log"
mkdir -p "$SOAK_SCRATCH"

# Keep each PocketIC server's stderr (the soak discards it): a server's own panic is the only
# record of why it died (a thread it could not spawn, memory, a replica bug).
WRAPPER="$SOAK_SCRATCH/pocket-ic-logged"
REAL_PIC="${POCKET_IC_BIN:-$(ls -d "$HOME"/.cache/dfinity/versions/*/pocket-ic 2>/dev/null | sort -V | tail -1)}"
if [ -n "$REAL_PIC" ] && [ "$REAL_PIC" != "$WRAPPER" ]; then
  printf '#!/bin/bash\nexec %q "$@" 2>>%q/pocket-ic-stderr-$$.log\n' "$REAL_PIC" "$SOAK_SCRATCH" > "$WRAPPER"
  chmod +x "$WRAPPER"
  export POCKET_IC_BIN="$WRAPPER"
fi

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
  wait_for_threads
  note "$SOAK_LABEL TIER attempt $attempt at $(date -u +%H:%M:%S) (free $(free -m | awk '/Mem:/{print $7}')MB)"
  start=$(date +%s)
  ./target/release/soak run >> "$RUN_LOG" 2>&1
  code=$?
  elapsed=$(( $(date +%s) - start ))
  if [ "$code" -eq 0 ]; then
    note "$SOAK_LABEL TIER COMPLETE (attempt $attempt, exit 0)"
    exit 0
  fi
  if [ "$(free_pids)" -lt "$MIN_FREE_PIDS" ] ||
     find "$SOAK_SCRATCH" -maxdepth 1 -name 'pocket-ic-stderr-*.log' -newermt "@$start" \
       -exec grep -aq 'failed to spawn thread' {} \; -print 2>/dev/null | grep -q .; then
    # the box ran out of threads: environmental, not a deterministic failure of the run
    fast_fails=0
  elif [ "$elapsed" -lt "$STARTUP_WINDOW" ]; then
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
