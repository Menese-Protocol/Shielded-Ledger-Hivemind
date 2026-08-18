#!/usr/bin/env bash
# Option (b), the chunked migration — K-1, K-1b, K-3, K-4, K-5, K-6, K-8.
# K-2, the rescue from a genuine layout-1 set, is exercised by a separate long-running battery
# that needs a layout-1 seed (built by scripts/build-layout1-fixture.sh).
#
# Thresholds are fixed in docs/thresholds/THRESHOLDS-chunked-migration.md, committed
# before any of this was run once. They are quoted here only so a failure is readable; that file is
# the one that counts and it is not edited.
#
#   K-1   SHAPE + CEILING (docs/thresholds/THRESHOLDS-chunked-migration.md §1a). The grow-path reclaim is now CHUNKED through
#         compactStep (a bounded slice per put, the stepMigration discipline), so per-message cost is
#         flat BY CONSTRUCTION, not by assertion. Asserted two ways, both required: SHAPE — the p99
#         per-message cost does not scale with N across >= 4 doubling rungs (p99 not max: max is
#         legitimately spiky, one put lands the reclaim slice) — the regression detector; CEILING — no
#         message exceeds a bound DERIVED from COMPACT_MAX_BYTES x measured atomic-op cost — the
#         catastrophe detector. mean flat is also checked.
#   K-1b  the OPENING message is FLAT now (reclaim moved off it into compactStep; the table allocation
#         is lazy Region.grow), the place the old pin warned an O(N) cost could hide.
#   K-3   zero false negatives and zero false positives at >= 8 cursor positions across a window
#   K-4   a real trap mid-window rolls the cursor back with everything else; re-running is idempotent
#   K-5   (i) the window closes in ceil(capacity/CHUNK) puts, strictly fewer than the puts available
#         before the next grow; (ii) an open window is bounded overhead, < 2.5x lookup cost, and
#         advanceMigration converges it in ceil(remaining/budget) messages
#   K-6   the force-complete branch is never taken: the forced counter stays 0
#   K-8   validateHeader rejects every corrupted field, proved by perturbation
#
# Usage: scripts/option-b-battery.sh [--baseline <half-lookup wasm>]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export PATH="${DFX_BIN_DIR:-/root/.local/share/dfx/bin}:$PATH"
BASELINE=""; [ "${1:-}" = "--baseline" ] && BASELINE="${2:-}"

PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  PASS  $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  FAIL  $1"; echo "        expected: $2"; echo "        actual:   $3"; }
eq(){ if failed "$2$3"; then bad "$1" "$2" "a call failed: $3"; return; fi
  if [ -z "$2" ] || [ -z "$3" ]; then bad "$1" "${2:-<empty>}" "${3:-<empty>}"; return; fi
  if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1" "$2" "$3"; fi; }
lt(){ if failed "$2$3" || [ -z "$2" ] || [ -z "$3" ]; then bad "$1" "< $3" "${2:-<empty or failed>}"; return; fi
  if python3 -c "import sys; sys.exit(0 if $2 < $3 else 1)"; then ok "$1 ($2 < $3)"; else bad "$1" "< $3" "$2"; fi; }
has(){ if failed "$3" || [ -z "$3" ]; then bad "$1" "contains '$2'" "${3:-<empty or failed>}"; return; fi
  case "$3" in *"$2"*) ok "$1";; *) bad "$1" "contains '$2'" "$(echo "$3" | cut -c1-160)";; esac; }
call(){ dfx canister call "$@" 2>&1 | grep -v "^WARNING"; }
# A reply that is an error must never reach a number parser. An IC0522 rejection contains digits —
# 5000000000 among them — and a battery that greps a failure for numbers reports nonsense that looks
# exactly like a measurement. This cost one full run.
# A failed call yields a SENTINEL, not an exit. `exit` inside $( ) only leaves the subshell, so the
# battery would carry on and compare two empty strings — which passes. Every comparator below treats
# the sentinel as a failure, so a broken call can never be mistaken for a result.
flat(){ local out; out=$(call "$@" | tr -d '\n' | tr -s ' ')
  case "$out" in
    *"Error:"*|*"reject"*|*"Rejection"*)
      echo "CALL_FAILED $(echo "$out" | cut -c1-200)";;
    *) echo "$out";;
  esac; }
# For calls that are SUPPOSED to fail — the K-4 trap — where a rejection is the result.
raw(){ call "$@" | tr -d '\n' | tr -s ' '; }
failed(){ case "$*" in *CALL_FAILED*) return 0;; *) return 1;; esac; }
# Type annotations are stripped first: `41 : nat64` otherwise yields 41 AND 64.
# Anchored on the record separator. An unanchored `capacity = ` also matches inside
# `active_capacity = `, and candid prints active_capacity first — which is how a staging assertion
# read the wrong number twice and still looked like a measurement.
# The trailing `tr -d` is not cosmetic: a stray newline in an extracted number makes a comparison
# that is arithmetically right read as a failure, which is how K-5(i) looked broken when it was not.
# Take everything after the '= ' rather than re-grepping for digits: an end-anchored digit pattern
# reads 8_192 as 192, because the underscore is still there when the anchor is applied.
field(){ echo "$1" | sed -E 's/:[[:space:]]*(nat|int)[0-9]*//g' | grep -oE "[;{] $2 = [0-9_]+" \
  | head -1 | sed -E 's/.*= //' | tr -d '_\n '; }
boolfield(){ echo "$1" | grep -oE "[;{] $2 = (true|false)" | head -1 | sed -E 's/.*= //' | tr -d '\n '; }

CANISTER=window_fixture
CHUNK=8

install_on(){ dfx canister install "$CANISTER" --mode "$2" --yes --wasm "$1" 2>&1 \
    | grep -v "^WARNING" | grep -ivE "^(Upgraded|Reinstalled)"
  local want live; want=$(sha256sum "$1" | cut -d' ' -f1)
  live=$(dfx canister status "$CANISTER" 2>&1 | grep -i "Module hash" | grep -oE "[0-9a-f]{64}")
  [ "$want" = "$live" ] || { echo "ABORT: install of $1 did not take (live $live)"; exit 2; }
  echo "  $CANISTER running module $live"; }

# Membership over the whole corpus, paged: a query is capped at 5e9 instructions and one probe is
# a SHA-256, so ~20,000 keys is about as much as one call may be asked for.
missing_total(){ local total=$1 from=0 sum=0 page=15000
  while [ "$from" -lt "$total" ]; do
    local n=$(( total - from < page ? total - from : page ))
    sum=$(( sum + $(flat "$CANISTER" missing_in "($from, $n)" | grep -oE '[0-9_]+' | head -1 | tr -d '_') ))
    from=$(( from + n ))
  done
  echo "$sum"; }

ghosts_total(){ flat "$CANISTER" ghosts_in "(0, $1)" | grep -oE '[0-9_]+' | head -1 | tr -d '_'; }

fill_to(){ local target=$1 from page=5000
  from=$(field "$(flat "$CANISTER" window '()')" entries)
  while [ "$from" -lt "$target" ]; do
    local n=$(( target - from < page ? target - from : page ))
    call "$CANISTER" put_range "($from, $n)" >/dev/null
    from=$(( from + n ))
  done; }

echo "=== option (b) — the chunked migration ==="
dfx canister create "$CANISTER" >/dev/null 2>&1
dfx canister update-settings "$CANISTER" --wasm-memory-limit 4294967296 >/dev/null 2>&1
dfx build "$CANISTER" >/dev/null 2>&1
FIXED=".dfx/local/canisters/$CANISTER/$CANISTER.wasm"

# ---------------------------------------------------------------------------------------------
# RED: the mistake the two-table lookup exists to prevent.
# ---------------------------------------------------------------------------------------------
if [ -n "$BASELINE" ]; then
  echo; echo "--- RED leg: a lookup that reads only the new table during a window ---"
  install_on "$BASELINE" reinstall
  call "$CANISTER" put_range "(0, 6000)" >/dev/null
  W=$(flat "$CANISTER" window '()')
  if [ "$(boolfield "$W" active)" != "true" ]; then
    echo "ABORT: no window is open, so the red leg would test nothing"; exit 2
  fi
  echo "  window open at cursor $(field "$W" cursor) of capacity $(field "$W" capacity)"
  MISS=$(missing_total 6000)
  GHOST=$(ghosts_total 500)
  if [ "${MISS:-0}" -gt 0 ]; then
    ok "red: skipping the old table loses $MISS committed keys mid-window"
  else
    bad "red: skipping the old table loses committed keys" "false negatives > 0" "$MISS"
  fi
  eq "red: and invents none — the defect is one-directional, which is what makes it silent" "0" "$GHOST"
  echo "  [red] on spent_nullifiers each of those $MISS keys is a nullifier that reads as unspent."
fi

# ---------------------------------------------------------------------------------------------
echo; echo "--- GREEN: this tree's build ---"
install_on "$FIXED" reinstall

# ---------------------------------------------------------------------------------------------
# K-1 / K-1b: four doubling rungs.
# ---------------------------------------------------------------------------------------------
echo; echo "--- K-1: per-message cost SHAPE (p99, does not scale with N) + CEILING (from COMPACT_MAX_BYTES) ---"
RUNGS="8192 16384 32768 65536"
declare -A MAXI MAXA OPENI OPENA P99 MEAN
for CAP in $RUNGS; do
  TARGET=$(( CAP * 7 / 10 ))              # the entry count the next put opens a window at
  fill_to "$TARGET"
  W=$(flat "$CANISTER" window '()')
  c=$(field "$W" capacity); e=$(field "$W" entries); a=$(boolfield "$W" active)
  [ "$c" = "$CAP" ] && [ "$a" = "false" ] || { echo "ABORT: rung $CAP not staged (capacity=$c active=$a entries=$e)"; exit 2; }
  STEPS=$(( (CAP + CHUNK - 1) / CHUNK ))
  WALK=$(flat "$CANISTER" window_walk "($e, $((STEPS + 2)), 1024)")
  opened=$(boolfield "$WALK" opened); closed=$(boolfield "$WALK" closed)
  [ "$opened" = "true" ] && [ "$closed" = "true" ] || { echo "ABORT: rung $CAP did not open AND close in one walk"; exit 2; }
  MAXI[$CAP]=$(field "$WALK" max_instr); MAXA[$CAP]=$(field "$WALK" max_alloc)
  OPENI[$CAP]=$(field "$WALK" open_instr); OPENA[$CAP]=$(field "$WALK" open_alloc)
  P99[$CAP]=$(field "$WALK" p99_instr)
  MEAN[$CAP]=$(python3 -c "print(int($(field "$WALK" sum_instr) / $(field "$WALK" puts)))")
  echo "  capacity $CAP: p99 ${P99[$CAP]} / mean ${MEAN[$CAP]} / max ${MAXI[$CAP]} (put $(field "$WALK" max_index)); ${MAXA[$CAP]} B; opening ${OPENI[$CAP]} instr"
done

ratios_of(){ local -n arr=$1; local label=$2 tol=$3
  local prev="" prevcap="" n=0 out=0
  for CAP in $RUNGS; do
    local v=${arr[$CAP]}
    if [ -n "$prev" ]; then
      local r; r=$(python3 -c "print(f'{$v / $prev:.4f}')")
      n=$((n + 1))
      python3 -c "import sys; sys.exit(0 if abs($r - 1.0) <= $tol else 1)" \
        && echo "    $label $prevcap -> $CAP : ${r}x" \
        || { echo "    $label $prevcap -> $CAP : ${r}x  OUT OF BAND"; out=$((out + 1)); }
    fi
    prev=$v; prevcap=$CAP
  done
  RATIO_N=$n; RATIO_OUT=$out; }

# CEILING — DERIVED from COMPACT_MAX_BYTES, not a measured max plus a fudge factor. The ONLY place a
# single message could do a whole bounded reclaim is the openWindow force-drain, and even that
# relocates at most COMPACT_MAX_BYTES and zeroes at most COMPACT_MAX_BYTES. Two MEASURED atomic-op
# costs (implementation constants, from measure_region_ops) turn the byte bound into an instruction
# bound. The chunked reclaim means the force-drain is COLD, so the real max lives far below this — the
# ceiling is the catastrophe bound, the p99 SHAPE below is the regression detector.
COMPACT_MAX_BYTES=8388608; STRIDE=41
OPS=$(flat "$CANISTER" measure_region_ops '(100000)' | sed -E 's/:[[:space:]]*nat[0-9]*//g')
SN64=$(echo "$OPS" | grep -oE '[0-9][0-9_]*' | sed -n 1p | tr -d '_')
SLOTCOPY=$(echo "$OPS" | grep -oE '[0-9][0-9_]*' | sed -n 2p | tr -d '_')
RELOC_SLOTS=$(( COMPACT_MAX_BYTES / STRIDE )); ZERO_WORDS=$(( COMPACT_MAX_BYTES / 8 ))
CEIL=$(( RELOC_SLOTS * SLOTCOPY + ZERO_WORDS * SN64 ))
echo "  CEILING: relocate $RELOC_SLOTS slots x $SLOTCOPY + zero $ZERO_WORDS words x $SN64 = $CEIL instr ($(python3 -c "print(f'{$CEIL/40e9*100:.2f}')")% of the 40e9 message limit)"

# SHAPE — the regression detector. p99, NOT max: max is one put landing the migration or reclaim
# slice and is legitimately spiky under any amortised scheme; p99 is the stable body of the
# distribution, and it must not scale with N. This is what "flat catches cost that starts scaling
# with N" requires — a future O(N) creep on the grow path lifts the p99 across rungs and fails here.
ratios_of P99 "p99:" 0.15
if [ "$RATIO_N" -ge 3 ] && [ "$RATIO_OUT" -eq 0 ]; then
  ok "K-1 SHAPE: p99 per-message cost is FLAT across all four rungs (does NOT scale with N)"
else
  bad "K-1 SHAPE: p99 per-message cost flat" "1.00 +/- 0.15 across >= 3 ratios" "$RATIO_N ratios, $RATIO_OUT out of band"
fi
ratios_of MEAN "mean:" 0.10
if [ "$RATIO_N" -ge 3 ] && [ "$RATIO_OUT" -eq 0 ]; then
  ok "K-1 SHAPE: mean per-message cost is FLAT across all four rungs (amortised per-put cost O(1) in N)"
else
  bad "K-1 mean per-message cost flat" "1.00 +/- 0.10" "$RATIO_N ratios, $RATIO_OUT out of band"
fi
# CEILING — the catastrophe detector. No message, at any rung, exceeds the COMPACT_MAX_BYTES-derived bound.
CEILBAD=0
for CAP in $RUNGS; do
  [ "${MAXI[$CAP]}" -lt "$CEIL" ] || { echo "    cap $CAP max ${MAXI[$CAP]} >= $CEIL"; CEILBAD=$((CEILBAD+1)); }
done
if [ "$CEILBAD" -eq 0 ]; then
  ok "K-1 CEILING: no message exceeds the derived $CEIL instr at any rung (from COMPACT_MAX_BYTES x op cost)"
else
  bad "K-1 CEILING" "max < $CEIL at every rung" "$CEILBAD rungs over"
fi
# The reclaim force-drain is COLD — the whole reclaim is chunked, so no message finishes one wholesale.
# A message that did would sit near the ceiling; assert the max is at least 10x under it as the evidence
# (K-6 proves the migration force-branch is cold; this is its compaction counterpart, by magnitude).
lt "K-1 the reclaim force-drain is COLD (max >= 10x under the derived ceiling — chunking holds)" "${MAXI[65536]}" "$(( CEIL / 10 ))"

# K-1b: the OPENING message is FLAT now, not a spike. The doubled-table allocation is lazy
# (Region.grow zero-fills virgin pages, O(1)), and the reclaim zero-fill moved OFF the opening into
# the chunked compactStep, so opening no longer scales with N — the very thing the old K-1b said was
# "where the wedge could hide". Assert flat + under the derived ceiling.
ratios_of OPENI "opening:" 0.15
if [ "$RATIO_N" -ge 3 ] && [ "$RATIO_OUT" -eq 0 ]; then
  ok "K-1b the OPENING message is FLAT across rungs (reclaim no longer lands on it)"
else
  bad "K-1b opening message flat" "1.00 +/- 0.15" "$RATIO_N ratios, $RATIO_OUT out of band"
fi
lt "K-1b opening-message instructions under the derived ceiling" "${OPENI[65536]}" "$CEIL"

# ALLOCATION — RESTORED. The pre-p99 (re-derived) battery asserted a max and an opening allocation
# bound; the p99 rewrite dropped both (that is the whole of the 39->38 leg-count change: -2 alloc
# legs, +1 p99-flat leg), a coverage loss corrected here so a future O(N) allocation regression is
# caught. The storeNat64 zeroing allocates NO blob, so per-message allocation is now only the copy
# phase's bounded loadBlobs (<= COMPACT_BUDGET slots) plus migration/probe blobs -- flat and tiny.
lt "K-1 max allocation per message is bounded (no O(N) allocation -- storeNat64, no blob)" "${MAXA[65536]}" 262144
ratios_of OPENA "opening alloc:" 0.10
if [ "$RATIO_N" -ge 3 ] && [ "$RATIO_OUT" -eq 0 ]; then
  ok "K-1b the OPENING allocation is FLAT across rungs (the doubled-table alloc is lazy Region.grow)"
else
  bad "K-1b opening allocation flat" "1.00 +/- 0.10" "$RATIO_N ratios, $RATIO_OUT out of band"
fi
lt "K-1b opening allocation per message is bounded" "${OPENA[65536]}" 262144

W=$(flat "$CANISTER" window '()')
eq "K-6 the force-complete branch was never taken across all four rungs" "0" "$(field "$W" forced)"

# ---------------------------------------------------------------------------------------------
# K-5(i): the bound that makes K-6 structural rather than lucky.
# ---------------------------------------------------------------------------------------------
echo; echo "--- K-5(i): a window closes long before the next grow can be demanded ---"
W=$(flat "$CANISTER" window '()')
CAPNOW=$(field "$W" capacity)
fill_to $(( CAPNOW * 7 / 10 ))                            # one below the threshold at THIS capacity
E=$(field "$(flat "$CANISTER" window '()')" entries)
call "$CANISTER" put_range "($E, 1)" >/dev/null           # the put that opens the window
W=$(flat "$CANISTER" window '()')
eq "K-5(i) a window is open"        "true" "$(boolfield "$W" active)"
eq "K-5(i) and it has only just opened, so the bound is measured from the start" \
   "$CHUNK" "$(field "$W" cursor)"
STEPS=$(field "$W" steps_needed); AVAIL=$(field "$W" puts_available); CAP=$(field "$W" capacity)
CUR=$(field "$W" cursor)
echo "  capacity $CAP: $STEPS puts to close, $AVAIL puts available before the next grow"
# From what REMAINS, not from the capacity: the put that opened the window already carried one chunk.
eq "K-5(i) steps needed is ceil(remaining/CHUNK)" "$(( (CAP - CUR + CHUNK - 1) / CHUNK ))" "$STEPS"
lt "K-5(i) and that is strictly fewer than the puts available" "$STEPS" "$AVAIL"

# ---------------------------------------------------------------------------------------------
# K-3: membership at every cursor position, sampled across the window.
# ---------------------------------------------------------------------------------------------
echo; echo "--- K-3: membership is never wrong mid-window (8 sample points) ---"
SAMPLES=8
SLICE=$(( STEPS / SAMPLES + 1 ))
MISSTOT=0; GHOSTTOT=0; SAMPLED=0
i=0
while [ "$i" -lt "$SAMPLES" ]; do
  E=$(field "$(flat "$CANISTER" window '()')" entries)
  call "$CANISTER" put_range "($E, $SLICE)" >/dev/null
  W=$(flat "$CANISTER" window '()')
  E2=$(field "$W" entries); CUR=$(field "$W" cursor); ACT=$(boolfield "$W" active)
  m=$(missing_total "$E2")
  g=$(ghosts_total 500)
  MISSTOT=$(( MISSTOT + m )); GHOSTTOT=$(( GHOSTTOT + g )); SAMPLED=$(( SAMPLED + 1 ))
  echo "    sample $((i+1)): window=$ACT cursor=$CUR entries=$E2 -> $m missing, $g ghosts"
  i=$(( i + 1 ))
done
eq "K-3 sample points taken across the window" "$SAMPLES" "$SAMPLED"
eq "K-3 zero false negatives at every sample point" "0" "$MISSTOT"
eq "K-3 zero false positives at every sample point" "0" "$GHOSTTOT"
V=$(call "$CANISTER" validate '()')
case "$V" in *ok*) ok "K-3 validate() is green mid-window: live_old + live_new == entry_count";;
              *) bad "K-3 validate() is green mid-window" "ok" "$V";; esac

# ---------------------------------------------------------------------------------------------
# K-5(ii): an open window is bounded overhead, and converges on demand.
# ---------------------------------------------------------------------------------------------
echo; echo "--- K-5(ii): an open window is overhead, not a wedge ---"
W=$(flat "$CANISTER" window '()')
if [ "$(boolfield "$W" active)" != "true" ]; then
  CAPNOW=$(field "$W" capacity)
  fill_to $(( CAPNOW * 7 / 10 ))
  E=$(field "$(flat "$CANISTER" window '()')" entries)
  call "$CANISTER" put_range "($E, 1)" >/dev/null
  W=$(flat "$CANISTER" window '()')
fi
[ "$(boolfield "$W" active)" = "true" ] || { echo "ABORT: could not open a window for K-5(ii)"; exit 2; }
OPENCOST=$(echo "$(flat "$CANISTER" membership_cost '(0, 2000)')" | sed -E 's/:[[:space:]]*(nat|int)[0-9]*//g' | grep -oE '[0-9_]+' | head -1 | tr -d '_')
REMAIN=$(( $(field "$W" capacity) - $(field "$W" cursor) ))
BUDGET=4096
EXPECTED=$(( (REMAIN + BUDGET - 1) / BUDGET ))
CALLS=0
while [ "$(boolfield "$(flat "$CANISTER" window '()')" active)" = "true" ]; do
  call "$CANISTER" advance "($BUDGET)" >/dev/null
  CALLS=$(( CALLS + 1 ))
  [ "$CALLS" -gt "$(( EXPECTED + 2 ))" ] && break
done
eq "K-5(ii) advanceMigration converged the window"              "false" "$(boolfield "$(flat "$CANISTER" window '()')" active)"
eq "K-5(ii) in ceil(remaining/budget) messages, no more"        "$EXPECTED" "$CALLS"
CLOSEDCOST=$(echo "$(flat "$CANISTER" membership_cost '(0, 2000)')" | sed -E 's/:[[:space:]]*(nat|int)[0-9]*//g' | grep -oE '[0-9_]+' | head -1 | tr -d '_')
RATIO=$(python3 -c "print(f'{$OPENCOST / $CLOSEDCOST:.3f}')")
echo "  2,000 lookups: $OPENCOST instr with a window open, $CLOSEDCOST with it closed (${RATIO}x)"
lt "K-5(ii) an open window costs less than 2.5x on the read path" "$RATIO" 2.5

# ---------------------------------------------------------------------------------------------
# K-4: a real trap mid-window.
# ---------------------------------------------------------------------------------------------
echo; echo "--- K-4: a message that traps mid-window rolls back, and the retry is idempotent ---"
W=$(flat "$CANISTER" window '()')
if [ "$(boolfield "$W" active)" != "true" ]; then
  CAPNOW=$(field "$W" capacity)
  fill_to $(( CAPNOW * 7 / 10 ))
  E=$(field "$(flat "$CANISTER" window '()')" entries)
  call "$CANISTER" put_range "($E, 1)" >/dev/null
fi
E=$(field "$(flat "$CANISTER" window '()')" entries)
call "$CANISTER" put_range "($E, 200)" >/dev/null
W=$(flat "$CANISTER" window '()')
[ "$(boolfield "$W" active)" = "true" ] || { echo "ABORT: no window open to interrupt"; exit 2; }
BEFORE_CUR=$(field "$W" cursor); BEFORE_ENT=$(field "$W" entries)
BEFORE_DIG=$(flat "$CANISTER" digest '()')
BEFORE_MEM="$(missing_total "$BEFORE_ENT")/$(ghosts_total 500)"
T=$(raw "$CANISTER" put_then_trap "($BEFORE_ENT, 400)")
has "K-4 the interrupting message really trapped" "TEST_ONLY:interrupted-window" "$T"
W=$(flat "$CANISTER" window '()')
eq "K-4 the cursor rolled back with the message"     "$BEFORE_CUR" "$(field "$W" cursor)"
eq "K-4 the entry count rolled back"                 "$BEFORE_ENT" "$(field "$W" entries)"
eq "K-4 the digest is byte-identical, so no tombstone or slot survived" "$BEFORE_DIG" "$(flat "$CANISTER" digest '()')"
eq "K-4 membership answers identically after the rollback" "$BEFORE_MEM" "$(missing_total "$BEFORE_ENT")/$(ghosts_total 500)"
call "$CANISTER" put_range "($BEFORE_ENT, 400)" >/dev/null
AFTER_DIG=$(flat "$CANISTER" digest '()')
call "$CANISTER" put_range "($BEFORE_ENT, 400)" >/dev/null
eq "K-4 re-running the same range is idempotent"     "$AFTER_DIG" "$(flat "$CANISTER" digest '()')"
eq "K-4 and the entry count moved exactly once"      "$(( BEFORE_ENT + 400 ))" "$(field "$(flat "$CANISTER" window '()')" entries)"
V=$(call "$CANISTER" validate '()')
case "$V" in *ok*) ok "K-4 validate() is green after the interruption";;
              *) bad "K-4 validate() is green after the interruption" "ok" "$V";; esac

# ---------------------------------------------------------------------------------------------
# K-8: validateHeader by perturbation.
# ---------------------------------------------------------------------------------------------
echo; echo "--- K-8: validateHeader rejects every corrupted field ---"
H=$(call "$CANISTER" header_ok '()')
case "$H" in *ok*) ok "K-8 the healthy header validates";; *) bad "K-8 the healthy header validates" "ok" "$H";; esac
CAPNOW=$(field "$(flat "$CANISTER" window '()')" capacity)
# 1<<63 overflows bash arithmetic, which is signed 64-bit: $(( 9223372036854775808 + x )) goes
# negative and candid then refuses the argument. Compute it where the width is not a problem.
CURSOR_POKE=$(python3 -c "print(2**63 + ${CAPNOW:-0})")

probe(){ local name=$1 offset=$2 value=$3 want=$4
  local out; out=$(flat "$CANISTER" probe_header "($offset, $value)")
  has "K-8 $name" "$want" "$out"; }

probe "a corrupted magic is rejected"                 0  1                          "stable-set:magic"
probe "a table_offset that disagrees with state"      16 999                        "stable-set:header-state-mismatch"
probe "a capacity that disagrees with state"          24 999                        "stable-set:header-state-mismatch"
probe "an entry_count that disagrees with state"      32 999                        "stable-set:header-state-mismatch"
probe "a next_offset that disagrees with state"       40 999                        "stable-set:header-state-mismatch"
probe "an out-of-range stride"                        48 4096                       "stable-set:table-bounds"
probe "a cursor set with the window bit clear"        56 7                          "stable-set:migration-word"
probe "a cursor at or past the end of the old table"  56 "$CURSOR_POKE"             "stable-set:migration-cursor"
S=$(flat "$CANISTER" probe_slot_tag "(0, 3)")
has "K-8 a slot tag that is neither empty, live nor tombstoned" "stable-set:slot-tag" "$S"
H=$(call "$CANISTER" header_ok '()')
case "$H" in *ok*) ok "K-8 every perturbation was put back — the header is healthy again";;
              *) bad "K-8 the header is healthy again" "ok" "$H";; esac

W=$(flat "$CANISTER" window '()')
eq "K-6 the force-complete branch was never taken, across the whole battery" "0" "$(field "$W" forced)"

echo
echo "=== RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
