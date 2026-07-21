/// MICRO-BENCH HARNESS — TEST INFRASTRUCTURE ONLY. Measures candidate inner-loop shapes for
/// the PIR v2 stripe matvec on a real replica, so the production loop is chosen by measured
/// instructions-per-madd, not by theory. Each variant computes the same mod-2^32 accumulate
/// ans[r] += cell(r,c) · qu[c] over `cols` columns of `mRows` cells and returns
/// (instructions, allocated bytes, checksum) — the checksum defeats dead-code elimination
/// and doubles as a cross-variant equality check (all variants must agree).

import Blob "mo:core/Blob";
import Nat8 "mo:core/Nat8";
import _Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import VarArray "mo:core/VarArray";
import Prim "mo:⛔";

persistent actor Pir2MicroBench {
  let M_ROWS : Nat = 17_280;
  let MASK32 : Nat64 = 0xFFFF_FFFF;

  let data = Region.new();
  var cols_ready : Nat = 0;

  func byteAt(c : Nat, r : Nat) : Nat8 {
    Nat8.fromNat((c * 31 + r * 7 + (r / 253)) % 256)
  };

  /// Deterministic column fill (content irrelevant to cost; nonzero to keep checksums honest).
  public func setup(cols : Nat) : async () {
    ignore Region.grow(data, Nat64.fromNat((cols * M_ROWS + 65_535) / 65_536));
    var c = 0;
    while (c < cols) {
      let bytes = Prim.Array_init<Nat8>(M_ROWS, 0);
      var r = 0;
      while (r < M_ROWS) { bytes[r] := byteAt(c, r); r += 1 };
      Region.storeBlob(data, Nat64.fromNat(c * M_ROWS), Blob.fromVarArray(bytes));
      c += 1;
    };
    cols_ready := cols;
  };

  func quAt(c : Nat) : Nat64 {
    Prim.nat32ToNat64(Prim.natToNat32((c * 2_654_435_761 + 12_345) % 4_294_967_296))
  };

  func finish(ans : [var Nat32], c0 : Nat64, a0 : Nat64) : (Nat64, Nat64, Nat64) {
    let c1 = Prim.performanceCounter(0);
    let a1 = Nat64.fromNat(Prim.rts_total_allocation() - Nat64.toNat(a0));
    var sum : Nat64 = 0;
    var r = 0;
    while (r < M_ROWS) { sum := sum +% Prim.nat32ToNat64(ans[r]); r += 1 };
    (c1 - c0, a1, sum)
  };

  /// V1 — current production shape: Blob.toArray + Nat64.fromNat(Nat8.toNat(...)).
  public func v1(cols : Nat) : async (Nat64, Nat64, Nat64) {
    let a0 = Nat64.fromNat(Prim.rts_total_allocation());
    let c0 = Prim.performanceCounter(0);
    let ans = VarArray.repeat<Nat32>(0, M_ROWS);
    var c = 0;
    while (c < cols) {
      let colBytes = Blob.toArray(Region.loadBlob(data, Nat64.fromNat(c * M_ROWS), M_ROWS));
      let quC = quAt(c);
      var r = 0;
      while (r < M_ROWS) {
        let prev = Prim.nat32ToNat64(ans[r]);
        let cell = Nat64.fromNat(Nat8.toNat(colBytes[r]));
        ans[r] := Prim.nat64ToNat32((prev +% cell *% quC) & MASK32);
        r += 1;
      };
      c += 1;
    };
    finish(ans, c0, a0)
  };

  /// V2 — direct bit-width chain: nat8ToNat16 → nat16ToNat32 → nat32ToNat64 (no bignum).
  public func v2(cols : Nat) : async (Nat64, Nat64, Nat64) {
    let a0 = Nat64.fromNat(Prim.rts_total_allocation());
    let c0 = Prim.performanceCounter(0);
    let ans = VarArray.repeat<Nat32>(0, M_ROWS);
    var c = 0;
    while (c < cols) {
      let colBytes = Blob.toArray(Region.loadBlob(data, Nat64.fromNat(c * M_ROWS), M_ROWS));
      let quC = quAt(c);
      var r = 0;
      while (r < M_ROWS) {
        let prev = Prim.nat32ToNat64(ans[r]);
        let cell = Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(colBytes[r])));
        ans[r] := Prim.nat64ToNat32((prev +% cell *% quC) & MASK32);
        r += 1;
      };
      c += 1;
    };
    finish(ans, c0, a0)
  };

  /// V3 — blob iterator (no toArray materialization), direct chain.
  public func v3(cols : Nat) : async (Nat64, Nat64, Nat64) {
    let a0 = Nat64.fromNat(Prim.rts_total_allocation());
    let c0 = Prim.performanceCounter(0);
    let ans = VarArray.repeat<Nat32>(0, M_ROWS);
    var c = 0;
    while (c < cols) {
      let col = Region.loadBlob(data, Nat64.fromNat(c * M_ROWS), M_ROWS);
      let quC = quAt(c);
      var r = 0;
      for (byte in col.values()) {
        let prev = Prim.nat32ToNat64(ans[r]);
        let cell = Prim.nat32ToNat64(Prim.nat16ToNat32(Prim.nat8ToNat16(byte)));
        ans[r] := Prim.nat64ToNat32((prev +% cell *% quC) & MASK32);
        r += 1;
      };
      c += 1;
    };
    finish(ans, c0, a0)
  };

  /// V4 — Region word loads (loadNat32, 4 cells/word, shift-extract; no heap blob at all).
  public func v4(cols : Nat) : async (Nat64, Nat64, Nat64) {
    let a0 = Nat64.fromNat(Prim.rts_total_allocation());
    let c0 = Prim.performanceCounter(0);
    let ans = VarArray.repeat<Nat32>(0, M_ROWS);
    var c = 0;
    while (c < cols) {
      let base = Nat64.fromNat(c * M_ROWS);
      let quC = quAt(c);
      var w = 0;
      while (w < M_ROWS / 4) {
        let packed = Prim.nat32ToNat64(Region.loadNat32(data, base + Nat64.fromNat(4 * w)));
        var lane = 0;
        while (lane < 4) {
          let r = 4 * w + lane;
          let cell = (packed >> Nat64.fromNat(8 * lane)) & 0xFF;
          let prev = Prim.nat32ToNat64(ans[r]);
          ans[r] := Prim.nat64ToNat32((prev +% cell *% quC) & MASK32);
          lane += 1;
        };
        w += 1;
      };
      c += 1;
    };
    finish(ans, c0, a0)
  };

  /// V6 — pure Nat32 arithmetic (no widening: the madd IS mod 2^32): toArray + direct
  /// nat8→nat16→nat32 chain, `ans[r] +%= cell *% quC` all in Nat32.
  public func v6(cols : Nat) : async (Nat64, Nat64, Nat64) {
    let a0 = Nat64.fromNat(Prim.rts_total_allocation());
    let c0 = Prim.performanceCounter(0);
    let ans = VarArray.repeat<Nat32>(0, M_ROWS);
    var c = 0;
    while (c < cols) {
      let colBytes = Blob.toArray(Region.loadBlob(data, Nat64.fromNat(c * M_ROWS), M_ROWS));
      let quC = Prim.nat64ToNat32(quAt(c));
      var r = 0;
      while (r < M_ROWS) {
        ans[r] := ans[r] +% Prim.nat16ToNat32(Prim.nat8ToNat16(colBytes[r])) *% quC;
        r += 1;
      };
      c += 1;
    };
    finish(ans, c0, a0)
  };

  /// V7 — pure Nat32 over the blob iterator (no toArray, no index on the source).
  public func v7(cols : Nat) : async (Nat64, Nat64, Nat64) {
    let a0 = Nat64.fromNat(Prim.rts_total_allocation());
    let c0 = Prim.performanceCounter(0);
    let ans = VarArray.repeat<Nat32>(0, M_ROWS);
    var c = 0;
    while (c < cols) {
      let col = Region.loadBlob(data, Nat64.fromNat(c * M_ROWS), M_ROWS);
      let quC = Prim.nat64ToNat32(quAt(c));
      var r = 0;
      for (byte in col.values()) {
        ans[r] := ans[r] +% Prim.nat16ToNat32(Prim.nat8ToNat16(byte)) *% quC;
        r += 1;
      };
      c += 1;
    };
    finish(ans, c0, a0)
  };

  /// V5 — arithmetic floor: cells pre-staged in a [var Nat32] arena (4 cells/word), measured
  /// loop is shift-extract + madd only. Shows how much of V1..V4 is data marshalling.
  public func v5(cols : Nat) : async (Nat64, Nat64, Nat64) {
    let staged = VarArray.repeat<Nat32>(0, cols * (M_ROWS / 4));
    var c = 0;
    while (c < cols) {
      let colBytes = Blob.toArray(Region.loadBlob(data, Nat64.fromNat(c * M_ROWS), M_ROWS));
      var w = 0;
      while (w < M_ROWS / 4) {
        let b0 = Nat8.toNat(colBytes[4 * w]);
        let b1 = Nat8.toNat(colBytes[4 * w + 1]);
        let b2 = Nat8.toNat(colBytes[4 * w + 2]);
        let b3 = Nat8.toNat(colBytes[4 * w + 3]);
        staged[c * (M_ROWS / 4) + w] := Prim.natToNat32(b0 + 256 * (b1 + 256 * (b2 + 256 * b3)));
        w += 1;
      };
      c += 1;
    };
    let a0 = Nat64.fromNat(Prim.rts_total_allocation());
    let c0 = Prim.performanceCounter(0);
    let ans = VarArray.repeat<Nat32>(0, M_ROWS);
    c := 0;
    while (c < cols) {
      let quC = quAt(c);
      let colBase = c * (M_ROWS / 4);
      var w = 0;
      while (w < M_ROWS / 4) {
        let packed = Prim.nat32ToNat64(staged[colBase + w]);
        var lane = 0;
        while (lane < 4) {
          let r = 4 * w + lane;
          let cell = (packed >> Nat64.fromNat(8 * lane)) & 0xFF;
          let prev = Prim.nat32ToNat64(ans[r]);
          ans[r] := Prim.nat64ToNat32((prev +% cell *% quC) & MASK32);
          lane += 1;
        };
        w += 1;
      };
      c += 1;
    };
    finish(ans, c0, a0)
  };
}
