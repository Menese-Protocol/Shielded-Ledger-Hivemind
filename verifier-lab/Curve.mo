/// **L1 REFERENCE** — BLS12-381 groups G1 (over Fp) and G2 (over Fp2), in pure `Nat`.
///
/// Menese DeFi Team. **THE MOST DANGEROUS LAYER IN THE TOWER.**
///
/// ### Why (read before touching anything here)
/// A dropped **subgroup check** is the classic catastrophic verifier omission (mutants M1/M2). A
/// point on the correct CURVE but in the WRONG SUBGROUP changes **no honest-path output whatsoever**
/// — so a port that skips the check will **byte-match the oracle on every valid proof ever generated**
/// and still **accept forged ones**. Value-matching cannot see it. Only an adversarial vector can.
/// In a shielded pool that is silent, unbounded, invisible inflation.
///
/// So this module implements the subgroup check **literally**: `isInSubgroup(P) := [r]P == O`.
/// Production code uses fast endomorphism-based checks (GLV / Bowe's trick). Those are *clever*, and
/// clever is exactly what you do not want in the correctness anchor — there is no shortcut here to
/// get subtly wrong. L2 may optimize it, and the L2-vs-L1 differential will catch it if it does.
///
/// Curves:  G1: y² = x³ + 4        over Fp
///          G2: y² = x³ + 4(1+u)   over Fp2
///
/// Points are AFFINE with an explicit infinity, and arithmetic uses the textbook chord-and-tangent
/// formulas with a field inversion per operation. That is slow. It is meant to be.

import Fp "Fp";
import T "Tower";


module {
  /// The order of the r-torsion subgroup (same for G1 and G2). Cross-checked against the oracle's
  /// `[curve] r=` line — not copied from a web page.
  public let R : Nat = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

  // =============================================================================================
  // G1 over Fp:  y² = x³ + 4
  // =============================================================================================
  public type G1 = { #inf; #pt : { x : Nat; y : Nat } };

  public let g1Inf : G1 = #inf;

  /// The generator, cross-checked against the oracle's `[generator]` line.
  public let g1Gen : G1 = #pt({
    x = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;
  });

  public func g1IsOnCurve(p : G1) : Bool {
    switch (p) {
      case (#inf) { true };
      case (#pt(q)) {
        // y² == x³ + 4
        let lhs = Fp.sqr(q.y);
        let rhs = Fp.add(Fp.mul(Fp.sqr(q.x), q.x), 4);
        lhs == rhs;
      };
    };
  };

  /// Coordinates must be canonical (< p). A non-canonical encoding must be REJECTED, never reduced.
  public func g1IsCanonical(p : G1) : Bool {
    switch (p) {
      case (#inf) { true };
      case (#pt(q)) { Fp.isCanonical(q.x) and Fp.isCanonical(q.y) };
    };
  };

  public func g1Neg(p : G1) : G1 {
    switch (p) {
      case (#inf) { #inf };
      case (#pt(q)) { #pt({ x = q.x; y = Fp.sub(0, q.y) }) };
    };
  };

  public func g1Eq(a : G1, b : G1) : Bool {
    switch (a, b) {
      case (#inf, #inf) { true };
      case (#pt(p), #pt(q)) { p.x == q.x and p.y == q.y };
      case (_, _) { false };
    };
  };

  /// Textbook affine chord-and-tangent addition.
  public func g1Add(a : G1, b : G1) : G1 {
    switch (a, b) {
      case (#inf, _) { b };
      case (_, #inf) { a };
      case (#pt(p), #pt(q)) {
        if (p.x == q.x) {
          // P + (-P) = O
          if (p.y != q.y or p.y == 0) { return #inf };
          // doubling: lambda = 3x² / 2y
          let num = Fp.mul(3, Fp.sqr(p.x));
          let den = Fp.mul(2, p.y);
          let lam = Fp.mul(num, Fp.inv(den));
          let x3 = Fp.sub(Fp.sqr(lam), Fp.mul(2, p.x));
          let y3 = Fp.sub(Fp.mul(lam, Fp.sub(p.x, x3)), p.y);
          #pt({ x = x3; y = y3 });
        } else {
          // chord: lambda = (y2 - y1) / (x2 - x1)
          let lam = Fp.mul(Fp.sub(q.y, p.y), Fp.inv(Fp.sub(q.x, p.x)));
          let x3 = Fp.sub(Fp.sub(Fp.sqr(lam), p.x), q.x);
          let y3 = Fp.sub(Fp.mul(lam, Fp.sub(p.x, x3)), p.y);
          #pt({ x = x3; y = y3 });
        };
      };
    };
  };

  public func g1Dbl(p : G1) : G1 { g1Add(p, p) };

  /// Double-and-add. Literal.
  public func g1Mul(p : G1, k : Nat) : G1 {
    var result : G1 = #inf;
    var base = p;
    var e = k;
    while (e > 0) {
      if (e % 2 == 1) { result := g1Add(result, base) };
      base := g1Dbl(base);
      e := e / 2;
    };
    result;
  };

  /// **THE CHECK.** `[r]P == O`. Literal, by definition. No endomorphism shortcut.
  public func g1IsInSubgroup(p : G1) : Bool {
    g1Eq(g1Mul(p, R), #inf);
  };

  /// Full validation of a decoded point, with a reason CODE the oracle also emits.
  /// Order matters: canonical, then on-curve, THEN subgroup. A port that rejects a wrong-subgroup
  /// point at the wrong stage has a live acceptance hole behind a coincidental reject.
  public func g1Validate(p : G1) : { #ok; #err : Text } {
    if (not g1IsCanonical(p)) { return #err("E_NONCANONICAL") };
    if (not g1IsOnCurve(p)) { return #err("E_NOT_ON_CURVE") };
    if (not g1IsInSubgroup(p)) { return #err("E_NOT_IN_SUBGROUP") };
    #ok;
  };

  // =============================================================================================
  // G2 over Fp2:  y² = x³ + 4(1+u)
  // =============================================================================================
  public type G2 = { #inf; #pt : { x : T.Fp2; y : T.Fp2 } };

  /// b = 4(1 + u)
  public let g2B : T.Fp2 = { c0 = 4; c1 = 4 };

  public func g2IsOnCurve(p : G2) : Bool {
    switch (p) {
      case (#inf) { true };
      case (#pt(q)) {
        let lhs = T.fp2Sqr(q.y);
        let rhs = T.fp2Add(T.fp2Mul(T.fp2Sqr(q.x), q.x), g2B);
        T.fp2Eq(lhs, rhs);
      };
    };
  };

  public func g2IsCanonical(p : G2) : Bool {
    switch (p) {
      case (#inf) { true };
      case (#pt(q)) {
        Fp.isCanonical(q.x.c0) and Fp.isCanonical(q.x.c1) and Fp.isCanonical(q.y.c0) and Fp.isCanonical(q.y.c1);
      };
    };
  };

  public func g2Neg(p : G2) : G2 {
    switch (p) {
      case (#inf) { #inf };
      case (#pt(q)) { #pt({ x = q.x; y = T.fp2Neg(q.y) }) };
    };
  };

  public func g2Eq(a : G2, b : G2) : Bool {
    switch (a, b) {
      case (#inf, #inf) { true };
      case (#pt(p), #pt(q)) { T.fp2Eq(p.x, q.x) and T.fp2Eq(p.y, q.y) };
      case (_, _) { false };
    };
  };

  public func g2Add(a : G2, b : G2) : G2 {
    switch (a, b) {
      case (#inf, _) { b };
      case (_, #inf) { a };
      case (#pt(p), #pt(q)) {
        if (T.fp2Eq(p.x, q.x)) {
          if (not T.fp2Eq(p.y, q.y) or T.fp2Eq(p.y, T.fp2Zero)) { return #inf };
          let three = T.fp2(3, 0);
          let two = T.fp2(2, 0);
          let num = T.fp2Mul(three, T.fp2Sqr(p.x));
          let den = T.fp2Mul(two, p.y);
          let lam = T.fp2Mul(num, T.fp2Inv(den));
          let x3 = T.fp2Sub(T.fp2Sqr(lam), T.fp2Mul(two, p.x));
          let y3 = T.fp2Sub(T.fp2Mul(lam, T.fp2Sub(p.x, x3)), p.y);
          #pt({ x = x3; y = y3 });
        } else {
          let lam = T.fp2Mul(T.fp2Sub(q.y, p.y), T.fp2Inv(T.fp2Sub(q.x, p.x)));
          let x3 = T.fp2Sub(T.fp2Sub(T.fp2Sqr(lam), p.x), q.x);
          let y3 = T.fp2Sub(T.fp2Mul(lam, T.fp2Sub(p.x, x3)), p.y);
          #pt({ x = x3; y = y3 });
        };
      };
    };
  };

  public func g2Dbl(p : G2) : G2 { g2Add(p, p) };

  public func g2Mul(p : G2, k : Nat) : G2 {
    var result : G2 = #inf;
    var base = p;
    var e = k;
    while (e > 0) {
      if (e % 2 == 1) { result := g2Add(result, base) };
      base := g2Dbl(base);
      e := e / 2;
    };
    result;
  };

  /// Same literal definition as G1. No shortcut.
  public func g2IsInSubgroup(p : G2) : Bool {
    g2Eq(g2Mul(p, R), #inf);
  };

  public func g2Validate(p : G2) : { #ok; #err : Text } {
    if (not g2IsCanonical(p)) { return #err("E_NONCANONICAL") };
    if (not g2IsOnCurve(p)) { return #err("E_NOT_ON_CURVE") };
    if (not g2IsInSubgroup(p)) { return #err("E_NOT_IN_SUBGROUP") };
    #ok;
  };

}
