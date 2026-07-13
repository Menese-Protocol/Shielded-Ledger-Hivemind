/// Optimized BLS12-381 final exponentiation in Motoko.
///
/// Literal port of arkworks 0.5's ePrint 2020/875 chain.  The easy part uses conjugation, one
/// inversion, and Frobenius^2; the hard part uses Granger-Scott cyclotomic squaring, NAF exp-by-x,
/// and table-driven Frobenius.  Rust arkworks remains the differential oracle, not the product.

import FpM "FpMont";
import TM "TowerMont";

module {
  public let X_ABS : Nat = 0xd201000000010000;

  func m2(c0 : Nat, c1 : Nat) : TM.Fp2M {
    { c0 = FpM.toMont(c0); c1 = FpM.toMont(c1) };
  };

  let a : Nat = 793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350;
  let pMinusA : Nat = 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437;
  let pMinusAMinus1 : Nat = 4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436;

  // Motoko library-module initializers must be static, so the pinned normal-form constants are
  // converted to Montgomery only for the selected power. Final exponentiation uses powers 1 and 2.
  func frob6c1(power : Nat) : TM.Fp2M {
    switch (power % 6) {
      case (0) { m2(1, 0) }; case (1) { m2(0, pMinusAMinus1) }; case (2) { m2(a, 0) };
      case (3) { m2(0, 1) }; case (4) { m2(pMinusAMinus1, 0) }; case (_) { m2(0, a) };
    };
  };
  func frob6c2(power : Nat) : TM.Fp2M {
    switch (power % 6) {
      case (0) { m2(1, 0) }; case (1) { m2(pMinusA, 0) }; case (2) { m2(pMinusAMinus1, 0) };
      case (3) { m2(FpM.P - 1, 0) }; case (4) { m2(a, 0) }; case (_) { m2(a + 1, 0) };
    };
  };

  // ark-bls12-381 0.5 `FROBENIUS_COEFF_FP12_C1`.
  func frob12c1(power : Nat) : TM.Fp2M {
    switch (power % 12) {
      case (0) { m2(1, 0) };
      case (1) { m2(3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760, 151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027) };
      case (2) { m2(a + 1, 0) };
      case (3) { m2(2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530, 1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257) };
      case (4) { m2(a, 0) };
      case (5) { m2(3125332594171059424908108096204648978570118281977575435832422631601824034463382777937621250592425535493320683825557, 877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230) };
      case (6) { m2(FpM.P - 1, 0) };
      case (7) { m2(151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027, 3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760) };
      case (8) { m2(pMinusAMinus1, 0) };
      case (9) { m2(1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257, 2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530) };
      case (10) { m2(pMinusA, 0) };
      case (_) { m2(877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230, 3125332594171059424908108096204648978570118281977575435832422631601824034463382777937621250592425535493320683825557) };
    };
  };

  func fp2Frobenius(x : TM.Fp2M, power : Nat) : TM.Fp2M {
    if (power % 2 == 0) { x } else { { c0 = x.c0; c1 = FpM.sub(0, x.c1) } };
  };
  func fp6MulByFp2(x : TM.Fp6M, c : TM.Fp2M) : TM.Fp6M {
    { c0 = TM.fp2Mul(x.c0, c); c1 = TM.fp2Mul(x.c1, c); c2 = TM.fp2Mul(x.c2, c) };
  };
  func fp6Frobenius(x : TM.Fp6M, power : Nat) : TM.Fp6M {
    let c0 = fp2Frobenius(x.c0, power);
    let c1 = TM.fp2Mul(fp2Frobenius(x.c1, power), frob6c1(power));
    let c2 = TM.fp2Mul(fp2Frobenius(x.c2, power), frob6c2(power));
    { c0; c1; c2 };
  };

  /// Table-driven Frobenius, diffed for every power 0..11 against L1's literal x^(p^i).
  public func fp12Frobenius(x : TM.Fp12M, power : Nat) : TM.Fp12M {
    {
      c0 = fp6Frobenius(x.c0, power);
      c1 = fp6MulByFp2(fp6Frobenius(x.c1, power), frob12c1(power));
    };
  };

  /// Square (a + b*y) in Fp4 where y^2 = xi = 1+u; returns (t0,t1).
  func fp4Square(a0 : TM.Fp2M, a1 : TM.Fp2M) : (TM.Fp2M, TM.Fp2M) {
    let ab = TM.fp2Mul(a0, a1);
    let t0 = TM.fp2Sub(
      TM.fp2Sub(TM.fp2Mul(TM.fp2Add(a0, a1), TM.fp2Add(TM.fp2MulByNonresidue(a1), a0)), ab),
      TM.fp2MulByNonresidue(ab),
    );
    (t0, TM.fp2Add(ab, ab));
  };
  func tripleMinusDouble(t : TM.Fp2M, z : TM.Fp2M) : TM.Fp2M {
    let delta = TM.fp2Sub(t, z);
    TM.fp2Add(TM.fp2Add(delta, delta), t);
  };
  func triplePlusDouble(t : TM.Fp2M, z : TM.Fp2M) : TM.Fp2M {
    let sum = TM.fp2Add(t, z);
    TM.fp2Add(TM.fp2Add(sum, sum), t);
  };

  /// Granger-Scott square. Valid only after the easy part has placed the input in the cyclotomic
  /// subgroup; the gate compares it with generic Fp12 square on such values.
  public func cyclotomicSquare(x : TM.Fp12M) : TM.Fp12M {
    let r0 = x.c0.c0; let r4 = x.c0.c1; let r3 = x.c0.c2;
    let r2 = x.c1.c0; let r1 = x.c1.c1; let r5 = x.c1.c2;
    let (t0, t1) = fp4Square(r0, r1);
    let (t2, t3) = fp4Square(r2, r3);
    let (t4, t5) = fp4Square(r4, r5);
    let nrT5 = TM.fp2MulByNonresidue(t5);
    {
      c0 = {
        c0 = tripleMinusDouble(t0, r0);
        c1 = tripleMinusDouble(t2, r4);
        c2 = tripleMinusDouble(t4, r3);
      };
      c1 = {
        c0 = triplePlusDouble(nrT5, r2);
        c1 = triplePlusDouble(t1, r1);
        c2 = triplePlusDouble(t3, r5);
      };
    };
  };

  /// Arkworks' NAF cyclotomic exponentiation by negative BLS parameter x.
  public func expByX(x : TM.Fp12M) : TM.Fp12M {
    let inverse = TM.fp12Conj(x);
    var result = TM.fp12OneM();
    var found = false;
    var i : Nat = 65;
    while (i > 0) {
      i -= 1;
      let digit : Int = nafDigit(i);
      if (found) { result := cyclotomicSquare(result) };
      if (digit != 0) {
        found := true;
        if (digit > 0) { result := TM.fp12Mul(result, x) }
        else { result := TM.fp12Mul(result, inverse) };
      };
    };
    // BLS12-381 x is negative.
    TM.fp12Conj(result);
  };

  /// f^((p^6-1)(p^2+1)); output is in the cyclotomic subgroup.
  public func easyPart(f : TM.Fp12M) : TM.Fp12M {
    let f1 = TM.fp12Conj(f);
    let f2 = TM.fp12Inv(f);
    let r0 = TM.fp12Mul(f1, f2);
    TM.fp12Mul(fp12Frobenius(r0, 2), r0);
  };

  /// Exact arkworks 0.5 / ePrint 2020/875 final exponentiation chain.
  public func finalExponentiate(f : TM.Fp12M) : TM.Fp12M {
    var r = easyPart(f);
    var y0 = cyclotomicSquare(r);
    var y1 = expByX(r);
    var y2 = TM.fp12Conj(r);
    y1 := TM.fp12Mul(y1, y2);
    y2 := expByX(y1);
    y1 := TM.fp12Conj(y1);
    y1 := TM.fp12Mul(y1, y2);
    y2 := expByX(y1);
    y1 := fp12Frobenius(y1, 1);
    y1 := TM.fp12Mul(y1, y2);
    r := TM.fp12Mul(r, y0);
    y0 := expByX(y1);
    y2 := expByX(y0);
    y0 := fp12Frobenius(y1, 2);
    y1 := TM.fp12Conj(y1);
    y1 := TM.fp12Mul(y1, y2);
    y1 := TM.fp12Mul(y1, y0);
    TM.fp12Mul(r, y1);
  };

  // NAF of 0xd201000000010000, little-endian nonzero positions:
  // 16:+1, 48:+1, 57:+1, 60:+1, 62:-1, 64:+1.
  func nafDigit(i : Nat) : Int {
    if (i == 16 or i == 48 or i == 57 or i == 60 or i == 64) { 1 }
    else if (i == 62) { -1 }
    else { 0 };
  };
}
