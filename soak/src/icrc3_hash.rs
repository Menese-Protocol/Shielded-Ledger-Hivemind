//! ICRC-3 representation-independent value hashing, written from the standard (the same
//! normative oracle `src/ICRC3.mo` cites) and pinned by the official test vectors below. The
//! replayer uses this to verify every `phash` link over the whole chain, and the harness uses it
//! to compute shield/unshield intent ids and the unshield recipient binding exactly as
//! `src/Main.mo` does.

use crate::candid_types::Value;
use candid::Nat;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn uleb128(n: &BigUint) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = n.clone();
    let base = BigUint::from(128u8);
    loop {
        let byte = (&v % &base).to_u64_digits().first().copied().unwrap_or(0) as u8;
        v /= &base;
        if v == BigUint::from(0u8) {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn sleb128(n: &candid::Int) -> Vec<u8> {
    // Euclidean low-seven-bits over arbitrary-precision Int, mirroring ICRC3.mo sleb128Int.
    use num_bigint::BigInt;
    let mut out = Vec::new();
    let mut v: BigInt = n.0.clone();
    let base = BigInt::from(128);
    loop {
        let mut low = &v % &base;
        if low < BigInt::from(0) {
            low += &base;
        }
        let byte = low.to_string().parse::<u8>().unwrap();
        let next = (&v - &low) / &base;
        let sign_set = byte >= 64;
        let done = (next == BigInt::from(0) && !sign_set) || (next == BigInt::from(-1) && sign_set);
        out.push(if done { byte } else { byte | 0x80 });
        if done {
            return out;
        }
        v = next;
    }
}

/// The representation-independent hash of an ICRC-3 value.
pub fn hash_value(value: &Value) -> [u8; 32] {
    match value {
        Value::Blob(bytes) => sha256(bytes),
        Value::Text(text) => sha256(text.as_bytes()),
        Value::Nat(n) => sha256(&uleb128(&n.0)),
        Value::Int(n) => sha256(&sleb128(n)),
        Value::Array(values) => {
            let mut hasher = Sha256::new();
            for v in values {
                hasher.update(hash_value(v));
            }
            hasher.finalize().into()
        }
        Value::Map(entries) => {
            let mut pairs: Vec<([u8; 32], [u8; 32])> = entries
                .iter()
                .map(|(k, v)| (sha256(k.as_bytes()), hash_value(v)))
                .collect();
            pairs.sort();
            let mut hasher = Sha256::new();
            for (kh, vh) in pairs {
                hasher.update(kh);
                hasher.update(vh);
            }
            hasher.finalize().into()
        }
    }
}

pub fn nat(n: u64) -> Value {
    Value::Nat(Nat::from(n))
}

pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

pub fn blob_v(b: impl Into<Vec<u8>>) -> Value {
    Value::Blob(crate::candid_types::blob(b.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_icrc3_hash_vectors() {
        let vectors: Vec<(Value, &str)> = vec![
            (nat(42), "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1"),
            (
                Value::Int(candid::Int::from(-42)),
                "de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc",
            ),
            (
                text("Hello, World!"),
                "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
            ),
            (
                blob_v(hex::decode("01020304").unwrap()),
                "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
            ),
            (
                Value::Array(vec![nat(3), text("foo"), blob_v(hex::decode("0506").unwrap())]),
                "514a04011caa503990d446b7dec5d79e19c221ae607fb08b2848c67734d468d6",
            ),
            (
                Value::Map(vec![
                    ("from".into(), blob_v(hex::decode("00abcdef0012340056789a00bcdef000012345678900abcdef01").unwrap())),
                    ("to".into(), blob_v(hex::decode("00ab0def0012340056789a00bcdef000012345678900abcdef01").unwrap())),
                    ("amount".into(), nat(42)),
                    ("created_at".into(), nat(1_699_218_263)),
                    ("memo".into(), nat(0)),
                ]),
                "c56ece650e1de4269c5bdeff7875949e3e2033f85b2d193c2ff4f7f78bdcfc75",
            ),
        ];
        for (value, expected) in vectors {
            assert_eq!(hex::encode(hash_value(&value)), expected);
        }
    }

    #[test]
    fn map_input_order_is_irrelevant() {
        let forward = Value::Map(vec![("alpha".into(), nat(1)), ("beta".into(), text("two"))]);
        let reverse = Value::Map(vec![("beta".into(), text("two")), ("alpha".into(), nat(1))]);
        assert_eq!(hash_value(&forward), hash_value(&reverse));
    }
}
