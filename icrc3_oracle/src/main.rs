use candid::{Int, Nat};
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::str::FromStr;

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", content = "value")]
enum OracleValue {
    Blob(String),
    Text(String),
    Nat(String),
    Int(String),
    Array(Vec<OracleValue>),
    Map(Vec<(String, OracleValue)>),
}

impl TryFrom<OracleValue> for ICRC3Value {
    type Error = String;

    fn try_from(value: OracleValue) -> Result<Self, Self::Error> {
        match value {
            OracleValue::Blob(hex_value) => Ok(Self::Blob(ByteBuf::from(
                hex::decode(hex_value).map_err(|error| error.to_string())?,
            ))),
            OracleValue::Text(text) => Ok(Self::Text(text)),
            OracleValue::Nat(number) => Ok(Self::Nat(
                Nat::from_str(&number).map_err(|error| error.to_string())?,
            )),
            OracleValue::Int(number) => Ok(Self::Int(
                Int::from_str(&number).map_err(|error| error.to_string())?,
            )),
            OracleValue::Array(values) => Ok(Self::Array(
                values
                    .into_iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            OracleValue::Map(entries) => {
                let mut map = BTreeMap::new();
                for (key, entry) in entries {
                    if map.insert(key.clone(), Self::try_from(entry)?).is_some() {
                        return Err(format!("duplicate ICRC-3 map key: {key}"));
                    }
                }
                Ok(Self::Map(map))
            }
        }
    }
}

fn hash(value: OracleValue) -> Result<String, String> {
    Ok(hex::encode(ICRC3Value::try_from(value)?.hash()))
}

fn main() -> Result<(), String> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| error.to_string())?;
    let value = serde_json::from_str(&input).map_err(|error| error.to_string())?;
    println!("{}", hash(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{hash, OracleValue};

    fn blob(value: &str) -> OracleValue {
        OracleValue::Blob(value.to_string())
    }

    #[test]
    fn official_icrc3_hash_vectors() {
        let vectors = [
            (
                OracleValue::Nat("42".into()),
                "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1",
            ),
            (
                OracleValue::Int("-42".into()),
                "de5a6f78116eca62d7fc5ce159d23ae6b889b365a1739ad2cf36f925a140d0cc",
            ),
            (
                OracleValue::Text("Hello, World!".into()),
                "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
            ),
            (
                blob("01020304"),
                "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
            ),
            (
                OracleValue::Array(vec![
                    OracleValue::Nat("3".into()),
                    OracleValue::Text("foo".into()),
                    blob("0506"),
                ]),
                "514a04011caa503990d446b7dec5d79e19c221ae607fb08b2848c67734d468d6",
            ),
            (
                OracleValue::Map(vec![
                    ("from".into(), blob("00abcdef0012340056789a00bcdef000012345678900abcdef01")),
                    ("to".into(), blob("00ab0def0012340056789a00bcdef000012345678900abcdef01")),
                    ("amount".into(), OracleValue::Nat("42".into())),
                    ("created_at".into(), OracleValue::Nat("1699218263".into())),
                    ("memo".into(), OracleValue::Nat("0".into())),
                ]),
                "c56ece650e1de4269c5bdeff7875949e3e2033f85b2d193c2ff4f7f78bdcfc75",
            ),
        ];

        for (value, expected) in vectors {
            assert_eq!(hash(value).unwrap(), expected);
        }
    }

    #[test]
    fn nat_43_fails_the_nat_42_digest() {
        assert_ne!(
            hash(OracleValue::Nat("43".into())).unwrap(),
            "684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1"
        );
    }

    #[test]
    fn map_input_order_is_irrelevant() {
        let forward = OracleValue::Map(vec![
            ("alpha".into(), OracleValue::Nat("1".into())),
            ("beta".into(), OracleValue::Text("two".into())),
        ]);
        let reverse = OracleValue::Map(vec![
            ("beta".into(), OracleValue::Text("two".into())),
            ("alpha".into(), OracleValue::Nat("1".into())),
        ]);
        assert_eq!(hash(forward).unwrap(), hash(reverse).unwrap());
    }
}
