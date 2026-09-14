use std::{collections::HashSet, fmt};

use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use zolana_keypair::KeypairError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hex<const N: usize>(pub [u8; N]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

fn hex_bytes<E: serde::de::Error>(value: &str) -> Result<Vec<u8>, E> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(E::custom("expected lowercase hexadecimal"));
    }
    hex::decode(value).map_err(E::custom)
}

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = hex_bytes::<D::Error>(&value)?;
        let actual = bytes.len();
        Ok(Self(bytes.try_into().map_err(|_| {
            serde::de::Error::custom(format!("expected {N} bytes, got {actual}"))
        })?))
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(hex_bytes::<D::Error>(&String::deserialize(
            deserializer,
        )?)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExpectedError {
    InvalidSecretKey,
    InvalidDerivationSeed { got: usize, expected: usize },
}

impl ExpectedError {
    pub fn candidate_error(&self) -> KeypairError {
        match *self {
            Self::InvalidSecretKey => KeypairError::InvalidSecretKey,
            Self::InvalidDerivationSeed { got, expected } => {
                KeypairError::InvalidDerivationSeed { got, expected }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expected<O> {
    Ok { outputs: O },
    Error { error: ExpectedError },
}

#[derive(Clone, Debug, Serialize)]
pub struct Case<I, O> {
    pub id: String,
    pub description: String,
    pub input: I,
    pub expected: Expected<O>,
}

impl<'de, I: DeserializeOwned, O: DeserializeOwned> Deserialize<'de> for Case<I, O> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Record {
            id: String,
            description: String,
            input: serde_json::Value,
            expected: serde_json::Value,
        }
        let record = Record::deserialize(deserializer)?;
        let input = serde_json::from_value(record.input)
            .map_err(|error| serde::de::Error::custom(format!("{}: input: {error}", record.id)))?;
        let expected = serde_json::from_value(record.expected).map_err(|error| {
            serde::de::Error::custom(format!("{}: expected: {error}", record.id))
        })?;
        Ok(Self {
            id: record.id,
            description: record.description,
            input,
            expected,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningInput {
    pub signing_secret: Hex<32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpansionInput {
    pub seed: Bytes,
}

fn account_index<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let index = u32::deserialize(deserializer)?;
    if index >= 0x8000_0000 {
        return Err(serde::de::Error::custom("index must be below 2^31"));
    }
    Ok(index)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedInput {
    pub mnemonic: String,
    pub passphrase: String,
    #[serde(deserialize_with = "account_index")]
    pub account: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildInput {
    pub parent_key: Hex<32>,
    pub parent_chain: Hex<32>,
    #[serde(deserialize_with = "account_index")]
    pub index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOutput {
    pub nullifier_secret: Hex<31>,
    pub nullifier_pubkey: Hex<32>,
    pub viewing_secret: Hex<32>,
    pub viewing_pubkey: Hex<33>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519Output {
    pub signer_pubkey: Hex<32>,
    pub derivation_message: Bytes,
    pub derivation_seed: Hex<64>,
    pub nullifier_secret: Hex<31>,
    pub nullifier_pubkey: Hex<32>,
    pub viewing_secret: Hex<32>,
    pub viewing_pubkey: Hex<33>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P256Output {
    pub derivation_seed: Hex<32>,
    pub nullifier_secret: Hex<31>,
    pub nullifier_pubkey: Hex<32>,
    pub viewing_secret: Hex<32>,
    pub viewing_pubkey: Hex<33>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedOutput {
    pub signing_secret: Hex<32>,
    pub signing_pubkey: Hex<32>,
    pub nullifier_secret: Hex<31>,
    pub nullifier_pubkey: Hex<32>,
    pub viewing_secret: Hex<32>,
    pub viewing_pubkey: Hex<33>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeOutput {
    pub private_key: Hex<32>,
    pub chain_code: Hex<32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(bound(deserialize = "O: DeserializeOwned"))]
pub struct RailFixture<O> {
    pub derivation_cases: Vec<Case<SigningInput, O>>,
    pub role_expansion_cases: Vec<Case<ExpansionInput, RoleOutput>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedFixture {
    pub cases: Vec<Case<SeedInput, SeedOutput>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slip10Fixture {
    pub master_cases: Vec<Case<ExpansionInput, NodeOutput>>,
    pub child_cases: Vec<Case<ChildInput, NodeOutput>>,
}

pub trait Fixture {
    fn case_metadata(&self) -> Vec<Vec<(&str, &str)>>;
}

fn metadata<I, O>(cases: &[Case<I, O>]) -> Vec<(&str, &str)> {
    cases
        .iter()
        .map(|case| (case.id.as_str(), case.description.as_str()))
        .collect()
}

impl<O> Fixture for RailFixture<O> {
    fn case_metadata(&self) -> Vec<Vec<(&str, &str)>> {
        vec![
            metadata(&self.derivation_cases),
            metadata(&self.role_expansion_cases),
        ]
    }
}
impl Fixture for SeedFixture {
    fn case_metadata(&self) -> Vec<Vec<(&str, &str)>> {
        vec![metadata(&self.cases)]
    }
}
impl Fixture for Slip10Fixture {
    fn case_metadata(&self) -> Vec<Vec<(&str, &str)>> {
        vec![metadata(&self.master_cases), metadata(&self.child_cases)]
    }
}

pub fn parse_fixture<T: DeserializeOwned + Fixture>(source: &str) -> Result<T, String> {
    let fixture: T = serde_json::from_str(source).map_err(|error| error.to_string())?;
    let mut ids = HashSet::new();
    for group in fixture.case_metadata() {
        if group.is_empty() {
            return Err("case list must not be empty".into());
        }
        for (id, description) in group {
            if id.is_empty() || description.trim().is_empty() {
                return Err("case ID and description must not be empty".into());
            }
            if !ids.insert(id) {
                return Err(format!("duplicate case ID: {id}"));
            }
        }
    }
    Ok(fixture)
}

pub fn load_fixture<T: DeserializeOwned + Fixture>(source: &str, suite: &str) -> T {
    parse_fixture(source).unwrap_or_else(|error| panic!("{suite}: invalid fixture: {error}"))
}

pub fn assert_outputs<O: Serialize>(context: &str, actual: &O, expected: &O) {
    let actual = serde_json::to_value(actual).unwrap();
    let expected = serde_json::to_value(expected).unwrap();
    for (field, value) in expected.as_object().expect("output is an object") {
        assert_eq!(&actual[field], value, "{context}: {field}");
    }
}

pub fn assert_result<O: Serialize + fmt::Debug>(
    context: &str,
    actual: Result<O, KeypairError>,
    expected: &Expected<O>,
) {
    match (actual, expected) {
        (Ok(actual), Expected::Ok { outputs }) => assert_outputs(context, &actual, outputs),
        (Err(actual), Expected::Error { error }) => {
            assert_eq!(actual, error.candidate_error(), "{context}: error");
        }
        (actual, expected) => {
            panic!("{context}: outcome mismatch: actual {actual:?}, expected {expected:?}")
        }
    }
}
