use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::Number;

use crate::diagnostic::{Error, Result};

pub const DOCUMENT_LIMITS: Limits = Limits {
    max_bytes: 16 * 1024 * 1024,
    max_depth: 64,
    max_string_bytes: 4 * 1024 * 1024,
    max_collection_items: 100_000,
    max_nodes: 200_000,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_string_bytes: usize,
    pub max_collection_items: usize,
    pub max_nodes: usize,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

#[allow(dead_code)]
impl Value {
    pub fn load(path: &Path, context: &str) -> Result<Self> {
        let mut file = File::open(path).map_err(|error| {
            Error::failure(format!("failed to read `{}`: {error}", path.display()))
        })?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(DOCUMENT_LIMITS.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                Error::failure(format!("failed to read `{}`: {error}", path.display()))
            })?;
        Self::parse_with_limits(path, context, &bytes, DOCUMENT_LIMITS)
    }

    pub fn parse(path: &Path, context: &str, bytes: &[u8]) -> Result<Self> {
        Self::parse_with_limits(path, context, bytes, DOCUMENT_LIMITS)
    }

    fn parse_with_limits(path: &Path, context: &str, bytes: &[u8], limits: Limits) -> Result<Self> {
        if bytes.len() > limits.max_bytes {
            return Err(Error::at(
                path,
                1,
                format!(
                    "{context} exceeds the JSON byte limit of {}",
                    limits.max_bytes
                ),
                "reduce the document before invoking Lorry",
            ));
        }
        let nodes = Cell::new(0);
        let seed = Seed {
            limits,
            depth: 0,
            nodes: &nodes,
        };
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let value = seed.deserialize(&mut deserializer).map_err(|error| {
            Error::at(
                path,
                error.line(),
                format!("invalid bounded JSON in {context}: {error}"),
                "fix duplicate keys, truncation, syntax, or configured size limits",
            )
        })?;
        deserializer.end().map_err(|error| {
            Error::at(
                path,
                error.line(),
                format!("invalid trailing JSON in {context}: {error}"),
                "keep exactly one JSON value",
            )
        })?;
        Ok(value)
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(value) => value.as_u64(),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.get(key)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = String::new();
        write_canonical(self, &mut output);
        output.push('\n');
        output.into_bytes()
    }
}

#[derive(Clone, Copy)]
struct Seed<'a> {
    limits: Limits,
    depth: usize,
    nodes: &'a Cell<usize>,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > self.limits.max_depth {
            return Err(D::Error::custom(format!(
                "JSON nesting depth exceeds {}",
                self.limits.max_depth
            )));
        }
        let nodes = self.nodes.get().saturating_add(1);
        if nodes > self.limits.max_nodes {
            return Err(D::Error::custom(format!(
                "JSON node count exceeds {}",
                self.limits.max_nodes
            )));
        }
        self.nodes.set(nodes);
        deserializer.deserialize_any(ValueVisitor { seed: self })
    }
}

struct ValueVisitor<'a> {
    seed: Seed<'a>,
}

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value within Lorry's configured limits")
    }

    fn visit_unit<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        self.string(value)
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        self.string(value)
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > self.seed.limits.max_string_bytes {
            return Err(E::custom(format!(
                "JSON string exceeds {} bytes",
                self.seed.limits.max_string_bytes
            )));
        }
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element_seed(self.seed.child())? {
            if output.len() >= self.seed.limits.max_collection_items {
                return Err(A::Error::custom(format!(
                    "JSON array exceeds {} items",
                    self.seed.limits.max_collection_items
                )));
            }
            output.push(value);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > self.seed.limits.max_string_bytes {
                return Err(A::Error::custom(format!(
                    "JSON object key exceeds {} bytes",
                    self.seed.limits.max_string_bytes
                )));
            }
            if output.len() >= self.seed.limits.max_collection_items {
                return Err(A::Error::custom(format!(
                    "JSON object exceeds {} entries",
                    self.seed.limits.max_collection_items
                )));
            }
            if output.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "duplicate JSON object key `{key}`"
                )));
            }
            let value = map.next_value_seed(self.seed.child())?;
            output.insert(key, value);
        }
        Ok(Value::Object(output))
    }
}

impl ValueVisitor<'_> {
    fn string<E>(self, value: &str) -> std::result::Result<Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > self.seed.limits.max_string_bytes {
            return Err(E::custom(format!(
                "JSON string exceeds {} bytes",
                self.seed.limits.max_string_bytes
            )));
        }
        Ok(Value::String(value.to_owned()))
    }
}

impl Seed<'_> {
    fn child(self) -> Self {
        Self {
            depth: self.depth.saturating_add(1),
            ..self
        }
    }
}

fn write_canonical(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(false) => output.push_str("false"),
        Value::Bool(true) => output.push_str("true"),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => write_string(value, output),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical(value, output);
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_string(key, output);
                output.push(':');
                write_canonical(value, output);
            }
            output.push('}');
        }
    }
}

fn write_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{00}'..='\u{1f}' => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", character as u32).unwrap();
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LIMITS: Limits = Limits {
        max_bytes: 128,
        max_depth: 2,
        max_string_bytes: 8,
        max_collection_items: 3,
        max_nodes: 8,
    };

    fn parsed(input: &str) -> Result<Value> {
        Value::parse_with_limits(
            Path::new("record.json"),
            "test record",
            input.as_bytes(),
            TEST_LIMITS,
        )
    }

    #[test]
    fn parses_every_value_and_writes_sorted_canonical_json() {
        let value = parsed(r#"{"z":null,"a":[true,-2,3.5],"s":"\u2603"}"#).unwrap();
        assert_eq!(value.get("s").and_then(Value::as_str), Some("☃"));
        assert_eq!(
            value.canonical_bytes(),
            b"{\"a\":[true,-2,3.5],\"s\":\"\xe2\x98\x83\",\"z\":null}\n"
        );
    }

    #[test]
    fn rejects_duplicate_keys_truncation_and_trailing_values() {
        for input in [
            r#"{"same":1,"same":2}"#,
            r#"{"unfinished":[1,2}"#,
            r#"{"ok":true} false"#,
        ] {
            assert!(parsed(input).is_err(), "{input}");
        }
    }

    #[test]
    fn enforces_byte_string_collection_depth_and_node_limits() {
        for input in [
            format!("\"{}\"", "x".repeat(9)),
            "[1,2,3,4]".to_owned(),
            "{\"a\":{\"b\":{\"c\":1}}}".to_owned(),
            "[[1,2,3],[4,5,6]]".to_owned(),
            " ".repeat(129),
        ] {
            assert!(parsed(&input).is_err(), "{input}");
        }
    }

    #[test]
    fn exposes_narrow_typed_accessors() {
        let value = parsed(r#"{"array":["x"],"bool":false,"integer":7}"#).unwrap();
        assert_eq!(value.get("array").unwrap().as_array().unwrap().len(), 1);
        assert_eq!(value.get("bool").unwrap().as_bool(), Some(false));
        assert_eq!(value.get("integer").unwrap().as_u64(), Some(7));
        assert!(value.as_object().is_some());
    }
}
