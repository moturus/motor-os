//! JSON represents configuration maps with structured keys as pairs.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

pub(super) fn serialize<K: Serialize, V: Serialize, S: Serializer>(
    map: &BTreeMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    map.iter().collect::<Vec<_>>().serialize(serializer)
}

pub(super) fn deserialize<
    'de,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
>(
    deserializer: D,
) -> Result<BTreeMap<K, V>, D::Error> {
    Vec::<(K, V)>::deserialize(deserializer).map(|pairs| pairs.into_iter().collect())
}

#[cfg(target_os = "motor")]
pub(super) mod environment {
    use super::*;
    use std::ffi::OsString;

    pub(crate) fn serialize<S: Serializer>(
        map: &BTreeMap<String, OsString>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let values = map
            .iter()
            .map(|(name, value)| {
                value.to_str().map(|value| (name, value)).ok_or_else(|| {
                    serde::ser::Error::custom("Motor environment value is not Unicode")
                })
            })
            .collect::<Result<BTreeMap<_, _>, S::Error>>()?;
        values.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<String, OsString>, D::Error> {
        BTreeMap::<String, String>::deserialize(deserializer).map(|values| {
            values
                .into_iter()
                .map(|(name, value)| (name, value.into()))
                .collect()
        })
    }
}
