use std::collections::BTreeSet;

use clap::ArgMatches;

use crate::diagnostic::{Error, Result};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FeatureSelection {
    pub features: BTreeSet<String>,
    pub all: bool,
    pub no_default: bool,
}

impl FeatureSelection {
    pub(super) fn parse(arguments: &ArgMatches) -> Result<Self> {
        let mut features = BTreeSet::new();
        for list in super::optional_values(arguments, "features") {
            for feature in list.split_whitespace().flat_map(|value| value.split(',')) {
                if feature.is_empty() {
                    continue;
                }
                if let Some((_, dependency_feature)) = feature.split_once('/') {
                    if dependency_feature.contains('/') {
                        return Err(Error::usage(
                            format!("multiple slashes in feature `{feature}` are not allowed"),
                            "use `package/feature` or `dependency?/feature`",
                        ));
                    }
                } else if feature.starts_with("dep:") {
                    return Err(Error::usage(
                        format!("feature `{feature}` cannot use explicit `dep:` syntax"),
                        "select the package's feature or implicit optional-dependency feature",
                    ));
                }
                features.insert(feature.to_owned());
            }
        }
        let flag = |name| {
            arguments
                .try_get_one::<bool>(name)
                .ok()
                .flatten()
                .copied()
                .unwrap_or(false)
        };
        Ok(Self {
            features,
            all: flag("all-features"),
            no_default: flag("no-default-features"),
        })
    }
}
