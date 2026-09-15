use std::collections::BTreeSet;

use gix::bstr::{BString, ByteSlice};

#[derive(Debug, Default)]
pub struct Policy {
    pub external_filters: BTreeSet<BString>,
    pub required_filters: BTreeSet<BString>,
    pub external_merge_drivers: BTreeSet<BString>,
    pub default_merge_driver: Option<BString>,
}

pub fn sanitize(repo: &mut gix::Repository) -> crate::Result<Policy> {
    let policy = inspect(repo)?;
    let mut config = repo.config_snapshot_mut();

    remove_values(&mut config, "core", &["askPass", "sshCommand"]);
    remove_values(&mut config, "gitoxide", &["commandWithoutShellFallback"]);
    remove_values(&mut config, "credential", &["helper"]);
    remove_values(&mut config, "diff", &["external", "command", "textconv"]);
    remove_values(&mut config, "filter", &["clean", "smudge", "process"]);
    remove_named_merge_sections(&mut config);
    remove_values(&mut config, "merge", &["default"]);
    config.commit()?;
    Ok(policy)
}

fn inspect(repo: &gix::Repository) -> crate::Result<Policy> {
    let snapshot = repo.config_snapshot();
    let config = snapshot.plumbing();
    let mut policy = Policy {
        default_merge_driver: snapshot.string("merge.default"),
        ..Default::default()
    };

    for section in config.sections_by_name("filter").into_iter().flatten() {
        let Some(name) = section
            .header()
            .subsection_name()
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        if ["clean", "smudge", "process"]
            .into_iter()
            .any(|key| section.value(key).is_some())
        {
            policy.external_filters.insert(name.to_owned());
        }
        if let Some(value) = section.value("required") {
            if bool::from(gix::config::Boolean::try_from(value.as_bstr())?) {
                policy.required_filters.insert(name.to_owned());
            } else {
                policy.required_filters.remove(name);
            }
        }
    }
    for section in config.sections_by_name("merge").into_iter().flatten() {
        let Some(name) = section
            .header()
            .subsection_name()
            .filter(|name| !name.is_empty())
        else {
            continue;
        };
        if section.value("driver").is_some() {
            policy.external_merge_drivers.insert(name.to_owned());
        }
    }
    Ok(policy)
}

fn remove_values(config: &mut gix::config::File, section_name: &str, value_names: &[&str]) {
    let ids = config
        .sections_and_ids_by_name(section_name)
        .into_iter()
        .flatten()
        .map(|(_, id)| id)
        .collect::<Vec<_>>();
    for id in ids {
        let Some(mut section) = config.section_mut_by_id(id) else {
            continue;
        };
        for name in value_names {
            while section.remove(name).is_some() {}
        }
    }
}

fn remove_named_merge_sections(config: &mut gix::config::File) {
    let ids = config
        .sections_and_ids_by_name("merge")
        .into_iter()
        .flatten()
        .filter_map(|(section, id)| {
            section
                .header()
                .subsection_name()
                .is_some_and(|name| !name.is_empty())
                .then_some(id)
        })
        .collect::<Vec<_>>();
    for id in ids {
        config.remove_section_by_id(id);
    }
}
