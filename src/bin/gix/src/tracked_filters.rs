use std::io;

use gix::{bstr::ByteSlice, index::entry::Mode, worktree::stack::state::attributes::Source};

use crate::{cancellation::Cancellation, command_config::Policy, repository::OpenedRepository};

pub(crate) fn reject_unsupported(
    opened: &OpenedRepository,
    index: &gix::index::State,
    source: Source,
    cancellation: &Cancellation,
) -> crate::Result {
    reject_unsupported_selected(
        opened,
        index,
        source,
        index
            .entries()
            .iter()
            .map(|entry| (entry.path(index), entry.mode)),
        cancellation,
    )
}

pub(crate) fn reject_unsupported_selected<'a>(
    opened: &OpenedRepository,
    index: &gix::index::State,
    source: Source,
    selected: impl IntoIterator<Item = (&'a gix::bstr::BStr, Mode)>,
    cancellation: &Cancellation,
) -> crate::Result {
    let policy = &opened.command_policy;
    if !policy.has_unsupported_filters() {
        return Ok(());
    }
    let attributes = opened.repo.attributes_only(index, source)?;
    check_attributes(policy, attributes, selected, cancellation)
}

pub(crate) fn check_attributes<'a>(
    policy: &Policy,
    mut attributes: gix::AttributeStack<'_>,
    selected: impl IntoIterator<Item = (&'a gix::bstr::BStr, Mode)>,
    cancellation: &Cancellation,
) -> crate::Result {
    let mut matches = attributes.selected_attribute_matches(["filter"]);
    for (path, mode) in selected {
        cancellation.check()?;
        if !matches!(mode, Mode::FILE | Mode::FILE_EXECUTABLE) {
            continue;
        }
        attributes
            .at_entry(path, Some(mode))?
            .matching_attributes(&mut matches);
        let filter = matches.iter_selected().next().and_then(|item| {
            if let gix::attrs::StateRef::Value(value) = item.assignment.state {
                Some(value.as_bstr())
            } else {
                None
            }
        });
        let Some(filter) = filter else {
            continue;
        };
        if policy.external_filters.contains(filter) || policy.required_filters.contains(filter) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "path '{}' uses unsupported filter '{}'",
                    path.to_str_lossy().escape_debug(),
                    filter.to_str_lossy().escape_debug()
                ),
            )
            .into());
        }
    }
    Ok(())
}
