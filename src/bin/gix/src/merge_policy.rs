use std::io;

use gix::{
    bstr::{BStr, ByteSlice},
    index::entry::Mode,
    merge::blob::BuiltinDriver,
    worktree::stack::state::attributes::Source,
};

use crate::{cancellation::Cancellation, command_config::Policy, repository::OpenedRepository};

/// Reject merge attributes or defaults that cannot be honored without an external command.
///
/// The complete supplied index provides the attribute context. The repository must already
/// have the application's sanitized policy.
pub fn reject_unsupported(
    opened: &OpenedRepository,
    index: &gix::index::State,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let mut attributes = opened.repo.attributes_only(index, Source::IdMapping)?;
    let mut matches = attributes.selected_attribute_matches(["merge"]);
    for entry in index.entries() {
        cancellation.check()?;
        if matches!(entry.mode, Mode::DIR | Mode::COMMIT) {
            continue;
        }
        let path = entry.path(index);
        attributes
            .at_entry(path, Some(entry.mode))?
            .matching_attributes(&mut matches);
        let state = matches
            .iter_selected()
            .next()
            .expect("initialized with the merge attribute")
            .assignment
            .state;
        let (name, is_default) = match state {
            gix::attrs::StateRef::Set | gix::attrs::StateRef::Unset => continue,
            gix::attrs::StateRef::Value(name) => (Some(name.as_bstr()), false),
            gix::attrs::StateRef::Unspecified => (
                opened
                    .command_policy
                    .default_merge_driver
                    .as_ref()
                    .map(|name| name.as_bstr()),
                true,
            ),
        };
        if let Some(name) = name {
            reject_driver(path, name, is_default, &opened.command_policy)?;
        }
    }
    cancellation.check()
}

fn reject_driver(path: &BStr, name: &BStr, is_default: bool, policy: &Policy) -> crate::Result {
    let kind = if policy.external_merge_drivers.contains(name) {
        "configured external"
    } else if name
        .to_str()
        .ok()
        .and_then(BuiltinDriver::by_name)
        .is_none()
    {
        "unknown"
    } else {
        return Ok(());
    };
    let default = if is_default { "default " } else { "" };
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "path '{}' uses {kind} {default}merge driver '{}'",
            path.to_str_lossy().escape_debug(),
            name.to_str_lossy().escape_debug()
        ),
    )
    .into())
}
