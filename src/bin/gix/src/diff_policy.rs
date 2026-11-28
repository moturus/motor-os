use std::io;

use gix::{
    bstr::{BStr, ByteSlice},
    diff::blob::{Algorithm, Platform, pipeline},
    index::entry::Mode,
};

use crate::{cancellation::Cancellation, repository::OpenedRepository};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryMode {
    Auto,
    Text,
    Binary,
}

impl BinaryMode {
    /// Classify content already obtained from the bounded diff loader. Missing sides are empty.
    pub fn is_binary(&self, before: &[u8], after: &[u8]) -> bool {
        match self {
            BinaryMode::Auto => [before, after]
                .into_iter()
                .any(|data| data[..data.len().min(8_000)].contains(&0)),
            BinaryMode::Text => false,
            BinaryMode::Binary => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathPolicy {
    /// Minimal remains visible so it can be rejected only if this path is classified as text.
    pub algorithm: Algorithm,
    pub binary: BinaryMode,
}

/// Resolve built-in diff metadata without loading or converting file content, and say
/// how a patch writes names and object IDs.
pub struct Resolver<'repo> {
    repo: &'repo gix::Repository,
    cache: Platform,
    matches: gix::attrs::search::Outcome,
    quote_path: bool,
    /// `core.abbrev`, or `None` to derive it from the number of objects when first needed.
    hex_len: Option<usize>,
}

impl<'repo> Resolver<'repo> {
    /// Build policy from sanitized configuration and attributes tied to the caller's held index.
    pub fn new(opened: &'repo OpenedRepository, index: &gix::index::State) -> crate::Result<Self> {
        let attributes = opened.repo.attributes_only(
            index,
            gix::worktree::stack::state::attributes::Source::WorktreeThenIdMapping,
        )?;
        let cache = gix::diff::resource_cache(
            &opened.repo,
            pipeline::Mode::ToGit,
            attributes.detach(),
            Default::default(),
        )?;
        let matches = cache.attr_stack.selected_attribute_matches(["diff"]);
        let config = opened.repo.config_snapshot();
        let hex_len = match config.string("core.abbrev") {
            Some(value) => gix::config::tree::Core::ABBREV
                .try_into_abbreviation(value, opened.repo.object_hash())?,
            None => None,
        };
        Ok(Self {
            repo: &opened.repo,
            cache,
            matches,
            quote_path: config.try_boolean("core.quotePath")?.unwrap_or(true),
            hex_len,
        })
    }

    /// Return the configured global algorithm without resolving path attributes. Without
    /// `diff.algorithm` it is Myers, as in Git.
    pub fn default_algorithm(&self) -> Algorithm {
        self.cache.options.algorithm.unwrap_or(Algorithm::Myers)
    }

    /// Whether names with bytes outside ASCII are written in quotes, as `core.quotePath` says.
    pub fn quote_path(&self) -> bool {
        self.quote_path
    }

    pub fn object_hash(&self) -> gix::hash::Kind {
        self.repo.object_hash()
    }

    /// Shorten `id` as Git does for an `index` line: to `core.abbrev` digits, and to more
    /// while another object of the repository starts with the same digits. `id` itself
    /// need not be an object of the repository.
    pub fn abbreviate(&mut self, id: &gix::oid) -> crate::Result<String> {
        let mut len = match self.hex_len {
            Some(len) => len,
            None => {
                // As Git: enough digits to tell apart the objects that are in packs.
                let packed = self.repo.objects.packed_object_count()?;
                let len = (u64::BITS - packed.leading_zeros()).div_ceil(2).max(7) as usize;
                *self.hex_len.insert(len)
            }
        };
        while len < id.kind().len_in_hex() {
            match self
                .repo
                .objects
                .lookup_prefix(gix::hash::Prefix::new(id, len)?, None)?
            {
                Some(Ok(found)) if found != id => len += 1,
                Some(Err(())) => len += 1,
                _ => break,
            }
        }
        Ok(id.to_hex_with_len(len).to_string())
    }

    pub fn resolve(
        &mut self,
        path: &BStr,
        mode: Mode,
        cancellation: &Cancellation,
    ) -> crate::Result<PathPolicy> {
        cancellation.check()?;
        if !matches!(mode, Mode::FILE | Mode::FILE_EXECUTABLE) {
            return Err(unsupported(path, "diff attributes require a regular file").into());
        }
        self.cache
            .attr_stack
            .at_path(path, Some(mode), &self.repo.objects)?
            .matching_attributes(&mut self.matches);
        cancellation.check()?;

        let state = self
            .matches
            .iter_selected()
            .next()
            .expect("initialized with the diff attribute")
            .assignment
            .state;
        let drivers = self.cache.filter.drivers();
        let driver = state.as_bstr().and_then(|name| {
            drivers
                .binary_search_by(|driver| driver.name.as_bstr().cmp(name))
                .ok()
                .map(|index| &drivers[index])
        });
        if let Some(driver) = driver
            && (driver.command.is_some() || driver.binary_to_text_command.is_some())
        {
            return Err(unsupported(
                path,
                &format!(
                    "diff driver '{}' uses an unsupported external command",
                    driver.name.to_str_lossy().escape_debug()
                ),
            )
            .into());
        }
        let binary = match state {
            gix::attrs::StateRef::Unset => BinaryMode::Binary,
            gix::attrs::StateRef::Set => BinaryMode::Text,
            gix::attrs::StateRef::Value(_) => match driver.and_then(|driver| driver.is_binary) {
                Some(true) => BinaryMode::Binary,
                Some(false) => BinaryMode::Text,
                None => BinaryMode::Auto,
            },
            gix::attrs::StateRef::Unspecified => BinaryMode::Auto,
        };
        Ok(PathPolicy {
            algorithm: driver
                .and_then(|driver| driver.algorithm)
                .or(self.cache.options.algorithm)
                .unwrap_or(Algorithm::Myers),
            binary,
        })
    }
}

fn unsupported(path: &BStr, message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "cannot diff '{}': {message}",
            path.to_str_lossy().escape_debug()
        ),
    )
}
