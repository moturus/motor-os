//! `gix remote [-v]`: list configured remotes in the format of `git remote`.

use std::io::Write;

use gix::{bstr::ByteSlice, remote::Direction};

use crate::cancellation::Cancellation;

/// List remote names in order; with `verbose`, add the fetch URL and every
/// push URL, rewritten by `url.<base>.insteadOf` and `pushInsteadOf` as Git does.
pub fn list(
    repo: &gix::Repository,
    verbose: bool,
    mut out: impl Write,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    for name in repo.remote_names() {
        cancellation.check()?;
        if !verbose {
            writeln!(out, "{name}")?;
            continue;
        }
        let remote = repo.find_remote(name.as_bstr())?;
        // Git fetches from the first URL only; without one it prints the name and a tab.
        match remote.urls(Direction::Fetch).next() {
            Some(url) => writeln!(out, "{name}\t{} (fetch)", url.to_bstring())?,
            None => writeln!(out, "{name}\t")?,
        }
        for url in remote.urls(Direction::Push) {
            writeln!(out, "{name}\t{} (push)", url.to_bstring())?;
        }
    }
    out.flush()?;
    cancellation.check()
}
