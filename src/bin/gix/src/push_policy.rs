use std::io;

use gix::{bstr::ByteSlice, remote::Direction};

use crate::{cancellation::Cancellation, object_database::Reader, ssh::Prepared};

pub struct Spec {
    source: String,
    pub destination: gix::refs::FullName,
    lease: Option<Option<gix::ObjectId>>,
}

impl Spec {
    pub fn parse(refspec: &str, lease: Option<&str>) -> crate::Result<Self> {
        let (source, destination) = refspec
            .split_once(':')
            .filter(|(source, _)| !source.is_empty() && !source.starts_with('+'))
            .ok_or_else(|| invalid("push requires one explicit SOURCE:DESTINATION"))?;
        let destination: gix::refs::FullName = destination.try_into()?;
        if !destination.as_bstr().starts_with(b"refs/heads/")
            && !destination.as_bstr().starts_with(b"refs/tags/")
        {
            return Err(invalid("push destination must be under refs/heads/ or refs/tags/").into());
        }
        let lease = lease
            .map(|lease| -> crate::Result<_> {
                let (name, expected) = lease
                    .split_once(':')
                    .ok_or_else(|| invalid("lease must be DESTINATION:OID"))?;
                if name.as_bytes() != destination.as_bstr().as_bytes() {
                    return Err(
                        invalid("lease destination must match the pushed destination").into(),
                    );
                }
                if expected.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(full_id(expected)?))
                }
            })
            .transpose()?;
        Ok(Self {
            source: source.to_owned(),
            destination,
            lease,
        })
    }

    /// Capture the exact object without peeling tags or accepting revision expressions.
    pub fn resolve(
        &self,
        repo: &gix::Repository,
        cancellation: &Cancellation,
    ) -> crate::Result<gix::ObjectId> {
        cancellation.check()?;
        crate::object_database::validate_full(repo, "push")?;
        let source = if self.source.len() == 40
            && self.source.bytes().all(|b| b.is_ascii_hexdigit())
        {
            full_id(&self.source)?
        } else {
            let mut reference = repo.find_reference(self.source.as_str())?;
            if self.source != "HEAD" && !reference.name().as_bstr().starts_with(b"refs/") {
                return Err(
                    invalid("push source must be a local ref, HEAD or a full object ID").into(),
                );
            }
            reference.follow_to_object()?.detach()
        };
        let object = Reader::new(repo, cancellation).load(source)?;
        if self.is_branch() && object.kind != gix::objs::Kind::Commit {
            return Err(invalid("a branch destination requires a commit object").into());
        }
        cancellation.check()?;
        Ok(source)
    }

    /// Return true only for a no-op; even that must satisfy an explicit lease.
    pub fn validate_update(
        &self,
        repo: &gix::Repository,
        source: gix::ObjectId,
        old: Option<gix::ObjectId>,
        cancellation: &Cancellation,
    ) -> crate::Result<bool> {
        cancellation.check()?;
        self.check_lease(old)?;
        if old == Some(source) {
            return Ok(true);
        }
        let Some(old) = old else {
            return Ok(false);
        };
        if self.lease.is_some() {
            return Ok(false);
        }
        if !self.is_branch() {
            return Err(
                invalid("replacing an existing tag requires an explicit matching lease").into(),
            );
        }
        let reader = Reader::new(repo, cancellation);
        let Some(previous) = reader.try_load(old)? else {
            return Err(invalid(
                "remote commit is unavailable locally; fetch first or use a matching lease",
            )
            .into());
        };
        if previous.kind != gix::objs::Kind::Commit {
            return Err(invalid(
                "remote branch does not name a commit; a matching lease is required",
            )
            .into());
        }
        drop(previous);
        if !crate::push_objects::is_ancestor(repo, source, old, cancellation)? {
            return Err(invalid(
                "push is not a fast-forward; an explicit matching lease is required",
            )
            .into());
        }
        Ok(false)
    }

    fn is_branch(&self) -> bool {
        self.destination.as_bstr().starts_with(b"refs/heads/")
    }

    fn check_lease(&self, old: Option<gix::ObjectId>) -> crate::Result {
        if self.lease.is_some_and(|expected| expected != old) {
            return Err(invalid("push lease does not match the advertised destination").into());
        }
        Ok(())
    }
}

/// Resolve exactly one push-direction URL, validating it before and after rewrites.
pub fn remote(repo: &gix::Repository, requested: &str) -> crate::Result<Prepared> {
    let mut remote = match repo.try_find_remote_without_url_rewrite(requested.as_bytes().as_bstr())
    {
        Some(remote) => remote?,
        None => repo.remote_at_without_url_rewrite(requested)?,
    };
    Prepared::new(one_url(&remote)?)?;
    remote.rewrite_urls()?;
    Prepared::new(one_url(&remote)?)
}

fn one_url(remote: &gix::Remote<'_>) -> crate::Result<gix::url::Url> {
    let mut urls = remote.urls(Direction::Push);
    let url = urls
        .next()
        .ok_or_else(|| invalid("remote has no push URL"))?;
    if urls.next().is_some() {
        return Err(invalid("push requires exactly one remote destination URL").into());
    }
    Ok(url.clone())
}

fn full_id(value: &str) -> crate::Result<gix::ObjectId> {
    if value.len() != 40 {
        return Err(invalid("push requires a full SHA-1 object ID").into());
    }
    let id = gix::ObjectId::from_hex(value.as_bytes())?;
    if id.is_null() {
        return Err(invalid(
            "use an empty lease OID for expected absence; null source IDs are invalid",
        )
        .into());
    }
    Ok(id)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_destination_and_lease_are_required_even_for_noop() -> crate::Result {
        let destination = "refs/heads/main";
        let id = gix::ObjectId::from_hex(b"1111111111111111111111111111111111111111")?;
        let absent = Spec::parse("HEAD:refs/heads/main", Some("refs/heads/main:"))?;
        absent.check_lease(None)?;
        assert!(absent.check_lease(Some(id)).is_err());
        let lease = format!("{destination}:{id}");
        let exact = Spec::parse("HEAD:refs/heads/main", Some(&lease))?;
        exact.check_lease(Some(id))?;
        assert!(exact.check_lease(None).is_err());
        for refspec in [
            "HEAD",
            ":refs/heads/main",
            "+HEAD:refs/heads/main",
            "HEAD:main",
            "HEAD:refs/remotes/origin/main",
            "HEAD:refs/tags/*",
            "HEAD:refs/heads/main:other",
        ] {
            assert!(Spec::parse(refspec, None).is_err(), "{refspec}");
        }
        for lease in [
            "refs/heads/other:",
            "refs/heads/main",
            "refs/heads/main:abcd",
            "refs/heads/main:0000000000000000000000000000000000000000",
        ] {
            assert!(
                Spec::parse("HEAD:refs/heads/main", Some(lease)).is_err(),
                "{lease}"
            );
        }
        Ok(())
    }
}
