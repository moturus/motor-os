use std::io;

use gix::bstr::{BStr, ByteSlice};
use gix::protocol::{Handshake, handshake::Ref};
use gix_transport::{Service, client::Capabilities};

use crate::cancellation::Cancellation;

/// Maximum number of object IDs retained from one receive-pack advertisement.
pub const MAX_ADVERTISED_IDS: usize = 65_536;

/// The remote objects advertised as available and the exact old destination ID.
pub struct Advertisement {
    pub advertised: Vec<gix::ObjectId>,
    pub destination_old: Option<gix::ObjectId>,
}

/// Perform receive-pack discovery without sending an update request.
pub fn discover(
    transport: &mut dyn gix_transport::client::blocking_io::Transport,
    destination: &gix::refs::FullNameRef,
    cancellation: &Cancellation,
) -> crate::Result<Advertisement> {
    cancellation.check()?;
    if !matches!(
        destination.category(),
        Some(gix::refs::Category::LocalBranch | gix::refs::Category::Tag)
    ) {
        return Err(invalid("push destination must be under refs/heads/ or refs/tags/").into());
    }
    let result = discover_inner(transport, destination, cancellation);
    match result {
        Ok(advertisement) => {
            cancellation.check()?;
            Ok(advertisement)
        }
        Err(error) => Err(cancellation.normalize_error(error)),
    }
}

fn discover_inner(
    transport: &mut dyn gix_transport::client::blocking_io::Transport,
    destination: &gix::refs::FullNameRef,
    cancellation: &Cancellation,
) -> crate::Result<Advertisement> {
    let mut progress = gix::progress::Discard;
    // The upstream callback requires this large error type, even when infallible.
    #[expect(clippy::result_large_err)]
    let no_credentials = |_| Ok(None);
    let handshake = gix::protocol::handshake(
        transport,
        Service::ReceivePack,
        no_credentials,
        Vec::new(),
        &mut progress,
    )?;
    cancellation.check()?;
    parse(handshake, destination, cancellation)
}

fn parse(
    handshake: Handshake,
    destination: &gix::refs::FullNameRef,
    cancellation: &Cancellation,
) -> crate::Result<Advertisement> {
    validate_capabilities(&handshake.capabilities)?;
    let refs = handshake
        .refs
        .ok_or_else(|| invalid("receive-pack did not advertise refs"))?;
    let mut advertised = Vec::new();
    let mut destination_old = None;
    for reference in refs {
        cancellation.check()?;
        match reference {
            Ref::Direct {
                full_ref_name,
                object,
            } => {
                let ordinary = validate_name(full_ref_name.as_bstr())?;
                retain(&mut advertised, object)?;
                if ordinary && full_ref_name.as_bstr() == destination.as_bstr() {
                    set_destination(&mut destination_old, object)?;
                }
            }
            Ref::Peeled {
                full_ref_name,
                tag,
                object,
            } => {
                if !validate_name(full_ref_name.as_bstr())? {
                    return Err(invalid("receive-pack advertised a peeled pseudo-reference").into());
                }
                retain(&mut advertised, tag)?;
                retain(&mut advertised, object)?;
                if full_ref_name.as_bstr() == destination.as_bstr() {
                    set_destination(&mut destination_old, tag)?;
                }
            }
            Ref::Symbolic { .. } | Ref::Unborn { .. } => {
                return Err(invalid("receive-pack advertised a symbolic reference").into());
            }
        }
    }
    Ok(Advertisement {
        advertised,
        destination_old,
    })
}

fn validate_capabilities(capabilities: &Capabilities) -> crate::Result {
    if !capabilities.contains("report-status") {
        return Err(invalid("receive-pack does not support report-status").into());
    }
    for format in capabilities
        .iter()
        .filter(|capability| capability.name() == b"object-format".as_bstr())
    {
        if format.value() != Some(b"sha1".as_bstr()) {
            return Err(invalid("receive-pack object format is not SHA-1").into());
        }
    }
    Ok(())
}

fn validate_name(name: &BStr) -> crate::Result<bool> {
    if name == b".have" {
        return Ok(false);
    }
    if !name.starts_with_str("refs/") {
        return Err(invalid("receive-pack advertised an unsupported pseudo-reference").into());
    }
    let _: &gix::refs::FullNameRef = name.try_into()?;
    Ok(true)
}

fn retain(ids: &mut Vec<gix::ObjectId>, id: gix::ObjectId) -> crate::Result {
    if id.kind() != gix::hash::Kind::Sha1 {
        return Err(invalid("receive-pack advertised a non-SHA-1 object ID").into());
    }
    if id.is_null() {
        return Err(invalid("receive-pack advertised a null object ID").into());
    }
    if ids.len() == MAX_ADVERTISED_IDS {
        return Err(invalid("receive-pack advertisement exceeds the object ID limit").into());
    }
    ids.try_reserve(1)?;
    ids.push(id);
    Ok(())
}

fn set_destination(slot: &mut Option<gix::ObjectId>, id: gix::ObjectId) -> crate::Result {
    if slot.replace(id).is_some() {
        return Err(invalid("receive-pack advertised the push destination more than once").into());
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> gix::ObjectId {
        [byte; 20].into()
    }

    fn caps(value: &str) -> Capabilities {
        Capabilities::from_bytes(format!("x\0{value}").as_bytes())
            .expect("valid test capabilities")
            .0
    }

    fn direct(name: &str, object: gix::ObjectId) -> Ref {
        Ref::Direct {
            full_ref_name: name.into(),
            object,
        }
    }

    fn parsed(
        refs: Vec<Ref>,
        capabilities: &Capabilities,
        destination: &str,
    ) -> crate::Result<Advertisement> {
        let destination = gix::refs::FullName::try_from(destination)?;
        parse(
            Handshake {
                refs: Some(refs),
                capabilities: capabilities.clone(),
                ..Default::default()
            },
            destination.as_ref(),
            &Cancellation::new(),
        )
    }

    #[test]
    fn receive_pack_advertisement_policy() -> crate::Result {
        use std::io::Write;

        let mut wire = Vec::new();
        {
            let mut writer =
                gix::protocol::transport::packetline::blocking_io::Writer::new(&mut wire);
            writer.write_all(
                b"0000000000000000000000000000000000000000 capabilities^{}\0report-status\n",
            )?;
            gix::protocol::transport::packetline::blocking_io::encode::flush_to_write(
                writer.inner_mut(),
            )?;
        }
        let mut output = Vec::new();
        let mut transport = gix_transport::client::git::blocking_io::Connection::new(
            wire.as_slice(),
            &mut output,
            gix_transport::Protocol::V1,
            "/empty.git",
            None::<(&str, Option<u16>)>,
            gix_transport::client::git::ConnectMode::Process,
            false,
        );
        let destination = gix::refs::FullName::try_from("refs/heads/main")?;
        let empty = discover(&mut transport, destination.as_ref(), &Cancellation::new())?;
        assert!(empty.advertised.is_empty());
        assert_eq!(empty.destination_old, None);
        drop(transport);
        assert!(output.is_empty());

        let one = id(1);
        let two = id(2);
        let three = id(3);
        for (name, capabilities, refs, destination, ids, old) in [
            (
                "direct and have",
                "report-status object-format=sha1",
                vec![direct("refs/heads/main", one), direct(".have", two)],
                "refs/heads/main",
                vec![one, two],
                Some(one),
            ),
            (
                "peeled tag",
                "report-status object-format=sha1",
                vec![Ref::Peeled {
                    full_ref_name: "refs/tags/v1".into(),
                    tag: two,
                    object: three,
                }],
                "refs/tags/v1",
                vec![two, three],
                Some(two),
            ),
        ] {
            let actual = parsed(refs, &caps(capabilities), destination)?;
            assert_eq!(actual.advertised, ids, "{name}");
            assert_eq!(actual.destination_old, old, "{name}");
        }

        let mut ids = vec![one; MAX_ADVERTISED_IDS - 1];
        retain(&mut ids, two)?;
        assert_eq!(ids.len(), MAX_ADVERTISED_IDS);
        assert!(retain(&mut ids, three).is_err());
        assert_eq!(ids.len(), MAX_ADVERTISED_IDS);

        let valid = caps("report-status");
        for (name, refs) in [
            ("duplicate", vec![direct("refs/heads/main", one); 2]),
            (
                "conflicting",
                vec![
                    direct("refs/heads/main", one),
                    direct("refs/heads/main", two),
                ],
            ),
            ("invalid", vec![direct("refs/heads/bad name", one)]),
            (
                "null",
                vec![direct(
                    "refs/heads/main",
                    gix::ObjectId::null(gix::hash::Kind::Sha1),
                )],
            ),
        ] {
            assert!(parsed(refs, &valid, "refs/heads/main").is_err(), "{name}");
        }
        for capabilities in ["object-format=sha1", "report-status object-format=sha256"] {
            assert!(parsed(vec![], &caps(capabilities), "refs/heads/main").is_err());
        }
        Ok(())
    }
}
