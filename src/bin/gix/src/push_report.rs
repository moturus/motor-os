use std::io;

use gix::bstr::{BStr, BString, ByteSlice};
use gix_transport::{
    client::{MessageKind, blocking_io::ExtendedBufRead},
    packetline::PacketLineRef,
};

#[derive(Debug, Eq, PartialEq)]
pub enum Report {
    Accepted,
    Rejected(String),
}

/// Read the complete report-status response for exactly one requested ref.
pub fn read<'a>(reader: &mut dyn ExtendedBufRead<'a>, destination: &BStr) -> crate::Result<Report> {
    let unpack = line(reader)?;
    let unpack = unpack
        .strip_prefix(b"unpack ")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("missing or malformed unpack result"))?;
    let status = line(reader)?;
    let rejection = if let Some(name) = status.strip_prefix(b"ok ") {
        if name != destination.as_bytes() {
            return Err(invalid("report named an unexpected ref").into());
        }
        if unpack != b"ok" {
            return Err(invalid("report accepted the ref after an unpack failure").into());
        }
        None
    } else if let Some(value) = status.strip_prefix(b"ng ") {
        let (name, reason) = value
            .split_once_str(b" ")
            .filter(|(_, reason)| !reason.is_empty())
            .ok_or_else(|| invalid("malformed ref rejection"))?;
        if name != destination.as_bytes() {
            return Err(invalid("report named an unexpected ref").into());
        }
        Some(reason.as_bstr().to_str_lossy().escape_debug().to_string())
    } else {
        return Err(invalid("missing or malformed ref result").into());
    };
    if reader.readline().transpose()?.transpose()?.is_some()
        || reader.stopped_at() != Some(MessageKind::Flush)
    {
        return Err(invalid("report must end after one ref result with a flush packet").into());
    }
    Ok(match rejection {
        None => Report::Accepted,
        Some(reason) if unpack == b"ok" => Report::Rejected(reason),
        Some(reason) => Report::Rejected(format!(
            "unpack: {}; ref: {reason}",
            unpack.as_bstr().to_str_lossy().escape_debug()
        )),
    })
}

fn line<'a>(reader: &mut dyn ExtendedBufRead<'a>) -> crate::Result<BString> {
    match reader.readline().transpose()?.transpose()? {
        Some(PacketLineRef::Data(bytes)) => Ok(bytes.strip_suffix(b"\n").unwrap_or(bytes).into()),
        _ => Err(invalid("report ended before both results were received").into()),
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gix_transport::packetline::blocking_io::{StreamingPeekableIter, encode};

    fn parse(lines: &[&[u8]], flush: bool) -> crate::Result<Report> {
        let mut bytes = Vec::new();
        for line in lines {
            encode::write_packet_line(&PacketLineRef::Data(line), &mut bytes)?;
        }
        if flush {
            encode::write_packet_line(&PacketLineRef::Flush, &mut bytes)?;
        }
        let mut packets =
            StreamingPeekableIter::new(bytes.as_slice(), &[PacketLineRef::Flush], false);
        read(
            &mut packets.as_read_without_sidebands(),
            b"refs/heads/main".as_bstr(),
        )
    }

    #[test]
    fn accepts_only_a_complete_matching_report() -> crate::Result {
        for lines in [
            [b"unpack ok".as_slice(), b"ok refs/heads/main".as_slice()],
            [
                b"unpack ok\n".as_slice(),
                b"ok refs/heads/main\n".as_slice(),
            ],
        ] {
            assert_eq!(parse(&lines, true)?, Report::Accepted);
        }
        assert_eq!(
            parse(&[b"unpack ok", b"ng refs/heads/main rejected"], true)?,
            Report::Rejected("rejected".into())
        );
        assert_eq!(
            parse(
                &[b"unpack broken pack", b"ng refs/heads/main unpacker error"],
                true
            )?,
            Report::Rejected("unpack: broken pack; ref: unpacker error".into())
        );
        for lines in [
            vec![],
            vec![b"unpack ok".as_slice()],
            vec![b"unpack ok".as_slice(), b"ok refs/heads/other"],
            vec![b"unpack broken pack".as_slice(), b"ok refs/heads/main"],
            vec![b"unpack ok".as_slice(), b"ng refs/heads/main"],
            vec![b"unpack ok".as_slice(), b"ng refs/heads/main "],
            vec![b"unpack ok".as_slice(), b"ok refs/heads/main extra"],
            vec![b"ok refs/heads/main".as_slice(), b"unpack ok"],
            vec![
                b"unpack ok".as_slice(),
                b"ok refs/heads/main",
                b"ok refs/heads/main",
            ],
        ] {
            assert!(parse(&lines, true).is_err(), "{lines:?}");
        }
        assert!(parse(&[b"unpack ok", b"ok refs/heads/main"], false).is_err());
        Ok(())
    }
}
