use std::io::{self, Read, Write};

use gix_transport::client::{MessageKind, WriteMode, blocking_io::Transport};

use crate::{
    cancellation::Cancellation,
    push_pack::PackReader,
    push_report::{self, Report},
};

// Git pkt-lines permit 65,520 bytes including their four-byte length prefix.
const MAX_PACKET_DATA_BYTES: usize = 65_516;

/// Construct one bounded command before preparing a pack or sending any update.
pub fn command(
    old: Option<gix::ObjectId>,
    new: gix::ObjectId,
    destination: &gix::refs::FullNameRef,
) -> crate::Result<Vec<u8>> {
    let old = old.unwrap_or_else(|| gix::ObjectId::null(gix::hash::Kind::Sha1));
    if old.kind() != gix::hash::Kind::Sha1 || new.kind() != gix::hash::Kind::Sha1 || new.is_null() {
        return Err(invalid("push requires SHA-1 IDs and a non-null new object").into());
    }
    const SUFFIX: &[u8] = b"\0report-status\n";
    let length = 82usize
        .checked_add(destination.as_bstr().len())
        .and_then(|n| n.checked_add(SUFFIX.len()))
        .filter(|n| *n <= MAX_PACKET_DATA_BYTES)
        .ok_or_else(|| invalid("push destination does not fit one command packet"))?;
    let mut command = Vec::new();
    command.try_reserve_exact(length)?;
    write!(&mut command, "{old} {new} ")?;
    command.extend_from_slice(destination.as_bstr());
    command.extend_from_slice(SUFFIX);
    Ok(command)
}

/// End discovery without sending an update or pack (no-op or dry-run).
pub fn finish_discovery(
    transport: &mut dyn Transport,
    cancellation: &Cancellation,
) -> crate::Result {
    cancellation.check()?;
    let mut request = transport.request(WriteMode::Binary, MessageKind::Flush, false)?;
    request.write_message(MessageKind::Flush)?;
    request.flush()?;
    Ok(())
}

/// Send a completed pack and read the complete status for exactly one ref.
pub fn send(
    transport: &mut dyn Transport,
    command: &[u8],
    destination: &gix::refs::FullNameRef,
    pack: (PackReader, u64),
    cancellation: &Cancellation,
    update_started: &mut bool,
) -> crate::Result<Report> {
    let (mut pack, length) = pack;
    let mut request = transport.request(WriteMode::Binary, MessageKind::Flush, false)?;
    cancellation.check()?;
    // Any error after the first attempted command write has an unknown outcome.
    *update_started = true;
    request.write_all(command)?;
    request.write_message(MessageKind::Flush)?;
    let (mut writer, mut reader) = request.into_parts();
    let mut remaining = length;
    let mut buffer = [0; 64 * 1024];
    while remaining != 0 {
        cancellation.check()?;
        let allowed = remaining.min(buffer.len() as u64) as usize;
        let count = pack.read(&mut buffer[..allowed])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "finished push pack was truncated",
            )
            .into());
        }
        writer.write_all(&buffer[..count])?;
        remaining -= count as u64;
    }
    if pack.read(&mut [0])? != 0 {
        return Err(invalid("finished push pack grew while being sent").into());
    }
    writer.flush()?;
    drop(writer);
    push_report::read(&mut *reader, destination.as_bstr())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_fits_exactly_one_packet_at_the_limit() -> crate::Result {
        let id = gix::ObjectId::from_bytes_or_panic(&[1; 20]);
        let prefix = "refs/heads/";
        let fixed = command(
            None,
            id,
            gix::refs::FullName::try_from(prefix.to_owned() + "a")?.as_ref(),
        )?
        .len()
            - 1;
        let name = prefix.to_owned() + &"a".repeat(MAX_PACKET_DATA_BYTES - fixed);
        let destination = gix::refs::FullName::try_from(name.as_str())?;
        let bytes = command(None, id, destination.as_ref())?;
        assert_eq!(bytes.len(), MAX_PACKET_DATA_BYTES);
        let mut wire = Vec::new();
        gix_transport::packetline::blocking_io::Writer::new(&mut wire).write_all(&bytes)?;
        assert_eq!(wire.len(), MAX_PACKET_DATA_BYTES + 4);
        let too_long = gix::refs::FullName::try_from(name + "a")?;
        assert!(command(None, id, too_long.as_ref()).is_err());
        Ok(())
    }
}
