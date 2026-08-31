use serde::{Deserialize, Serialize};

pub const POSIX_RENAME: &str = "posix-rename@openssh.com";
pub const POSIX_RENAME_VERSION: &str = "1";

// The request payload is two SFTP strings; russh-sftp's wire codec handles
// the framing, and, like its own packet decoding, converts non-UTF-8 path
// bytes lossily instead of rejecting the request.
#[derive(Debug, Deserialize, Serialize)]
struct PosixRenameRequest {
    oldpath: String,
    newpath: String,
}

pub fn encode_posix_rename(oldpath: &str, newpath: &str) -> Vec<u8> {
    russh_sftp::ser::to_bytes(&PosixRenameRequest {
        oldpath: oldpath.to_owned(),
        newpath: newpath.to_owned(),
    })
    .expect("encoding two in-memory SFTP strings cannot fail")
    .to_vec()
}

pub fn decode_posix_rename(data: Vec<u8>) -> Result<(String, String), String> {
    let mut bytes = data.into();
    let request: PosixRenameRequest =
        russh_sftp::de::from_bytes(&mut bytes).map_err(|error| error.to_string())?;
    // The payload is exactly two strings; trailing bytes are a malformed
    // request.
    if !bytes.is_empty() {
        return Err("trailing posix-rename data".to_owned());
    }
    Ok((request.oldpath, request.newpath))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_rename_paths_round_trip() {
        let data = encode_posix_rename("old/path", "new path");
        assert_eq!(
            decode_posix_rename(data).unwrap(),
            ("old/path".to_owned(), "new path".to_owned())
        );
    }

    #[test]
    fn posix_rename_rejects_truncated_and_trailing_data() {
        let valid = encode_posix_rename("old", "new");
        for len in 0..valid.len() {
            assert!(decode_posix_rename(valid[..len].to_vec()).is_err());
        }
        let mut trailing = valid;
        trailing.push(0);
        assert!(decode_posix_rename(trailing).is_err());
    }

    #[test]
    fn posix_rename_degrades_unusual_paths_like_the_rename_packet() {
        // OpenSSH sends raw filesystem bytes; russh-sftp decodes them lossily
        // in SSH_FXP_RENAME, and the extension must not be stricter.
        let invalid_utf8 = [0, 0, 0, 1, 0xff, 0, 0, 0, 0].to_vec();
        assert_eq!(
            decode_posix_rename(invalid_utf8).unwrap(),
            ("\u{fffd}".to_owned(), String::new())
        );
    }
}
