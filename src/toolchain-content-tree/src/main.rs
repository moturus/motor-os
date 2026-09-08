//! Stream the existing content-tree encoding without spawning per-file tools.
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn field(output: &mut impl Write, name: &str, bytes: &[u8]) -> io::Result<()> {
    write!(output, "{}:{name}{}:", name.len(), bytes.len())?;
    output.write_all(bytes)
}

fn component(input: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.read_until(0, &mut bytes)?;
    if bytes.pop() != Some(0) {
        return Err(invalid("unterminated content-tree record"));
    }
    Ok(bytes)
}

fn serialize(input: &mut impl BufRead, output: &mut impl Write) -> io::Result<()> {
    while !input.fill_buf()?.is_empty() {
        let path = component(input)?;
        let relative = component(input)?;
        let kind = component(input)?;
        let mode = component(input)?;
        let path = Path::new(OsStr::from_bytes(&path));
        let metadata = fs::symlink_metadata(path)?;
        field(output, "path", &relative)?;
        field(output, "kind", &kind)?;
        field(output, "mode", &mode)?;
        match kind.as_slice() {
            b"symlink" if metadata.is_symlink() && mode == b"120000" => {
                let target = fs::read_link(path)?;
                field(output, "content", target.as_os_str().as_bytes())?;
            }
            b"file" if metadata.is_file() && (mode == b"100644" || mode == b"100755") => {
                let mut file = File::open(path)?;
                let size = file.metadata()?.len();
                write!(output, "7:content{size}:")?;
                if io::copy(&mut file, output)? != size {
                    return Err(invalid("content-tree file size changed while reading"));
                }
            }
            _ => return Err(invalid("invalid or changed content-tree file kind/mode")),
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let mut input = BufReader::new(io::stdin().lock());
    let mut output = BufWriter::with_capacity(64 * 1024, io::stdout().lock());
    serialize(&mut input, &mut output)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_count_bytes_and_preserve_binary_content() {
        let mut output = Vec::new();
        field(&mut output, "content", b"\0\xff\n").unwrap();
        assert_eq!(output, b"7:content3:\0\xff\n");
    }

    #[test]
    fn truncated_records_and_missing_files_fail() {
        for input in [
            b"path".as_slice(),
            b"path\0",
            b"\0relative\0file\x00100644\0",
        ] {
            assert!(serialize(&mut &input[..], &mut Vec::new()).is_err());
        }
        serialize(&mut &b""[..], &mut Vec::new()).unwrap();
    }

    #[test]
    fn output_errors_are_not_swallowed() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            field(&mut Broken, "content", b"x").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
