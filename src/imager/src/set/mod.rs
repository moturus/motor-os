//! Offline credential replacement; secrets are never included in diagnostics.

pub(crate) mod credentials;
pub(crate) mod image;
mod ssh_config;

use std::ffi::OsString;
use std::io;
use std::path::Path;

pub(crate) enum Input<'a> {
    Password(&'a str),
    LoginKey(&'a Path),
    HostKey(&'a Path),
    Tls(&'a Path),
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn usage() -> io::Error {
    invalid("expected one of --ssh-password PWD, --ssh-key PUBLIC_KEY_FILE, --ssh-server-key KEY_FILE, or --ssl-keys DIR, and -i IMAGE")
}

/// Parses `(OPTION VALUE)` pairs in any order: exactly one credential option and one `-i`.
fn parse<'a>(args: &'a [&'a str]) -> io::Result<(Input<'a>, &'a Path)> {
    let mut input = None;
    let mut image = None;
    for pair in args.chunks(2) {
        let [option, value] = pair else {
            return Err(usage());
        };
        let parsed = match *option {
            "-i" => {
                if image.replace(Path::new(*value)).is_some() {
                    return Err(usage());
                }
                continue;
            }
            "--ssh-password" => {
                credentials::validate_password(value)?;
                Input::Password(value)
            }
            "--ssh-key" => Input::LoginKey(Path::new(*value)),
            "--ssh-server-key" => Input::HostKey(Path::new(*value)),
            "--ssl-keys" => Input::Tls(Path::new(*value)),
            _ => return Err(usage()),
        };
        if input.replace(parsed).is_some() {
            return Err(usage());
        }
    }
    input.zip(image).ok_or_else(usage)
}

pub(super) fn run(args: &[OsString]) -> io::Result<()> {
    let args = args
        .iter()
        .map(|arg| {
            arg.to_str()
                .ok_or_else(|| invalid("set arguments must be UTF-8"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let (input, image) = parse(&args)?;
    let credentials = credentials::Credentials::read(input)?;
    image::update(image, &[credentials])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_commands_without_echoing_arguments() {
        for (args, kind) in [
            (
                vec!["--ssh-password", " /not/a/file 雪 ", "-i", "image path"],
                0,
            ),
            (vec!["--ssh-password", "-i", "-i", "image path"], 0),
            (vec!["--ssh-key", "key path.pub", "-i", "image path"], 1),
            (vec!["-i", "image path", "--ssh-server-key", "key path"], 2),
            (vec!["--ssl-keys", "cert directory", "-i", "image path"], 3),
        ] {
            let (input, image) = parse(&args).unwrap();
            assert_eq!(image, Path::new("image path"));
            let value = args[args.iter().position(|arg| arg.starts_with("--")).unwrap() + 1];
            assert_eq!(
                match input {
                    Input::Password(password) => {
                        assert_eq!(password, value);
                        0
                    }
                    Input::LoginKey(path) => {
                        assert_eq!(path, Path::new(value));
                        1
                    }
                    Input::HostKey(path) => {
                        assert_eq!(path, Path::new(value));
                        2
                    }
                    Input::Tls(path) => {
                        assert_eq!(path, Path::new(value));
                        3
                    }
                },
                kind
            );
        }
        for args in [
            vec![],
            vec!["secret"],
            vec!["--ssh-password", "secret"],
            vec!["--ssh-password", "secret", "-i"],
            vec!["--ssh-password", "secret", "-i", "image", "extra"],
            vec!["--ssh-password", "secret", "-i", "image", "-i", "image"],
            vec![
                "--ssh-password",
                "secret",
                "--ssh-key",
                "secret",
                "-i",
                "image",
            ],
            vec!["--ssl", "secret", "-i", "image"],
            vec!["ssh-password", "secret", "image"],
            vec!["ssl", "keys", "secret", "image"],
        ] {
            let error = parse(&args).err().unwrap().to_string();
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn rejects_password_line_breaks_and_bom_without_echoing() {
        for password in [
            "",
            "secret\n",
            "\rsecret",
            "\u{feff}secret",
            "sec\u{feff}ret",
        ] {
            let error = parse(&["--ssh-password", password, "-i", "image"])
                .err()
                .unwrap();
            assert!(!error.to_string().contains("secret"));
        }
    }
}
