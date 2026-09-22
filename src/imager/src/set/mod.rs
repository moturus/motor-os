//! Offline credential replacement; secrets are never included in diagnostics.

mod credentials;
mod image;
mod ssh_config;

use std::ffi::OsString;
use std::io;
use std::path::Path;

enum Input<'a> {
    Password(&'a str),
    LoginKey(&'a Path),
    HostKey(&'a Path),
    Tls(&'a Path),
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse<'a>(args: &'a [&'a str]) -> io::Result<(Input<'a>, &'a Path)> {
    match args {
        ["ssh-password", password, image] => {
            credentials::validate_password(password)?;
            Ok((Input::Password(password), Path::new(image)))
        }
        ["ssh-key", key, image] => Ok((Input::LoginKey(Path::new(key)), Path::new(image))),
        ["ssh-server-key", key, image] => Ok((Input::HostKey(Path::new(key)), Path::new(image))),
        ["ssl", "keys", directory, image] => Ok((Input::Tls(Path::new(directory)), Path::new(image))),
        _ => Err(invalid("expected ssh-password PWD IMAGE, ssh-key PUBLIC_KEY_FILE IMAGE, ssh-server-key KEY_FILE IMAGE, or ssl keys DIR IMAGE")),
    }
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
    image::update(image, &credentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_commands_without_echoing_arguments() {
        for (args, kind) in [
            (vec!["ssh-password", " /not/a/file 雪 ", "image path"], 0),
            (vec!["ssh-key", "key path.pub", "image path"], 1),
            (vec!["ssh-server-key", "key path", "image path"], 2),
            (vec!["ssl", "keys", "cert directory", "image path"], 3),
        ] {
            let (input, image) = parse(&args).unwrap();
            assert_eq!(image, Path::new("image path"));
            assert_eq!(
                match input {
                    Input::Password(value) => {
                        assert_eq!(value, args[1]);
                        0
                    }
                    Input::LoginKey(path) => {
                        assert_eq!(path, Path::new(args[1]));
                        1
                    }
                    Input::HostKey(path) => {
                        assert_eq!(path, Path::new(args[1]));
                        2
                    }
                    Input::Tls(path) => {
                        assert_eq!(path, Path::new(args[2]));
                        3
                    }
                },
                kind
            );
        }
        for args in [
            vec![],
            vec!["secret"],
            vec!["ssh-password", "secret"],
            vec!["ssh-password", "secret", "image", "extra"],
            vec!["ssl", "secret", "image"],
            vec!["ssl", "key", "secret", "image"],
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
            let error = parse(&["ssh-password", password, "image"]).err().unwrap();
            assert!(!error.to_string().contains("secret"));
        }
    }
}
