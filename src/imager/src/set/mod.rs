//! Offline credential replacement; secrets are never included in diagnostics.

mod bare_toml;
pub(crate) mod credentials;
pub(crate) mod image;

use std::ffi::OsString;
use std::io;
use std::path::Path;

pub(crate) enum Input<'a> {
    Password(&'a str),
    LoginKey(&'a Path),
    HostKey(&'a Path),
    Tls(&'a Path),
}

/// Which login a password or a login key is for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Selector<'a> {
    Default,
    Existing(&'a str),
    New(&'a str),
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn usage() -> io::Error {
    invalid("expected [--ssh-user NAME | --ssh-new-user NAME] with --ssh-password PWD or --ssh-key PUBLIC_KEY_FILE, or one of --ssh-server-key KEY_FILE or --ssl-keys DIR, and -i IMAGE")
}

/// Parses `(OPTION VALUE)` pairs in any order: exactly one credential option,
/// one `-i`, and at most one user selector, which only user credentials take.
fn parse<'a>(args: &'a [&'a str]) -> io::Result<(Input<'a>, Selector<'a>, &'a Path)> {
    let mut input = None;
    let mut image = None;
    let mut selector = None;
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
            "--ssh-user" | "--ssh-new-user" => {
                credentials::validate_user_name(value)?;
                let chosen = if *option == "--ssh-user" {
                    Selector::Existing(value)
                } else {
                    Selector::New(value)
                };
                if selector.replace(chosen).is_some() {
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
    let (input, image) = input.zip(image).ok_or_else(usage)?;
    if selector.is_some() && matches!(input, Input::HostKey(_) | Input::Tls(_)) {
        return Err(usage());
    }
    Ok((input, selector.unwrap_or(Selector::Default), image))
}

pub(super) fn run(args: &[OsString]) -> io::Result<()> {
    let args = args
        .iter()
        .map(|arg| {
            arg.to_str()
                .ok_or_else(|| invalid("set arguments must be UTF-8"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let (input, selector, image) = parse(&args)?;
    let credentials = credentials::Credentials::read(input, selector)?;
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
            let (input, selector, image) = parse(&args).unwrap();
            assert_eq!(image, Path::new("image path"));
            assert_eq!(selector, Selector::Default);
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
    fn user_selectors_apply_to_user_credentials_only() {
        for (args, expected) in [
            (
                ["--ssh-user", "alice", "--ssh-password", "pw", "-i", "image"],
                Selector::Existing("alice"),
            ),
            (
                ["--ssh-key", "key.pub", "--ssh-user", "alice", "-i", "image"],
                Selector::Existing("alice"),
            ),
            (
                ["-i", "image", "--ssh-new-user", "a-b_9", "--ssh-key", "k"],
                Selector::New("a-b_9"),
            ),
        ] {
            assert_eq!(parse(&args).unwrap().1, expected);
        }
        let long = "n".repeat(65);
        for args in [
            vec!["--ssh-user", "a", "--ssh-server-key", "k", "-i", "image"],
            vec!["--ssh-new-user", "a", "--ssl-keys", "dir", "-i", "image"],
            vec!["--ssh-user", "a", "-i", "image"],
            vec![
                "--ssh-user",
                "a",
                "--ssh-new-user",
                "b",
                "--ssh-key",
                "k",
                "-i",
                "image",
            ],
            vec![
                "--ssh-user",
                "a",
                "--ssh-user",
                "a",
                "--ssh-key",
                "k",
                "-i",
                "image",
            ],
            vec!["--ssh-user", "", "--ssh-key", "k", "-i", "image"],
            vec!["--ssh-user", "a/b", "--ssh-key", "k", "-i", "image"],
            vec!["--ssh-user", "../a", "--ssh-key", "k", "-i", "image"],
            vec!["--ssh-new-user", "a b", "--ssh-key", "k", "-i", "image"],
            vec!["--ssh-new-user", &long, "--ssh-key", "k", "-i", "image"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
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
