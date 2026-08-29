use std::io::Write;
use std::path::{Path, PathBuf};

use russh::keys::{Algorithm, PrivateKey, load_secret_key};

use super::{AppletError, KeygenArgs};
use crate::client::{local, prompt};

pub(super) fn run(args: KeygenArgs) -> Result<i32, AppletError> {
    if args.print_public {
        return print_public(&args);
    }
    let (path, is_default) = output_path(args.output);
    let public_path = public_path(&path);
    if path.exists() || public_path.exists() {
        return Err(AppletError::Message(format!(
            "refusing to overwrite '{}' or '{}'",
            path.display(),
            public_path.display()
        )));
    }
    if is_default {
        local::ensure_private_dir(path.parent().unwrap())?;
    }

    let mut passphrase = match args.passphrase {
        Some(value) => value,
        None => read_new_passphrase()?,
    };
    let result = generate(&path, &public_path, args.comment, &passphrase);
    prompt::clear_secret(&mut passphrase);
    result?;
    if !args.quiet {
        println!("Your identification has been saved in {}", path.display());
        println!(
            "Your public key has been saved in {}",
            public_path.display()
        );
    }
    Ok(0)
}

fn print_public(args: &KeygenArgs) -> Result<i32, AppletError> {
    let path = args.output.as_ref().unwrap();
    let key = match load_secret_key(path, None) {
        Ok(key) => key,
        Err(russh::keys::Error::KeyIsEncrypted) => {
            let mut passphrase =
                prompt::secret(&format!("Enter passphrase for key '{}': ", path.display()))?;
            let key = load_secret_key(path, Some(&passphrase));
            prompt::clear_secret(&mut passphrase);
            key?
        }
        Err(error) => return Err(error.into()),
    };
    println!("{}", key.public_key().to_openssh()?);
    Ok(0)
}

fn read_new_passphrase() -> Result<String, AppletError> {
    let mut first = prompt::secret("Enter passphrase (empty for no passphrase): ")?;
    let mut second = prompt::secret("Enter same passphrase again: ")?;
    if first != second {
        prompt::clear_secret(&mut first);
        prompt::clear_secret(&mut second);
        return Err(AppletError::Message("passphrases do not match".to_owned()));
    }
    prompt::clear_secret(&mut second);
    Ok(first)
}

fn generate(
    path: &Path,
    public_path: &Path,
    comment: Option<String>,
    passphrase: &str,
) -> Result<(), AppletError> {
    let mut key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    if let Some(comment) = comment {
        key.set_comment(comment);
    }
    let public = format!("{}\n", key.public_key().to_openssh()?);
    let key = if passphrase.is_empty() {
        key
    } else {
        key.encrypt(&mut rand::rng(), passphrase)?
    };
    let private = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;

    let mut private_file = local::create_file(path, 0o600)?;
    if let Err(error) = private_file.write_all(private.as_bytes()) {
        drop(private_file);
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    if let Err(error) = private_file.flush() {
        drop(private_file);
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    drop(private_file);

    let mut public_file = match local::create_file(public_path, 0o644) {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(path);
            return Err(error.into());
        }
    };
    if let Err(error) = public_file
        .write_all(public.as_bytes())
        .and_then(|()| public_file.flush())
    {
        drop(public_file);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(public_path);
        return Err(error.into());
    }
    Ok(())
}

fn output_path(output: Option<PathBuf>) -> (PathBuf, bool) {
    if let Some(path) = output {
        return (path, false);
    }
    #[cfg(target_os = "motor")]
    return (PathBuf::from("/user/cfg/ssh/id_ed25519"), true);
    #[cfg(not(target_os = "motor"))]
    {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        (home.join(".ssh/id_ed25519"), true)
    }
}

fn public_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(".pub");
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(name: &str) -> (PathBuf, PathBuf) {
        let private =
            std::env::temp_dir().join(format!("russhd-keygen-{}-{name}", std::process::id()));
        let public = public_path(&private);
        let _ = std::fs::remove_file(&private);
        let _ = std::fs::remove_file(&public);
        (private, public)
    }

    #[test]
    fn generates_round_trip_keys() {
        for (name, passphrase) in [("plain", ""), ("encrypted", "secret")] {
            let (private, public) = paths(name);
            generate(&private, &public, Some("comment".to_owned()), passphrase).unwrap();
            let decoded =
                load_secret_key(&private, (!passphrase.is_empty()).then_some(passphrase)).unwrap();
            assert_eq!(decoded.public_key().comment().as_str().unwrap(), "comment");
            assert_eq!(
                std::fs::read_to_string(&public).unwrap().trim(),
                decoded.public_key().to_openssh().unwrap()
            );
            std::fs::remove_file(private).unwrap();
            std::fs::remove_file(public).unwrap();
        }
    }

    #[test]
    fn refuses_to_replace_public_key() {
        let (private, public) = paths("replace");
        std::fs::write(&public, b"existing").unwrap();
        assert!(generate(&private, &public, None, "").is_err());
        assert!(!private.exists());
        assert_eq!(std::fs::read(&public).unwrap(), b"existing");
        std::fs::remove_file(public).unwrap();
    }
}
