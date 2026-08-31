use std::io::BufRead;
use std::path::{Path, PathBuf};

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::protocol::{FileAttributes, StatusCode};

use super::{AppletError, SftpArgs};
use crate::client::prompt;
use crate::client::sftp::SftpConnection;
use crate::client::{local, transfer};

pub(super) async fn run(mut args: SftpArgs) -> Result<i32, AppletError> {
    let batch = args.batch_file.is_some();
    if batch {
        args.connection.batch_mode = true;
    }
    let connection = SftpConnection::connect(&args.connection, &args.destination).await?;
    let result = async {
        let remote = connection.raw.realpath(".").await.map_err(sftp_error)?;
        let mut state = State {
            remote_cwd: remote
                .files
                .first()
                .ok_or_else(|| AppletError::Message("SFTP realpath returned no path".to_owned()))?
                .filename
                .clone(),
            local_cwd: std::env::current_dir()?,
        };
        if let Some(file) = args.batch_file {
            run_batch(&connection, &mut state, &file).await
        } else {
            run_interactive(&connection, &mut state).await
        }
    }
    .await;
    let close = connection.close().await;
    result?;
    close?;
    Ok(0)
}

struct State {
    remote_cwd: String,
    local_cwd: PathBuf,
}

async fn run_batch(
    connection: &SftpConnection,
    state: &mut State,
    path: &Path,
) -> Result<(), AppletError> {
    let input: Box<dyn BufRead> = if path == Path::new("-") {
        Box::new(std::io::BufReader::new(std::io::stdin()))
    } else {
        Box::new(std::io::BufReader::new(std::fs::File::open(path)?))
    };
    for line in input.lines() {
        let words = tokenize(&line?)?;
        if words.is_empty() {
            continue;
        }
        if execute(connection, state, &words).await? == Control::Stop {
            break;
        }
    }
    Ok(())
}

async fn run_interactive(
    connection: &SftpConnection,
    state: &mut State,
) -> Result<(), AppletError> {
    loop {
        let line = prompt::line("sftp> ")?;
        let words = match tokenize(&line) {
            Ok(words) => words,
            Err(error) => {
                eprintln!("sftp: {error}");
                continue;
            }
        };
        if words.is_empty() {
            continue;
        }
        match execute(connection, state, &words).await {
            Ok(Control::Continue) => {}
            Ok(Control::Stop) => return Ok(()),
            Err(error) => eprintln!("sftp: {error}"),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Control {
    Continue,
    Stop,
}

async fn execute(
    connection: &SftpConnection,
    state: &mut State,
    words: &[String],
) -> Result<Control, AppletError> {
    let args = &words[1..];
    match words[0].as_str() {
        "pwd" => {
            no_args(args)?;
            println!("Remote working directory: {}", state.remote_cwd);
        }
        "lpwd" => {
            no_args(args)?;
            println!("Local working directory: {}", state.local_cwd.display());
        }
        "cd" => {
            let path = one_arg(args)?;
            let path = remote_path(&state.remote_cwd, path);
            let canonical = connection.raw.realpath(path).await.map_err(sftp_error)?;
            let path = canonical
                .files
                .first()
                .ok_or_else(|| AppletError::Message("SFTP realpath returned no path".to_owned()))?
                .filename
                .clone();
            if !connection
                .raw
                .stat(path.clone())
                .await
                .map_err(sftp_error)?
                .attrs
                .is_dir()
            {
                return Err(AppletError::Message(
                    "remote path is not a directory".to_owned(),
                ));
            }
            state.remote_cwd = path;
        }
        "lcd" => {
            let path = local_path(&state.local_cwd, one_arg(args)?);
            if !path.metadata()?.is_dir() {
                return Err(AppletError::Message(
                    "local path is not a directory".to_owned(),
                ));
            }
            state.local_cwd = path;
        }
        "ls" => list_remote(connection, state, args).await?,
        "lls" => list_local(state, args)?,
        "get" => get(connection, state, args).await?,
        "put" => put(connection, state, args).await?,
        "mkdir" => {
            let path = remote_path(&state.remote_cwd, one_arg(args)?);
            connection
                .raw
                .mkdir(path, attributes(0o755, true))
                .await
                .map_err(sftp_error)?;
        }
        "lmkdir" => local::create_dir(&local_path(&state.local_cwd, one_arg(args)?), 0o755)?,
        "rm" => {
            let path = remote_path(&state.remote_cwd, one_arg(args)?);
            connection.raw.remove(path).await.map_err(sftp_error)?;
        }
        "rmdir" => {
            let path = remote_path(&state.remote_cwd, one_arg(args)?);
            connection.raw.rmdir(path).await.map_err(sftp_error)?;
        }
        "rename" => {
            // Like OpenSSH sftp: a replacing posix-rename when the server
            // supports it; `-l` requests the plain no-replace rename.
            let (legacy, args) = if args.first().is_some_and(|value| value == "-l") {
                (true, &args[1..])
            } else {
                (false, args)
            };
            two_args(args)?;
            let oldpath = remote_path(&state.remote_cwd, &args[0]);
            let newpath = remote_path(&state.remote_cwd, &args[1]);
            if legacy || !connection.posix_rename {
                connection
                    .raw
                    .rename(oldpath, newpath)
                    .await
                    .map_err(sftp_error)?;
            } else {
                transfer::posix_rename(connection, &oldpath, &newpath).await?;
            }
        }
        "help" => {
            no_args(args)?;
            println!(
                "Commands: pwd lpwd cd lcd ls lls get put mkdir lmkdir rm rmdir rename help bye exit quit"
            );
        }
        "bye" | "exit" | "quit" => {
            no_args(args)?;
            return Ok(Control::Stop);
        }
        command => {
            return Err(AppletError::Message(format!(
                "unsupported SFTP command '{command}'"
            )));
        }
    }
    Ok(Control::Continue)
}

async fn list_remote(
    connection: &SftpConnection,
    state: &State,
    args: &[String],
) -> Result<(), AppletError> {
    at_most_one(args)?;
    let path = remote_path(&state.remote_cwd, args.first().map_or(".", String::as_str));
    let attrs = connection
        .raw
        .lstat(path.clone())
        .await
        .map_err(sftp_error)?
        .attrs;
    if !attrs.is_dir() {
        println!("{path}");
        return Ok(());
    }
    let handle = connection
        .raw
        .opendir(path)
        .await
        .map_err(sftp_error)?
        .handle;
    let result = async {
        loop {
            match connection.raw.readdir(handle.clone()).await {
                Ok(names) => {
                    for entry in names.files {
                        if entry.filename != "." && entry.filename != ".." {
                            println!("{}", entry.filename);
                        }
                    }
                }
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => break,
                Err(error) => return Err(sftp_error(error)),
            }
        }
        Ok(())
    }
    .await;
    let close = connection.raw.close(handle).await.map_err(sftp_error);
    result?;
    close?;
    Ok(())
}

fn list_local(state: &State, args: &[String]) -> Result<(), AppletError> {
    at_most_one(args)?;
    let path = local_path(&state.local_cwd, args.first().map_or(".", String::as_str));
    if !path.is_dir() {
        println!("{}", path.display());
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        println!("{}", entry?.file_name().to_string_lossy());
    }
    Ok(())
}

async fn get(
    connection: &SftpConnection,
    state: &State,
    args: &[String],
) -> Result<(), AppletError> {
    let (recursive, source, target) = transfer_args(args)?;
    let source = remote_path(&state.remote_cwd, source);
    let mut target = match target {
        Some(path) => local_path(&state.local_cwd, path),
        None => state.local_cwd.join(transfer::basename(&source)?),
    };
    if target.is_dir() {
        target = target.join(transfer::basename(&source)?);
    }
    let attrs = connection
        .raw
        .lstat(source.clone())
        .await
        .map_err(sftp_error)?
        .attrs;
    if attrs.is_dir() {
        if !recursive {
            return Err(AppletError::Message("get directory requires -r".to_owned()));
        }
        transfer::download_tree(connection, &source, &target).await?;
    } else {
        transfer::download_file(connection, &source, &target).await?;
    }
    Ok(())
}

async fn put(
    connection: &SftpConnection,
    state: &State,
    args: &[String],
) -> Result<(), AppletError> {
    let (recursive, source, target) = transfer_args(args)?;
    let source = local_path(&state.local_cwd, source);
    let mut target = match target {
        Some(path) => remote_path(&state.remote_cwd, path),
        None => {
            let name = source
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| AppletError::Message("local path has no UTF-8 name".to_owned()))?;
            remote_path(&state.remote_cwd, name)
        }
    };
    if remote_is_dir(connection, &target).await? {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| AppletError::Message("local path has no UTF-8 name".to_owned()))?;
        target = transfer::remote_join(&target, name);
    }
    let metadata = source.symlink_metadata()?;
    if metadata.is_dir() {
        if !recursive {
            return Err(AppletError::Message("put directory requires -r".to_owned()));
        }
        transfer::upload_tree(connection, &source, &target).await?;
    } else {
        transfer::upload_file(connection, &source, &target).await?;
    }
    Ok(())
}

async fn remote_is_dir(connection: &SftpConnection, path: &str) -> Result<bool, AppletError> {
    match connection.raw.stat(path.to_owned()).await {
        Ok(attrs) => Ok(attrs.attrs.is_dir()),
        Err(SftpError::Status(status)) if status.status_code == StatusCode::NoSuchFile => Ok(false),
        Err(error) => Err(sftp_error(error)),
    }
}

fn transfer_args(args: &[String]) -> Result<(bool, &str, Option<&str>), AppletError> {
    let (recursive, args) = if args.first().is_some_and(|value| value == "-r") {
        (true, &args[1..])
    } else {
        (false, args)
    };
    if !(1..=2).contains(&args.len()) {
        return Err(AppletError::Message(
            "get/put require SOURCE and optional TARGET".to_owned(),
        ));
    }
    Ok((recursive, &args[0], args.get(1).map(String::as_str)))
}

fn remote_path(cwd: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        transfer::remote_join(cwd, path)
    }
}

fn local_path(cwd: &Path, path: &str) -> PathBuf {
    let path = Path::new(path);
    if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    }
}

fn attributes(mode: u32, directory: bool) -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(mode);
    if directory {
        attrs.set_dir(true);
    }
    attrs
}

fn no_args(args: &[String]) -> Result<(), AppletError> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(AppletError::Message(
            "command takes no arguments".to_owned(),
        ))
    }
}

fn one_arg(args: &[String]) -> Result<&str, AppletError> {
    if args.len() == 1 {
        Ok(&args[0])
    } else {
        Err(AppletError::Message(
            "command requires one argument".to_owned(),
        ))
    }
}

fn two_args(args: &[String]) -> Result<(), AppletError> {
    if args.len() == 2 {
        Ok(())
    } else {
        Err(AppletError::Message(
            "command requires two arguments".to_owned(),
        ))
    }
}

fn at_most_one(args: &[String]) -> Result<(), AppletError> {
    if args.len() <= 1 {
        Ok(())
    } else {
        Err(AppletError::Message(
            "command takes at most one argument".to_owned(),
        ))
    }
}

fn sftp_error(error: SftpError) -> AppletError {
    crate::client::transfer::Error::from(error).into()
}

fn tokenize(line: &str) -> Result<Vec<String>, AppletError> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for character in line.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            started = true;
        } else if character == '\\' {
            escaped = true;
            started = true;
        } else if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else {
                word.push(character);
            }
        } else if character == '\'' || character == '"' {
            quote = Some(character);
            started = true;
        } else if character.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(character);
            started = true;
        }
    }
    if escaped || quote.is_some() {
        return Err(AppletError::Message(
            "unterminated quote or escape".to_owned(),
        ));
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_quotes_and_escapes() {
        assert_eq!(
            tokenize("put 'two words' three\\ words \"four five\"").unwrap(),
            ["put", "two words", "three words", "four five"]
        );
        assert_eq!(tokenize("mkdir ''").unwrap(), ["mkdir", ""]);
        assert!(tokenize("put 'unterminated").is_err());
        assert!(tokenize("put trailing\\").is_err());
    }

    #[test]
    fn parses_transfer_arguments() {
        let args = ["source", "target"].map(str::to_owned);
        assert_eq!(
            transfer_args(&args).unwrap(),
            (false, "source", Some("target"))
        );

        let recursive = ["-r", "source"].map(str::to_owned);
        assert_eq!(transfer_args(&recursive).unwrap(), (true, "source", None));

        assert!(transfer_args(&[]).is_err());
        let too_many = ["one", "two", "three"].map(str::to_owned);
        assert!(transfer_args(&too_many).is_err());
    }
}
