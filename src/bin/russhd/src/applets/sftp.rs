use std::io::BufRead;
use std::path::{Path, PathBuf};

use russh_sftp::client::error::Error as SftpError;

use super::{AppletError, SftpArgs};
use crate::client::prompt;
use crate::client::sftp::SftpConnection;
use crate::client::transfer;

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
        "help" => {
            no_args(args)?;
            println!("Commands: pwd lpwd cd lcd help bye exit quit");
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
}
