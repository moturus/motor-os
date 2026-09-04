use std::env;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn main() {
    if let Err(error) = run() {
        eprintln!("git-curl fixture: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let value_after = |name: &str| {
        arguments
            .windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].as_str())
            .ok_or_else(|| format!("missing {name}"))
    };
    let url = value_after("--url")?;
    let write_out = value_after("--write-out")?;
    let nonce = write_out
        .lines()
        .find_map(|line| line.strip_prefix("LORRY-CURL-GIT-1 "))
        .ok_or_else(|| "missing Git control nonce".to_owned())?;
    let remote = url
        .strip_prefix("https://")
        .ok_or_else(|| "request is not HTTPS".to_owned())?;
    let (_, path_and_query) = remote
        .split_once('/')
        .ok_or_else(|| "request URL has no path".to_owned())?;
    let (path, query) = path_and_query
        .split_once('?')
        .map_or((path_and_query, ""), |(path, query)| (path, query));
    let headers = arguments
        .windows(2)
        .filter(|pair| pair[0] == "--header")
        .map(|pair| pair[1].as_str())
        .collect::<Vec<_>>();
    let content_type = header(&headers, "Content-Type").unwrap_or_default();
    let git_protocol = header(&headers, "Git-Protocol").unwrap_or_default();
    let post = arguments.iter().any(|argument| argument == "--data-binary");
    let mut body = Vec::new();
    if post {
        std::io::stdin()
            .read_to_end(&mut body)
            .map_err(|error| format!("failed to read request body: {error}"))?;
    }

    let executable = env::current_exe()
        .map_err(|error| format!("failed to locate fixture executable: {error}"))?;
    let work = executable
        .parent()
        .and_then(|path| path.parent())
        .ok_or_else(|| "fixture executable has no work root".to_owned())?;
    let mut command = Command::new("/usr/bin/git");
    command
        .arg("http-backend")
        .env_clear()
        .env("GIT_PROJECT_ROOT", work.join("git"))
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", if post { "POST" } else { "GET" })
        .env("PATH_INFO", format!("/{path}"))
        .env("QUERY_STRING", query)
        .env("SERVER_PROTOCOL", "HTTP/1.1")
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("CONTENT_TYPE", content_type)
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("HTTP_GIT_PROTOCOL", git_protocol)
        .stdin(if post { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to start git http-backend: {error}"))?;
    if post {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&body)
            .map_err(|error| format!("failed to send request body: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for git http-backend: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git http-backend failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let split = output
        .stdout
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|position| (position, 4))
        .or_else(|| {
            output
                .stdout
                .windows(2)
                .position(|bytes| bytes == b"\n\n")
                .map(|position| (position, 2))
        })
        .ok_or_else(|| "git http-backend emitted no CGI header terminator".to_owned())?;
    let response_headers = String::from_utf8_lossy(&output.stdout[..split.0]);
    let status = response_headers
        .lines()
        .find_map(|line| line.strip_prefix("Status: "))
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or("200");
    let response_type = response_headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Type: "))
        .map(str::trim)
        .unwrap_or("");
    let response_body = &output.stdout[split.0 + split.1..];
    std::io::stdout()
        .write_all(response_body)
        .map_err(|error| format!("failed to write response body: {error}"))?;
    eprintln!(
        "\nLORRY-CURL-GIT-1 {nonce}\nstatus={status}\nurl={url}\nredirect=\ntype={response_type}\nsize={}\nEND-LORRY-CURL-GIT-1 {nonce}",
        response_body.len()
    );
    Ok(())
}

fn header<'a>(headers: &'a [&str], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|header| {
        let (candidate, value) = header.split_once(':')?;
        candidate
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}
