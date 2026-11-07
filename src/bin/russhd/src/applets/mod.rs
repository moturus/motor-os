use std::path::PathBuf;

use crate::client::args::{Applet, ConnectionOptions, Destination, ParseError, PtyMode, SshArgs};

#[derive(Debug)]
pub enum AppletError {
    Parse(ParseError),
    Ssh(russh::Error),
    Io(std::io::Error),
    Key(russh::keys::Error),
    SshKey(russh::keys::ssh_key::Error),
    ClientSftp(crate::client::sftp::Error),
    Transfer(crate::client::transfer::Error),
    Message(String),
}

impl std::fmt::Display for AppletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(error) => error.fmt(f),
            Self::Ssh(error) => error.fmt(f),
            Self::Io(error) => error.fmt(f),
            Self::Key(error) => error.fmt(f),
            Self::SshKey(error) => error.fmt(f),
            Self::ClientSftp(error) => error.fmt(f),
            Self::Transfer(error) => error.fmt(f),
            Self::Message(message) => message.fmt(f),
        }
    }
}

impl From<ParseError> for AppletError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<russh::Error> for AppletError {
    fn from(error: russh::Error) -> Self {
        Self::Ssh(error)
    }
}

impl From<std::io::Error> for AppletError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<russh::keys::Error> for AppletError {
    fn from(error: russh::keys::Error) -> Self {
        Self::Key(error)
    }
}

impl From<russh::keys::ssh_key::Error> for AppletError {
    fn from(error: russh::keys::ssh_key::Error) -> Self {
        Self::SshKey(error)
    }
}

impl From<crate::client::sftp::Error> for AppletError {
    fn from(error: crate::client::sftp::Error) -> Self {
        Self::ClientSftp(error)
    }
}

impl From<crate::client::transfer::Error> for AppletError {
    fn from(error: crate::client::transfer::Error) -> Self {
        Self::Transfer(error)
    }
}

mod copy_id;
mod keygen;
mod scp;
mod sftp;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CopyEndpoint {
    Local(PathBuf),
    Remote {
        destination: Destination,
        path: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScpArgs {
    pub connection: ConnectionOptions,
    pub recursive: bool,
    pub sources: Vec<CopyEndpoint>,
    pub target: CopyEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftpArgs {
    pub connection: ConnectionOptions,
    pub destination: Destination,
    pub batch_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeygenArgs {
    pub output: Option<PathBuf>,
    pub comment: Option<String>,
    pub passphrase: Option<String>,
    pub quiet: bool,
    pub print_public: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyIdArgs {
    pub connection: ConnectionOptions,
    pub destination: Destination,
    pub public_key: Option<PathBuf>,
    pub target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedArgs {
    Ssh(SshArgs),
    Scp(ScpArgs),
    Sftp(SftpArgs),
    SshKeygen(KeygenArgs),
    SshCopyId(CopyIdArgs),
}

pub fn parse(applet: Applet, args: &[String]) -> Result<ParsedArgs, ParseError> {
    match applet {
        Applet::Ssh => parse_ssh(args).map(ParsedArgs::Ssh),
        Applet::Scp => parse_scp(args).map(ParsedArgs::Scp),
        Applet::Sftp => parse_sftp(args).map(ParsedArgs::Sftp),
        Applet::SshKeygen => parse_keygen(args).map(ParsedArgs::SshKeygen),
        Applet::SshCopyId => parse_copy_id(args).map(ParsedArgs::SshCopyId),
    }
}

pub fn run(applet: Applet, args: &[String]) -> Result<i32, AppletError> {
    if applet == Applet::Ssh
        && args
            .first()
            .is_some_and(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print!("{}", include_str!("ssh-help.txt"));
        return Ok(0);
    }
    let parsed = parse(applet, args)?;
    match parsed {
        ParsedArgs::Ssh(args) => {
            let runtime = runtime()?;
            runtime
                .block_on(crate::client::session::run_ssh(args))
                .map_err(Into::into)
        }
        ParsedArgs::Scp(args) => runtime()?.block_on(scp::run(args)),
        ParsedArgs::Sftp(args) => runtime()?.block_on(sftp::run(args)),
        ParsedArgs::SshKeygen(args) => keygen::run(args),
        ParsedArgs::SshCopyId(args) => runtime()?.block_on(copy_id::run(args)),
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, AppletError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| AppletError::Message("failed to create SSH runtime".to_owned()))
}

fn parse_ssh(args: &[String]) -> Result<SshArgs, ParseError> {
    let mut connection = ConnectionOptions::default();
    let mut pty = PtyMode::Auto;
    let mut no_session = false;
    let mut index = 0;
    let mut options = true;
    while index < args.len() {
        if options && args[index] == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && parse_common(args, &mut index, &mut connection, 'p', true)? {
            continue;
        }
        if options
            && option_value(args, &mut index, 'L', |value| {
                connection.add_local_forward(value)
            })?
        {
            continue;
        }
        if options && args[index] == "-N" {
            no_session = true;
            index += 1;
            continue;
        }
        if options && args[index] == "-g" {
            connection.force_gateway_ports();
            index += 1;
            continue;
        }
        if options && args[index] == "-t" {
            pty = PtyMode::Force;
            index += 1;
            continue;
        }
        if options && args[index] == "-T" {
            pty = PtyMode::Disable;
            index += 1;
            continue;
        }
        if options && args[index].starts_with('-') {
            return Err(unsupported(&args[index]));
        }
        break;
    }
    let value = args
        .get(index)
        .ok_or_else(|| ParseError::new("missing destination"))?;
    let destination = Destination::parse(value)?;
    Ok(SshArgs {
        connection,
        destination,
        command: args[index + 1..].to_vec(),
        pty,
        no_session,
    })
}

fn parse_scp(args: &[String]) -> Result<ScpArgs, ParseError> {
    let mut connection = ConnectionOptions::default();
    let mut recursive = false;
    let mut index = 0;
    let mut options = true;
    while index < args.len() {
        if options && args[index] == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && parse_common(args, &mut index, &mut connection, 'P', true)? {
            continue;
        }
        if options && args[index] == "-r" {
            recursive = true;
            index += 1;
            continue;
        }
        if options && args[index].starts_with('-') {
            return Err(unsupported(&args[index]));
        }
        break;
    }
    if args.len().saturating_sub(index) < 2 {
        return Err(ParseError::new("scp requires a source and target"));
    }
    let mut endpoints = args[index..]
        .iter()
        .map(|value| parse_copy_endpoint(value))
        .collect::<Result<Vec<_>, _>>()?;
    let target = endpoints.pop().unwrap();
    let remote_sources = endpoints
        .iter()
        .filter(|endpoint| matches!(endpoint, CopyEndpoint::Remote { .. }))
        .count();
    let target_remote = matches!(target, CopyEndpoint::Remote { .. });
    if (target_remote && remote_sources != 0)
        || (!target_remote && (remote_sources != 1 || endpoints.len() != 1))
    {
        return Err(ParseError::new(
            "exactly one side of an scp transfer must be remote",
        ));
    }
    Ok(ScpArgs {
        connection,
        recursive,
        sources: endpoints,
        target,
    })
}

fn parse_sftp(args: &[String]) -> Result<SftpArgs, ParseError> {
    let mut connection = ConnectionOptions::default();
    let mut batch_file = None;
    let mut index = 0;
    let mut options = true;
    while index < args.len() {
        if options && args[index] == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && parse_common(args, &mut index, &mut connection, 'P', true)? {
            continue;
        }
        if options
            && option_value(args, &mut index, 'b', |value| {
                batch_file = Some(PathBuf::from(value));
                Ok(())
            })?
        {
            continue;
        }
        if options && args[index].starts_with('-') {
            return Err(unsupported(&args[index]));
        }
        break;
    }
    let destination = one_destination(args, index)?;
    if batch_file.is_some() {
        connection.force_batch_mode();
    }
    Ok(SftpArgs {
        connection,
        destination,
        batch_file,
    })
}

fn parse_keygen(args: &[String]) -> Result<KeygenArgs, ParseError> {
    let mut parsed = KeygenArgs {
        output: None,
        comment: None,
        passphrase: None,
        quiet: false,
        print_public: false,
    };
    let mut index = 0;
    while index < args.len() {
        if option_value(args, &mut index, 't', |value| {
            if value != "ed25519" {
                return Err(ParseError::new(format!("unsupported key type '{value}'")));
            }
            Ok(())
        })? || option_value(args, &mut index, 'f', |value| {
            if parsed.output.is_none() {
                parsed.output = Some(PathBuf::from(value));
            }
            Ok(())
        })? || option_value(args, &mut index, 'C', |value| {
            if parsed.comment.is_none() {
                parsed.comment = Some(value.to_owned());
            }
            Ok(())
        })? || option_value(args, &mut index, 'N', |value| {
            if parsed.passphrase.is_none() {
                parsed.passphrase = Some(value.to_owned());
            }
            Ok(())
        })? {
            continue;
        }
        match args[index].as_str() {
            "-q" => parsed.quiet = true,
            "-y" => parsed.print_public = true,
            value => return Err(unsupported(value)),
        }
        index += 1;
    }
    if parsed.print_public && parsed.output.is_none() {
        return Err(ParseError::new("ssh-keygen -y requires -f FILE"));
    }
    Ok(parsed)
}

fn parse_copy_id(args: &[String]) -> Result<CopyIdArgs, ParseError> {
    let mut connection = ConnectionOptions::default();
    let mut public_key = None;
    let mut target = None;
    let mut index = 0;
    let mut options = true;
    while index < args.len() {
        if options && args[index] == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && parse_common(args, &mut index, &mut connection, 'p', false)? {
            continue;
        }
        if options
            && option_value(args, &mut index, 'i', |value| {
                public_key = Some(PathBuf::from(value));
                Ok(())
            })?
        {
            continue;
        }
        if options
            && option_value(args, &mut index, 't', |value| {
                target = Some(value.to_owned());
                Ok(())
            })?
        {
            continue;
        }
        if options && args[index].starts_with('-') {
            return Err(unsupported(&args[index]));
        }
        break;
    }
    let destination = one_destination(args, index)?;
    Ok(CopyIdArgs {
        connection,
        destination,
        public_key,
        target,
    })
}

fn one_destination(args: &[String], index: usize) -> Result<Destination, ParseError> {
    if args.len().saturating_sub(index) != 1 {
        return Err(ParseError::new("expected exactly one destination"));
    }
    Destination::parse(&args[index])
}

fn parse_common(
    args: &[String],
    index: &mut usize,
    options: &mut ConnectionOptions,
    port_option: char,
    identity: bool,
) -> Result<bool, ParseError> {
    if option_value(args, index, port_option, |value| options.set_port(value))? {
        return Ok(true);
    }
    if identity && option_value(args, index, 'i', |value| options.add_identity(value))? {
        return Ok(true);
    }
    if option_value(args, index, 'F', |value| {
        if value.is_empty() {
            return Err(ParseError::new("-F requires a config path"));
        }
        options.config_file = Some(PathBuf::from(value));
        Ok(())
    })? {
        return Ok(true);
    }
    if option_value(args, index, 'J', |value| options.apply("ProxyJump", value))? {
        return Ok(true);
    }
    option_value(args, index, 'o', |value| options.apply_o(value))
}

fn option_value(
    args: &[String],
    index: &mut usize,
    option: char,
    apply: impl FnOnce(&str) -> Result<(), ParseError>,
) -> Result<bool, ParseError> {
    let token = &args[*index];
    let prefix = format!("-{option}");
    if token == &prefix {
        let value = args
            .get(*index + 1)
            .ok_or_else(|| ParseError::new(format!("-{option} requires an argument")))?;
        apply(value)?;
        *index += 2;
        Ok(true)
    } else if let Some(value) = token
        .strip_prefix(&prefix)
        .filter(|value| !value.is_empty())
    {
        apply(value)?;
        *index += 1;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn parse_copy_endpoint(value: &str) -> Result<CopyEndpoint, ParseError> {
    let split = if let Some(bracket) = value.find(']') {
        value[bracket + 1..]
            .find(':')
            .map(|colon| bracket + 1 + colon)
    } else {
        value.find(':')
    };
    let Some(colon) = split else {
        return Ok(CopyEndpoint::Local(PathBuf::from(value)));
    };
    let destination = Destination::parse(&value[..colon])?;
    let path = match &value[colon + 1..] {
        "" => ".".to_owned(),
        path => path.to_owned(),
    };
    Ok(CopyEndpoint::Remote { destination, path })
}

fn unsupported(value: &str) -> ParseError {
    ParseError::new(format!("unsupported option or argument '{value}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_required_ssh_forms() {
        let parsed = parse_ssh(&strings(&["user@host"])).unwrap();
        assert_eq!(parsed.destination.user, "user");
        assert!(parsed.command.is_empty());

        let parsed = parse_ssh(&strings(&[
            "-p2222",
            "-o",
            "IdentitiesOnly=yes",
            "-i",
            "test.key",
            "motor@192.168.4.2",
            "echo",
            "hello world",
        ]))
        .unwrap();
        assert_eq!(parsed.connection.port, 2222);
        assert!(parsed.connection.identities_only);
        assert_eq!(parsed.command, ["echo", "hello world"]);
    }

    #[test]
    fn ssh_option_termination_and_pty_order_are_strict() {
        let parsed = parse_ssh(&strings(&["-t", "-T", "--", "-host", "-x"])).unwrap();
        assert_eq!(parsed.pty, PtyMode::Disable);
        assert_eq!(parsed.destination.host, "-host");
        assert_eq!(parsed.command, ["-x"]);
        assert!(parse_ssh(&strings(&["-v", "host"])).is_err());
        let parsed = parse_ssh(&strings(&["-F", "config", "host"])).unwrap();
        assert_eq!(parsed.connection.config_file, Some(PathBuf::from("config")));

        let parsed = parse_ssh(&strings(&["host", "command", "--help"])).unwrap();
        assert_eq!(parsed.command, ["command", "--help"]);
    }

    #[test]
    fn ssh_forwarding_flags_and_o_forms_share_the_endpoint_parser() {
        let parsed = parse_ssh(&strings(&[
            "-N",
            "-g",
            "-L",
            "8080:target:80",
            "-L[::1]:8081:[::2]:81",
            "-o",
            "LocalForward=8082 localhost.:82",
            "-oExitOnForwardFailure=yes",
            "host",
        ]))
        .unwrap();
        assert!(parsed.no_session);
        assert!(parsed.connection.gateway_ports);
        assert!(parsed.connection.exit_on_forward_failure);
        assert_eq!(
            parsed
                .connection
                .local_forwards
                .iter()
                .map(|forward| forward.listen.port)
                .collect::<Vec<_>>(),
            [8080, 8081, 8082]
        );
        assert_eq!(
            parsed.connection.local_forwards[1]
                .target
                .as_ref()
                .unwrap()
                .host,
            "::2"
        );
        for flags in [["-oGatewayPorts=no", "-g"], ["-g", "-oGatewayPorts=no"]] {
            let args = [flags.as_slice(), &["host"]].concat();
            assert!(parse_ssh(&strings(&args)).unwrap().connection.gateway_ports);
        }
        let command = parse_ssh(&strings(&["host", "-N", "-L8080:target:80"])).unwrap();
        assert!(!command.no_session);
        assert!(command.connection.local_forwards.is_empty());
        assert_eq!(command.command, ["-N", "-L8080:target:80"]);
    }

    #[test]
    fn forwarding_flags_are_ssh_only_but_copy_applets_accept_config_options() {
        for flag in ["-N", "-g", "-L8080:target:80"] {
            assert!(parse_scp(&strings(&[flag, "local", "u@host:remote"])).is_err());
            assert!(parse_sftp(&strings(&[flag, "host"])).is_err());
        }
        let scp = parse_scp(&strings(&[
            "-oLocalForward=8080 target:80",
            "local",
            "u@host:remote",
        ]))
        .unwrap();
        let sftp = parse_sftp(&strings(&["-oLocalForward=8080 target:80", "host"])).unwrap();
        assert_eq!(
            scp.connection.local_forwards,
            sftp.connection.local_forwards
        );
        assert_eq!(scp.connection.local_forwards.len(), 1);
        for bad in [
            ["-L", "host"],
            ["-L0:target:80", "host"],
            ["-L8080:::1:80", "host"],
        ] {
            assert!(parse_ssh(&strings(&bad)).is_err());
        }
    }

    #[test]
    fn scp_requires_exactly_one_remote_side() {
        let upload = parse_scp(&strings(&["-P", "2222", "a", "b", "u@h:dir"])).unwrap();
        assert_eq!(upload.sources.len(), 2);
        assert!(matches!(upload.target, CopyEndpoint::Remote { .. }));

        let download = parse_scp(&strings(&["u@[::1]:file", "local"])).unwrap();
        assert!(matches!(download.sources[0], CopyEndpoint::Remote { .. }));
        assert!(parse_scp(&strings(&["a", "b"])).is_err());
        assert!(parse_scp(&strings(&["u@a:x", "u@b:y", "local"])).is_err());
        assert!(parse_scp(&strings(&["u@a:x", "u@b:y"])).is_err());
        assert!(parse_scp(&strings(&["-p", "a", "u@h:b"])).is_err());
    }

    #[test]
    fn sftp_batch_mode_survives_later_connection_options() {
        for values in [
            &["-b-", "host"][..],
            &["-b", "commands", "host"],
            &["-oBatchMode=no", "-b-", "host"],
            &["-b-", "-oBatchMode=no", "host"],
        ] {
            let mut parsed = parse_sftp(&strings(values)).unwrap();
            // Config resolution applies matching settings after CLI parsing.
            parsed.connection.apply("BatchMode", "no").unwrap();
            assert!(parsed.connection.batch_mode, "{values:?}");
        }

        let mut interactive = parse_sftp(&strings(&["host"])).unwrap();
        assert!(!interactive.connection.batch_mode);
        interactive.connection.apply("BatchMode", "yes").unwrap();
        assert!(interactive.connection.batch_mode);

        let mut explicit = parse_sftp(&strings(&["-oBatchMode=no", "host"])).unwrap();
        explicit.connection.apply("BatchMode", "yes").unwrap();
        assert!(!explicit.connection.batch_mode);
    }

    #[test]
    fn parses_sftp_keygen_and_copy_id() {
        let sftp = parse_sftp(&strings(&["-P2222", "-b-", "u@host"])).unwrap();
        assert_eq!(sftp.connection.port, 2222);
        assert_eq!(sftp.batch_file, Some(PathBuf::from("-")));

        let keygen = parse_keygen(&strings(&[
            "-t", "ed25519", "-fkey", "-C", "comment", "-N", "secret", "-q",
        ]))
        .unwrap();
        assert_eq!(keygen.output, Some(PathBuf::from("key")));
        assert_eq!(keygen.passphrase.as_deref(), Some("secret"));
        assert!(keygen.quiet);
        assert!(parse_keygen(&strings(&["-t", "rsa"])).is_err());
        assert!(parse_keygen(&strings(&["-y"])).is_err());

        let copy_id = parse_copy_id(&strings(&["-i", "id.pub", "-p", "2200", "u@h"])).unwrap();
        assert_eq!(copy_id.public_key, Some(PathBuf::from("id.pub")));
        assert_eq!(copy_id.connection.port, 2200);
        assert_eq!(copy_id.target, None);

        let copy_id = parse_copy_id(&strings(&["-t", "/a/list", "u@h"])).unwrap();
        assert_eq!(copy_id.target.as_deref(), Some("/a/list"));
        assert!(parse_copy_id(&strings(&["u@h", "-t", "/a/list"])).is_err());
        assert!(parse_copy_id(&strings(&["-t"])).is_err());
    }
}
