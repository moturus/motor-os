#![allow(unexpected_cfgs)]

#[cfg(target_os = "moturus")]
use std::io::IsTerminal;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::*;

use russh::server::{Msg, Server as _, Session};
use russh::*;

use russhd::config;
use russhd::local_session::StdinTx;

// Intercept Ctrl+C ourselves if the OS does not do it for us.
#[cfg(target_os = "moturus")]
fn input_listener() {
    use std::io::Read;

    if !std::io::stdin().is_terminal() {
        return;
    }
    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        if sz == 0 {
            break;
        }
        for b in &input[0..sz] {
            if *b == 3 {
                log::info!("Got ^C. Bye!");
                std::process::exit(0);
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    #[cfg(target_os = "moturus")]
    if std::io::stdin().is_terminal() {
        std::thread::spawn(input_listener);

        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            // .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        moto_log::init("russhd").unwrap();
    }

    let args = Vec::from_iter(std::env::args());
    assert!(!args.is_empty());
    if args.len() != 2 {
        log::error!("Usage: {} %CONFIG_FILENAME", args[0]);
        return;
    }

    let Ok(program_config) = config::read_from_file(&args[1]) else {
        log::error!("Error reading config file '{}'.", args[1]);
        return;
    };

    if program_config.is_default() {
        log::error!(
            "\n\nWARNING: {}: one of configuration secrets is set to a default/test value. This is NOT secure.\n\n",
            args[0]
        );
    }

    let russh_config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![program_config.host_key().clone()],
        preferred: Preferred {
            ..Preferred::default()
        },
        ..Default::default()
    };
    let config = Arc::new(russh_config);
    let mut sh = ConnectionHandler::new(program_config.clone(), None);

    log::info!("Starting SSHD on {:?}.", program_config.listen_on());
    sh.run_on_address(config, program_config.listen_on())
        .await
        .unwrap();
}

#[allow(unused)]
#[derive(Debug)]
struct PtyRequest {
    cols: u32,
    rows: u32,

    #[allow(unused)]
    modes: Vec<(Pty, u32)>,
}

/// Handles a client connection, which can _potentially_ have multiple channels
/// (multiple shell sessions, port forwarding, sftp, etc.). But in our current
/// implementation we support only a single channel.
struct ConnectionHandler {
    id: u64,
    config: Arc<config::Config>,

    channel: Option<(ChannelId, server::Handle)>,
    remote_addr: Option<SocketAddr>,
    pty_request: Option<PtyRequest>,
    authenticated_user: Option<String>,

    stdin_tx: Option<StdinTx>,
}

impl ConnectionHandler {
    fn new(config: Arc<config::Config>, remote_addr: Option<SocketAddr>) -> Self {
        static ID: AtomicU64 = AtomicU64::new(0);
        Self {
            config,
            channel: None,
            pty_request: None,
            id: ID.fetch_add(1, Ordering::Relaxed) + 1,
            remote_addr,
            authenticated_user: None,
            stdin_tx: None,
        }
    }

    async fn spawn_shell(&mut self) -> Result<(), russh::Error> {
        #[cfg(target_os = "moturus")]
        let cmd = "/bin/rush -i";
        #[cfg(not(target_os = "moturus"))]
        let cmd = "/bin/bash -i";

        let (channel, session) = self.channel.clone().unwrap();
        let session_clone = session.clone();
        self.stdin_tx =
            Some(russhd::local_session::spawn(cmd, channel, session, &self.config).await?);

        // Show a greeting.
        #[cfg(target_os = "moturus")]
        let data = CryptoVec::from("\n\rHello! Welcome to Motor OS.\r\n\n\r");
        #[cfg(not(target_os = "moturus"))]
        let data = CryptoVec::from("Hello! Welcome to RUSSHD.\r\n\r\n");

        session_clone
            .data(channel, data)
            .await
            .map_err(|_| russh::Error::Inconsistent)?;

        Ok(())
    }

    async fn exec(&mut self, cmdline: &str) -> Result<(), russh::Error> {
        let (channel, session) = self.channel.clone().unwrap();
        self.stdin_tx =
            Some(russhd::local_session::spawn(cmdline, channel, session, &self.config).await?);

        Ok(())
    }
}

impl server::Server for ConnectionHandler {
    type Handler = Self;
    fn new_client(&mut self, addr: Option<std::net::SocketAddr>) -> Self {
        log::info!("New Client: {addr:?}");
        Self::new(self.config.clone(), addr)
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        log::info!("Session error: {error:?}");
    }
}

impl server::Handler for ConnectionHandler {
    type Error = russh::Error;

    // // The standard openssh client does not print the banner.
    // async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
    //     Ok(Some("Motor OS SSH Server.".to_owned()))
    // }

    async fn auth_none(&mut self, user: &str) -> Result<server::Auth, Self::Error> {
        let can_pwd = self.config.can_auth_pwd(user);
        let can_key = self.config.can_auth_pubkey(user);

        if !can_pwd && !can_key {
            return Ok(server::Auth::reject());
        }

        let mut methods = vec![];
        if can_pwd {
            methods.push(russh::MethodKind::Password);
        }
        if can_key {
            methods.push(russh::MethodKind::PublicKey);
        }

        Ok(server::Auth::Reject {
            proceed_with_methods: Some(russh::MethodSet::from((methods).as_slice())),
            partial_success: false,
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &keys::ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        let can_pwd = self.config.can_auth_pwd(user);
        let can_key = self.config.can_auth_pubkey(user);

        if !can_pwd && !can_key {
            return Ok(server::Auth::reject());
        }

        if can_key && self.config.authenticate_pubkey(user, public_key).is_ok() {
            return Ok(server::Auth::Accept);
        }

        let mut methods = vec![];
        if can_pwd {
            methods.push(russh::MethodKind::Password);
        }
        if can_key {
            methods.push(russh::MethodKind::PublicKey);
        }

        Ok(server::Auth::Reject {
            proceed_with_methods: Some(russh::MethodSet::from((methods).as_slice())),
            partial_success: true,
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &keys::ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        if let Some(authenticated) = self.authenticated_user.as_ref() {
            log::warn!(
                "auth_pubkey() called for user '{user}' while user '{authenticated}' has been authenticated."
            );
            return Ok(server::Auth::reject());
        }

        match self.config.authenticate_pubkey(user, key) {
            Ok(_) => {
                log::info!("User {user} authenticated.");
                self.authenticated_user = Some(user.to_owned());
                Ok(server::Auth::Accept)
            }
            Err(err) => {
                log::info!("User {user} failed to authenticate: {err:?}.");
                Ok(server::Auth::reject())
            }
        }
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        _certificate: &keys::Certificate,
    ) -> Result<server::Auth, Self::Error> {
        self.auth_none(user).await
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<server::Auth, Self::Error> {
        if let Some(authenticated) = self.authenticated_user.as_ref() {
            log::warn!(
                "auth_password() called for user '{user}' while user '{authenticated}' has been authenticated."
            );
            return Ok(server::Auth::reject());
        }

        match self.config.authenticate_pwd(user, password) {
            Ok(_) => {
                log::info!("User {user} authenticated.");
                self.authenticated_user = Some(user.to_owned());
                Ok(server::Auth::Accept)
            }
            Err(err) => {
                log::info!("User {user} failed to authenticate: {err:?}.");
                Ok(server::Auth::reject())
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        log::info!("New Session: {:?}", channel.id());
        if self.channel.is_some() {
            return Ok(false);
        }

        self.channel = Some((channel.id(), session.handle()));
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // After a client has sent an EOF, indicating that they don't want
        // to send more data in this session, the channel can be closed.
        session.close(channel)
    }

    #[allow(unused_variables, clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::debug!(
            "pty_request: {channel}-'{term}': {col_width}:{row_height} - {pix_width}:{pix_height} {modes:?}"
        );

        let Some((chan, _)) = self.channel else {
            return Err(Self::Error::Inconsistent);
        };
        if channel != chan {
            return Err(Self::Error::Inconsistent);
        }

        if let Some(prev) = self.pty_request.replace(PtyRequest {
            cols: col_width,
            rows: row_height,
            modes: modes.to_vec(),
        }) {
            // Logging as a warning as we don't know what to do here (yet).
            log::warn!("prev PTY request: {prev:?}");
        }

        Ok(())
    }

    #[allow(unused_variables)]
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::info!("shell_request");

        let Some((chan, _)) = self.channel else {
            return Err(Self::Error::Inconsistent);
        };
        if channel != chan {
            return Err(Self::Error::Inconsistent);
        }
        if self.pty_request.is_none() {
            return Err(Self::Error::Inconsistent);
        }

        self.spawn_shell().await
    }

    #[allow(unused_variables)]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Ok(cmdline) = str::from_utf8(data) else {
            return Err(Self::Error::IO(std::io::ErrorKind::InvalidInput.into()));
        };

        log::info!("exec_request: `{cmdline}`");
        self.exec(cmdline).await
    }

    #[allow(unused_variables)]
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::info!("subsystem_request: {name}");
        session.channel_failure(channel)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(stdin_tx) = self.stdin_tx.as_ref() else {
            log::warn!("Got remote data without local shell session.");
            return Err(russh::Error::Disconnect);
        };

        if let Err(err) = stdin_tx.send(data.to_vec()).await {
            log::warn!("stdin_tx.send() failed with error '{err:?}'.");
            return Err(russh::Error::Disconnect);
        }

        Ok(())
    }
}

impl Drop for ConnectionHandler {
    fn drop(&mut self) {
        let from = self
            .remote_addr
            .map(|addr| format!(" from {addr:?}"))
            .unwrap_or_default();
        log::info!(
            "Dropping Connection #{} for user '{}'{}",
            self.id,
            self.authenticated_user.as_ref().unwrap_or(&String::new()),
            from
        );
    }
}
