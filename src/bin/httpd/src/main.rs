/// A simple HTTP(s) server. Supports minimal HTTP 1.1 functionality,
/// basically serving static html/png content. The main focus is on
/// stability.
use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    addr: std::net::SocketAddr,
    #[arg(short, long)]
    dir: String, // The directory to serve content from.

    #[arg(long)]
    ssl_cert: Option<String>,
    #[arg(long)]
    ssl_key: Option<String>,
}

// Intercept Ctrl+C ourselves if the OS does not do it for us.
fn input_listener() {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("\ncaught ^C: exiting.");
                std::process::exit(0);
            }
        }
    }
}

static ROOT_DIR: Mutex<String> = Mutex::new(String::new());
static TXT_FILE_CACHE: Mutex<Option<HashMap<PathBuf, String>>> = Mutex::new(None);
static IMG_FILE_CACHE: Mutex<Option<HashMap<PathBuf, Vec<u8>>>> = Mutex::new(None);
static BAD_FILE_CACHE: Mutex<Option<HashSet<PathBuf>>> = Mutex::new(None);
const MAX_BAD_CACHE_LEN: usize = 4096;
const MAX_HEADER_LEN: usize = 4096 * 4;
const MAX_HEADERS: usize = 64;

static BINARY_CONTENT_TYPES: std::sync::LazyLock<HashMap<&'static str, &'static str>> =
    std::sync::LazyLock::new(|| {
        let mut types = HashMap::new();
        types.insert("png", "image/png");
        types.insert("woff", "font/woff");
        types.insert("woff2", "font/woff2");

        types
    });

fn get_txt_file(pb: PathBuf) -> Option<String> {
    // Try cache hit.
    {
        let mut cache = TXT_FILE_CACHE.lock().unwrap();
        if cache.is_none() {
            *cache = Some(HashMap::new());
        }

        let map = cache.as_mut().unwrap();
        if let Some(s) = map.get(&pb) {
            return Some(s.clone());
        }
    }

    let mut bad_cache_full = false;
    // Try cache miss.
    {
        let bad_cache = BAD_FILE_CACHE.lock().unwrap();
        if let Some(set) = &*bad_cache {
            if set.len() >= MAX_BAD_CACHE_LEN {
                bad_cache_full = true;
            }
            if set.contains(&pb) {
                return None;
            }
        }
    }

    // Try reading the file.
    if let Ok(s) = std::fs::read_to_string(pb.clone()) {
        TXT_FILE_CACHE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .insert(pb, s.clone());
        Some(s)
    } else {
        if !bad_cache_full {
            let mut bad_cache = BAD_FILE_CACHE.lock().unwrap();
            if bad_cache.is_none() {
                *bad_cache = Some(HashSet::new());
            }
            bad_cache.as_mut().unwrap().insert(pb);
        }
        None
    }
}

fn get_img_file(pb: PathBuf) -> Option<Vec<u8>> {
    // Try cache hit.
    {
        let mut cache = IMG_FILE_CACHE.lock().unwrap();
        if cache.is_none() {
            *cache = Some(HashMap::new());
        }

        let map = cache.as_mut().unwrap();
        if let Some(v) = map.get(&pb) {
            return Some(v.clone());
        }
    }

    let mut bad_cache_full = false;
    // Try cache miss.
    {
        let bad_cache = BAD_FILE_CACHE.lock().unwrap();
        if let Some(set) = &*bad_cache {
            if set.len() >= MAX_BAD_CACHE_LEN {
                bad_cache_full = true;
            }
            if set.contains(&pb) {
                return None;
            }
        }
    }

    // Try reading the file.
    if let Ok(bytes) = std::fs::read(pb.clone()) {
        IMG_FILE_CACHE
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .insert(pb, bytes.clone());
        Some(bytes)
    } else {
        if !bad_cache_full {
            let mut bad_cache = BAD_FILE_CACHE.lock().unwrap();
            if bad_cache.is_none() {
                *bad_cache = Some(HashSet::new());
            }
            bad_cache.as_mut().unwrap().insert(pb);
        }
        None
    }
}

fn sanitize(s: &[u8]) -> String {
    let mut res = String::new();
    res.reserve(64);
    let bytes = if s.len() < 64 { s } else { &s[0..64] };
    for b in bytes {
        if b.is_ascii() {
            res.push(*b as char);
        } else {
            res.push('¿');
        }
    }
    res
}

fn log_request(status: u16, request: &[u8]) {
    let now = time::OffsetDateTime::now_utc();
    println!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC {status}: {}",
        now.year(),
        now.month() as u8,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.millisecond(),
        sanitize(request)
    );
}

// Only GET requests are currently supported.
struct HttpRequest {
    url: String,
    #[allow(unused)]
    headers: Vec<String>,
}

fn read_line(reader: &mut dyn std::io::Read) -> Result<String, u32> {
    let mut line = String::new();

    let mut buf = [0_u8; 1];
    loop {
        let sz = reader.read(&mut buf).map_err(|_| 400_u32)?;
        if sz == 0 {
            return Err(400);
        }

        assert_eq!(sz, 1);
        let b = buf[0];
        if b == b'\n' {
            if line.is_empty() {
                continue;
            }
            return Err(400);
        }

        if b == b'\r' {
            break;
        }

        if !b.is_ascii() {
            return Err(400);
        }

        line.push(b.into());

        // Lines are only read as the first/status line and as headers.
        if line.len() > MAX_HEADER_LEN {
            return Err(431); // Header too large.
        }
    }

    Ok(line)
}

fn parse_status_line(line: &str) -> Result<(&str, String), u32> {
    let words: Vec<&str> = line.split_whitespace().collect();
    if words.len() < 2 {
        return Err(400);
    }

    Ok((words[0], words[1].to_owned()))
}

fn read_request(reader: &mut dyn std::io::Read) -> Result<HttpRequest, u32> {
    let line = read_line(reader)?;
    let (method, url) = parse_status_line(line.as_str())?;

    if method != "GET" {
        return Err(421); // Misdirected.
    }

    let mut headers = vec![];
    loop {
        if headers.len() > MAX_HEADERS {
            return Err(431); // Header too large.
        }

        let line = read_line(reader)?;
        if line.is_empty() {
            break;
        }
        headers.push(line);
    }

    Ok(HttpRequest { url, headers })
}

fn handle_request(request: HttpRequest, writer: &mut dyn std::io::Write) -> Result<(), ()> {
    let root = ROOT_DIR.lock().unwrap().clone();

    let request_path = {
        let mut url = request.url.as_str();
        if url.contains("..") {
            // Somebody is naughty.
            log_request(400, request.url.as_bytes());
            return write_error(400, writer);
        }

        if url.contains("?") {
            // We don't accept/support dynamic content.
            log_request(421, request.url.as_bytes());
            return write_error(421, writer); // Misdirected request.
        }

        if url == "/" {
            Path::new(root.as_str()).join("index.html")
        } else {
            while url.starts_with('/') {
                url = &url[1..];
            }
            if url.is_empty() {
                log_request(404, url.as_bytes());
                return write_error(404, writer);
            }
            Path::new(root.as_str()).join(url)
        }
    };

    let path_str = request_path.clone().into_os_string().into_string().unwrap();
    if path_str.len() > 256 {
        log_request(404, request.url.as_bytes());
        return write_error(404, writer);
    }

    if path_str.contains("..") {
        log_request(404, request.url.as_bytes());
        return write_error(404, writer);
    }

    if let Some(ext) = request_path.extension().and_then(std::ffi::OsStr::to_str) {
        if let Some(content_type) = BINARY_CONTENT_TYPES.get(ext) {
            if let Some(bytes) = get_img_file(request_path.clone()) {
                log_request(200, request.url.as_bytes());

                writer.write_all(format!("HTTP/1.1 200 OK\r\nContent-type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        content_type, bytes.len()
                    )
                    .as_bytes(),
                )
                .map_err(|err| {
                    println!("write headers failed with erro {err:?}");
                })?;
                writer.write_all(&bytes).map_err(|err| {
                    println!("write bytes failed with err {err:?}");
                })?;
                return writer.flush().map_err(|err| {
                    println!("writer flush failed with err {err:?}");
                });
            }
            log_request(404, request.url.as_bytes());
            return write_error(404, writer);
        }
    }

    if !path_str.as_str().ends_with(".html") {
        log_request(404, request.url.as_bytes());
        return write_error(404, writer);
    }

    if let Some(text) = get_txt_file(request_path.clone()) {
        log_request(200, request.url.as_bytes());
        let bytes = text.as_bytes();

        writer.write_all(format!("HTTP/1.1 200 OK\r\nContent-type: text/html;charset=UTF-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()).as_bytes()).map_err(|err| {
                println!("write headers failed with erro {err:?}");
            })?;
        writer.write_all(bytes).map_err(|err| {
            println!("write bytes failed with err {err:?}");
        })?;
        return writer.flush().map_err(|err| {
            println!("writer flush failed with err {err:?}");
        });
    }

    log_request(404, request.url.as_bytes());
    write_error(404, writer)
}

fn write_error(error: u32, writer: &mut dyn std::io::Write) -> Result<(), ()> {
    let str_error = match error {
        400 => "400 Bad Request",
        404 => "404 Not Found",
        421 => "421 Misdirected Request",
        431 => "431 Request Header Fields Too Large",
        _ => {
            println!("{}:{} unknown request status: {error}", file!(), line!());
            "500 Internal Server Error"
        }
    };
    writer
        .write_all(
            format!("HTTP/1.1 {str_error}\r\nContent-type: text/plain\r\n\r\n{str_error}\r\n")
                .as_bytes(),
        )
        .map_err(|_| ())?;

    writer.flush().map_err(|_| ())
}

/// The "normal" TcpStream may return Ok(0) when reading/writing from/to a closed
/// stream, and Rustls does not handle this properly. So we intercept Ok(0) here
/// and return errors.
struct StrictTcpStream {
    inner: std::net::TcpStream,
}

impl std::io::Read for StrictTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let sz = self.inner.read(buf)?;
        if sz == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF",
            ))
        } else {
            Ok(sz)
        }
    }
}

impl std::io::Write for StrictTcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let sz = self.inner.write(buf)?;
        if sz == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF",
            ))
        } else {
            Ok(sz)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// A client connected to this HTTP(s) server.
struct ClientConnection {
    tcp_stream: StrictTcpStream,

    // Although this is a client connection, rustls calls it
    // a server connection.
    tls_conn: Option<rustls::ServerConnection>,
}

impl ClientConnection {
    fn new(
        tcp_stream: std::net::TcpStream,
        tls_config: Option<Arc<rustls::ServerConfig>>,
    ) -> std::io::Result<Self> {
        let mut tcp_stream = StrictTcpStream { inner: tcp_stream };

        if let Some(tls_config) = tls_config {
            let mut tls_conn = rustls::ServerConnection::new(tls_config).unwrap();
            if tls_conn.is_handshaking() {
                tls_conn.complete_io(&mut tcp_stream)?;
                assert!(!tls_conn.is_handshaking());
            }
            Ok(Self {
                tcp_stream,
                tls_conn: Some(tls_conn),
            })
        } else {
            Ok(Self {
                tcp_stream,
                tls_conn: None,
            })
        }
    }
}

impl std::io::Read for ClientConnection {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Self {
            tcp_stream,
            tls_conn,
        } = self;
        match tls_conn {
            None => tcp_stream.read(buf),
            Some(tls_conn) => loop {
                match tls_conn.reader().read(buf) {
                    Ok(sz) => return Ok(sz),
                    Err(err) => {
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            tls_conn.complete_io(tcp_stream)?;
                            continue;
                        }
                    }
                }
            },
        }
    }
}

impl std::io::Write for ClientConnection {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Self {
            tcp_stream,
            tls_conn,
        } = self;
        match tls_conn {
            None => tcp_stream.write(buf),
            Some(tls_conn) => {
                assert!(!tls_conn.wants_write());
                match tls_conn.writer().write(buf) {
                    Ok(sz) => {
                        while tls_conn.wants_write() {
                            let _ = tls_conn.write_tls(tcp_stream)?;
                        }
                        Ok(sz)
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let Self {
            tcp_stream,
            tls_conn,
        } = self;
        if let Some(tls_conn) = tls_conn {
            debug_assert!(!tls_conn.wants_write());
            let _ = tls_conn.complete_io(tcp_stream);
            tcp_stream.flush()
            // Ok(())
        } else {
            tcp_stream.flush()
        }
    }
}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        let Self {
            tcp_stream,
            tls_conn,
        } = self;
        if let Some(tls_conn) = tls_conn {
            tls_conn.send_close_notify();
            let _ = tls_conn.write_tls(tcp_stream);
            std::thread::sleep(std::time::Duration::from_millis(10));
            let _ = tcp_stream.inner.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::thread::spawn(input_listener);

    let args = Args::parse();

    match std::fs::read_dir(Path::new(&args.dir)) {
        Ok(_) => {
            *ROOT_DIR.lock().unwrap() = args.dir.clone();
        }
        Err(_) => {
            eprintln!("Directory '{}' not found.", &args.dir);
            std::process::exit(-1);
        }
    }

    let tcp_listener = TcpListener::bind(args.addr).unwrap();

    let tls_config = if args.ssl_cert.is_some() {
        let cert_file = args.ssl_cert.as_ref().unwrap();
        let private_key_file = args.ssl_key.as_ref().unwrap();

        let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_file)?))
            .collect::<Result<Vec<_>, _>>()?;
        let private_key =
            rustls_pemfile::private_key(&mut BufReader::new(&mut File::open(private_key_file)?))?
                .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .unwrap();
        println!("Serving HTTPs on {:?}. Press Ctrl+C to exit.", args.addr);
        Some(Arc::new(config))
    } else {
        println!("Serving HTTP on {:?}. Press Ctrl+C to exit.", args.addr);
        None
    };

    static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

    loop {
        let (stream, _) = tcp_listener.accept().unwrap();
        let tls_config = tls_config.clone();

        let _ = std::thread::spawn(move || {
            let num_conns = CONNECTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if num_conns > 20 {
                println!("{num_conns} open connections");
            }

            let mut conn = match ClientConnection::new(stream, tls_config) {
                Ok(conn) => conn,
                Err(err) => {
                    println!("ClientConnection::new() failed with {err:?}");
                    CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            };

            let request = read_request(&mut conn);

            let _ = match request {
                Ok(req) => handle_request(req, &mut conn),
                Err(err) => write_error(err, &mut conn),
            };

            CONNECTIONS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}
