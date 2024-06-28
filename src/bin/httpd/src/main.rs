use clap::Parser;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    addr: std::net::SocketAddr,
    #[arg(short, long)]
    dir: String,
    #[arg(short, long, default_value_t = 4)]
    threads: u8,
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

fn get_txt_file(pb: PathBuf) -> Option<String> {
    // Try cache hit.
    {
        let mut cache = TXT_FILE_CACHE.lock().unwrap();
        if cache.is_none() {
            *cache = Some(HashMap::new());
        }

        let map = cache.as_mut().unwrap();
        match map.get(&pb) {
            Some(s) => return Some(s.clone()),
            None => {}
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
        match map.get(&pb) {
            Some(v) => return Some(v.clone()),
            None => {}
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

fn process(request: tiny_http::Request) {
    let hdr_server =
        tiny_http::Header::from_bytes(&b"Server"[..], &b"tiny-http (Motor OS)"[..]).unwrap();

    match *request.method() {
        tiny_http::Method::Get => {}
        _ => {
            log_request(405, request.url().as_bytes());
            let _ = request.respond(
                tiny_http::Response::empty(tiny_http::StatusCode(405)).with_header(hdr_server),
            );
            return;
        }
    }

    let root = ROOT_DIR.lock().unwrap().clone();

    let request_path = {
        let mut url = request.url();
        if url == "/" {
            Path::new(root.as_str()).join("index.html")
        } else {
            while url.starts_with('/') {
                url = &url[1..];
            }
            if url.is_empty() {
                log_request(404, url.as_bytes());
                let _ = request.respond(
                    tiny_http::Response::empty(tiny_http::StatusCode(404)).with_header(hdr_server),
                );
                return;
            }
            Path::new(root.as_str()).join(url)
        }
    };

    let path_str = request_path.clone().into_os_string().into_string().unwrap();
    if path_str.len() > 256 {
        log_request(404, request.url().as_bytes());
        let _ = request.respond(
            tiny_http::Response::empty(tiny_http::StatusCode(404)).with_header(hdr_server),
        );
        return;
    }

    if path_str.find("..").is_some() {
        log_request(404, request.url().as_bytes());
        let _ = request.respond(tiny_http::Response::empty(tiny_http::StatusCode(404)));
        return;
    }

    if path_str.as_str().ends_with(".jpg") {
        if let Some(bytes) = get_img_file(request_path.clone()) {
            log_request(200, request.url().as_bytes());
            let content_type =
                tiny_http::Header::from_bytes(&b"Content-type"[..], &b"image/jpeg"[..]).unwrap();
            let response = tiny_http::Response::from_data(bytes);
            let _ = request.respond(
                response
                    .with_header(hdr_server)
                    .with_header(content_type)
                    .with_status_code(200),
            );
            return;
        }
    }

    if path_str.as_str().ends_with(".png") {
        if let Some(bytes) = get_img_file(request_path.clone()) {
            log_request(200, request.url().as_bytes());
            let content_type =
                tiny_http::Header::from_bytes(&b"Content-type"[..], &b"image/png"[..]).unwrap();
            let response = tiny_http::Response::from_data(bytes);
            let _ = request.respond(
                response
                    .with_header(hdr_server)
                    .with_header(content_type)
                    .with_status_code(200),
            );
            return;
        }
    }
    if let Some(text) = get_txt_file(request_path.clone()) {
        log_request(200, request.url().as_bytes());
        let response = tiny_http::Response::from_data(text.as_bytes());
        let _ = request.respond(response.with_header(hdr_server).with_status_code(200));
        return;
    }

    log_request(404, request.url().as_bytes());
    let _ = request
        .respond(tiny_http::Response::empty(tiny_http::StatusCode(404)).with_header(hdr_server));
}

fn main() {
    std::thread::spawn(move || input_listener());

    let mut args = Args::parse();
    if args.threads == 0 {
        args.threads = 1;
    }

    match std::fs::read_dir(Path::new(&args.dir)) {
        Ok(_) => {
            *ROOT_DIR.lock().unwrap() = args.dir.clone();
        }
        Err(_) => {
            eprintln!("Directory '{}' not found.", &args.dir);
            std::process::exit(-1);
        }
    }

    let server = Arc::new(tiny_http::Server::http(args.addr).unwrap());
    println!("Serving HTTP on {:?}. Press Ctrl+C to exit.", args.addr);

    let mut threads = Vec::new();
    for _ in 0..args.threads {
        let server = server.clone();

        threads.push(std::thread::spawn(move || loop {
            let request = match server.recv() {
                Ok(rq) => rq,
                Err(e) => {
                    eprintln!("error: {}", e);
                    continue;
                }
            };

            process(request);
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }
}
