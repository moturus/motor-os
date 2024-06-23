use oxhttp::model::{Request, Response, Status};
use oxhttp::Server;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

// Intercept Ctrl+C ourselves if the OS does not do it for us.
fn input_listener(prog: String) {
    use std::io::Read;

    loop {
        let mut input = [0_u8; 16];
        let sz = std::io::stdin().read(&mut input).unwrap();
        for b in &input[0..sz] {
            if *b == 3 {
                println!("\n{prog}: caught ^C: exiting.");
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

fn log_request(status: Status, request: &[u8]) {
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

fn serve(request: &mut Request) -> Response {
    if request.method().as_bytes() != b"GET" {
        log_request(Status::NOT_IMPLEMENTED, request.method().as_bytes());
        return Response::builder(Status::NOT_IMPLEMENTED).with_body("501: Not implemented.");
    }

    let root = ROOT_DIR.lock().unwrap().clone();

    let request_path = {
        let mut url = request.url().path();
        if url == "/" {
            Path::new(root.as_str()).join("index.html")
        } else {
            while url.starts_with('/') {
                url = &url[1..];
            }
            if url.is_empty() {
                log_request(Status::NOT_FOUND, request.url().path().as_bytes());
                return Response::builder(Status::NOT_FOUND).with_body("404: Not found.");
            }
            Path::new(root.as_str()).join(url)
        }
    };

    let path_str = request_path.clone().into_os_string().into_string().unwrap();
    if path_str.len() > 256 {
        log_request(Status::NOT_FOUND, request.url().path().as_bytes());
        return Response::builder(Status::NOT_FOUND).with_body("404: Not found.");
    }

    if path_str.find("..").is_some() {
        log_request(Status::NOT_FOUND, request.url().path().as_bytes());
        return Response::builder(Status::NOT_FOUND).with_body("404: Not found.");
    }

    if path_str.as_str().ends_with(".jpg") {
        if let Some(bytes) = get_img_file(request_path.clone()) {
            log_request(Status::OK, request.url().path().as_bytes());
            return Response::builder(Status::OK)
                .with_header("Content-type", "image/jpeg")
                .unwrap()
                .with_header("Content-Length", format!("{}", bytes.len()))
                .unwrap()
                .with_body(bytes);
        }
    }

    if path_str.as_str().ends_with(".png") {
        if let Some(bytes) = get_img_file(request_path.clone()) {
            log_request(Status::OK, request.url().path().as_bytes());
            return Response::builder(Status::OK)
                .with_header("Content-type", "image/png")
                .unwrap()
                .with_header("Content-Length", format!("{}", bytes.len()))
                .unwrap()
                .with_body(bytes);
        }
    }
    if let Some(text) = get_txt_file(request_path.clone()) {
        log_request(Status::OK, request.url().path().as_bytes());
        return Response::builder(Status::OK).with_body(text);
    }

    log_request(Status::NOT_FOUND, request.url().path().as_bytes());
    return Response::builder(Status::NOT_FOUND).with_body("404: Not found.");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prog = std::path::Path::new(args[0].as_str())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();

    let prog_copy = prog.to_owned();

    if args.len() != 3 {
        eprintln!("Usage: {} host:port www-dir", prog);
        std::process::exit(-1);
    }

    std::thread::spawn(move || input_listener(prog_copy));

    let url = &args[1];
    match std::fs::read_dir(Path::new(&args[2])) {
        Ok(_) => {
            *ROOT_DIR.lock().unwrap() = args[2].clone();
        }
        Err(_) => {
            eprintln!("Directory '{}' not found.", &args[2]);
            std::process::exit(-1);
        }
    }

    println!("Serving HTTP on {}. Press Ctrl+C to exit.", url);

    #[cfg(target_os = "moturus")]
    let server_name = "motor-os httpd";
    #[cfg(not(target_os = "moturus"))]
    let server_name = prog;

    let result = Server::new(serve)
        .with_global_timeout(Duration::from_secs(10))
        .with_server_name(server_name)
        .unwrap()
        .listen(url.as_str());

    if result.is_err() {
        eprintln!("listen() failed.");
    }
}
