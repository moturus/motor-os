use oxhttp::model::{Request, Response, Status};
use oxhttp::Server;
use std::path::Path;
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

fn serve(request: &mut Request) -> Response {
    if request.method().as_bytes() != b"GET" {
        println!("\"{}\": 501", request.method());
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
                println!("\"GET {}\": 404", request.url().path());
                return Response::builder(Status::NOT_FOUND).with_body("404: Not found.");
            }
            Path::new(root.as_str()).join(url)
        }
    };

    let path_str = request_path.clone().into_os_string().into_string().unwrap();
    if path_str.find("..").is_some() {
        println!("\"GET {}\": 404", request.url().path());
        return Response::builder(Status::NOT_FOUND).with_body("404: Not found.");
    }

    if let Ok(text) = std::fs::read_to_string(request_path.clone()) {
        println!("\"GET {}\": 200", request.url().path());
        return Response::builder(Status::OK).with_body(text);
    }

    if path_str.as_str().ends_with(".jpg") {
        if let Ok(bytes) = std::fs::read(request_path.clone()) {
            println!("\"GET {}\": 200", request.url().path());
            return Response::builder(Status::OK)
                .with_header("Content-type", "image/jpeg")
                .unwrap()
                .with_header("Content-Length", format!("{}", bytes.len()))
                .unwrap()
                .with_body(bytes);
        }
    }

    if path_str.as_str().ends_with(".png") {
        if let Ok(bytes) = std::fs::read(request_path.clone()) {
            println!("\"GET {}\": 200", request.url().path());
            return Response::builder(Status::OK)
                .with_header("Content-type", "image/png")
                .unwrap()
                .with_header("Content-Length", format!("{}", bytes.len()))
                .unwrap()
                .with_body(bytes);
        }
    }

    println!("\"GET {}\": 404", request.url().path());
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

    std::thread::spawn(move || input_listener(prog_copy));

    if args.len() != 3 {
        eprintln!("Usage: {} host:port www-dir", prog);
        std::process::exit(-1);
    }

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

    let result = Server::new(serve)
        .with_global_timeout(Duration::from_secs(10))
        .with_server_name(prog)
        .unwrap()
        .listen(url.as_str());

    if result.is_err() {
        eprintln!("listen() failed.");
    }
}
