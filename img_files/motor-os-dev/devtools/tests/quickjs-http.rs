use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for _ in 0..6 {
        let (mut stream, _) = listener.accept()?;
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
        let mut header_bytes = line.len();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 || line == "\r\n" {
                break;
            }
            header_bytes += line.len();
            assert!(header_bytes < 16 * 1024);
        }
        let (status, body) = match path.as_str() {
            "/binary" => ("200 OK", vec![0, 127, 128, 255]),
            "/missing" => ("404 Not Found", b"missing".to_vec()),
            "/large" => ("200 OK", vec![b'x'; 64 * 1024]),
            _ => ("200 OK", b"Motor QuickJS\n".to_vec()),
        };
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nX-QJS: local\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        stream.write_all(&response)?;
    }
    Ok(())
}
