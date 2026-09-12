use tokio::process::Command;
use tokio::runtime::Runtime;
use tokio_test::assert_ok;

fn rt() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

async fn smoke_test() {
    let mut cmd;

    if cfg!(windows) {
        cmd = Command::new("cmd");
        cmd.arg("/c");
    } else {
        cmd = Command::new("sh");
        cmd.arg("-c");
    }

    let mut child = cmd.arg("exit 2").spawn().unwrap();

    let _id = child.id().expect("missing id");
    // assert!(id > 0);

    let status = assert_ok!(child.wait().await);
    assert_eq!(status.code(), Some(2));

    // test that the `.wait()` method is fused just like the stdlib
    let status = assert_ok!(child.wait().await);
    assert_eq!(status.code(), Some(2));

    // Can't get id after process has exited
    assert_eq!(child.id(), None);
    drop(child.kill());

    println!("process::smoke_test PASS");
}

async fn piped_stdio_test() {
    use std::process::Stdio;

    let mut cmd;

    if cfg!(windows) {
        cmd = Command::new("cmd");
        cmd.arg("/c");
    } else {
        cmd = Command::new("sh");
        cmd.arg("-c");
    }

    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.arg("exit 2").spawn().unwrap();

    let _id = child.id().expect("missing id");
    // assert!(id > 0);

    let status = assert_ok!(child.wait().await);
    assert_eq!(status.code(), Some(2));

    // test that the `.wait()` method is fused just like the stdlib
    let status = assert_ok!(child.wait().await);
    assert_eq!(status.code(), Some(2));

    // Can't get id after process has exited
    assert_eq!(child.id(), None);
    drop(child.kill());
    println!("process::piped_stdio_test PASS");
}

pub fn run_all_tests() {
    let rt = rt();
    rt.block_on(smoke_test());
    rt.block_on(piped_stdio_test());
    rt.block_on(framed_stdio_test());

    println!("process PASS");
}

// The helper reads complete requests before replying, like an LSP server.
// Keep all three streams open throughout the exchange: EOF cannot unblock it.
pub fn stdio_echo() {
    use std::io::{Read, Write};

    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    for expected_size in [16_u32, 8192, 65536] {
        let mut header = [0; 4];
        input.read_exact(&mut header).unwrap();
        assert_eq!(u32::from_le_bytes(header), expected_size);
        let mut body = vec![0; expected_size as usize];
        input.read_exact(&mut body).unwrap();
        output.write_all(&header).unwrap();
        output.write_all(&body).unwrap();
        output.flush().unwrap();
    }
    std::io::stderr()
        .write_all(b"stdio echo complete\n")
        .unwrap();
}

async fn framed_stdio_test() {
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("stdio-echo")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut writer = BufWriter::new(child.stdin.take().unwrap());
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut stderr = child.stderr.take().unwrap();

    let exchange = async {
        // The large frames force partial writes and reuse the same registered
        // descriptors after the reader has drained a full pipe.
        for size in [16_u32, 8192, 65536] {
            let payload: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
            writer.write_all(&size.to_le_bytes()).await.unwrap();
            writer.write_all(&payload).await.unwrap();
            writer.flush().await.unwrap();
            let mut header = [0; 4];
            reader.read_exact(&mut header).await.unwrap();
            assert_eq!(u32::from_le_bytes(header), size);
            let mut reply = vec![0; size as usize];
            reader.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, payload);
        }
        drop(writer);
        assert!(child.wait().await.unwrap().success());
        let mut tail = String::new();
        stderr.read_to_string(&mut tail).await.unwrap();
        assert_eq!(tail, "stdio echo complete\n");
    };
    tokio::time::timeout(Duration::from_secs(5), exchange)
        .await
        .expect("framed child stdio exchange stalled");
    println!("process::framed_stdio_test PASS");
}
