use std::cell::Cell;
use std::future::Future;
use std::io;
use std::pin::{pin, Pin};
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::process::Command;
use tokio::runtime::Runtime;
use tokio::time::Instant;
use tokio_test::assert_ok;

// Observe the pipes below BufReader/BufWriter: accepting bytes into a local
// buffer must not keep a stalled child alive.
struct ProgressIo<T> {
    inner: T,
    last_progress: Rc<Cell<Instant>>,
}

impl<T> ProgressIo<T> {
    fn new(inner: T, last_progress: &Rc<Cell<Instant>>) -> Self {
        Self {
            inner,
            last_progress: last_progress.clone(),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ProgressIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.last_progress.set(Instant::now());
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ProgressIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            this.last_progress.set(Instant::now());
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn timeout_on_stall<F: Future>(
    idle: Duration,
    last_progress: &Cell<Instant>,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    let mut future = pin!(future);
    loop {
        let observed = last_progress.get();
        match tokio::time::timeout_at(observed + idle, future.as_mut()).await {
            Err(_) if last_progress.get() > observed => continue,
            result => return result,
        }
    }
}

async fn progress_timeout_test() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};

    // Expired deadlines exercise the watchdog without sleeping or depending
    // on how quickly this test gets scheduled.
    let expired = Instant::now() - Duration::from_millis(1);
    let last_progress = Rc::new(Cell::new(expired));
    assert!(
        timeout_on_stall(Duration::ZERO, &last_progress, std::future::pending::<()>())
            .await
            .is_err()
    );

    let (input, output) = tokio::io::duplex(64);
    let mut writer = ProgressIo::new(output, &last_progress);
    let mut reader = ProgressIo::new(input, &last_progress);
    timeout_on_stall(Duration::ZERO, &last_progress, async {
        writer.write_all(b"x").await.unwrap();
        tokio::task::yield_now().await;
    })
    .await
    .unwrap();
    last_progress.set(expired);
    timeout_on_stall(Duration::ZERO, &last_progress, async {
        assert_eq!(reader.read_u8().await.unwrap(), b'x');
        tokio::task::yield_now().await;
    })
    .await
    .unwrap();

    last_progress.set(expired);
    let mut buffered = BufWriter::new(writer);
    assert!(timeout_on_stall(Duration::ZERO, &last_progress, async {
        buffered.write_all(b"x").await.unwrap();
        tokio::task::yield_now().await;
    })
    .await
    .is_err());
    assert_eq!(last_progress.get(), expired);
    println!("process::progress_timeout_test PASS");
}

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
    rt.block_on(progress_timeout_test());
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("stdio-echo")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let last_progress = Rc::new(Cell::new(Instant::now()));
    let mut writer = BufWriter::new(ProgressIo::new(child.stdin.take().unwrap(), &last_progress));
    let mut reader = BufReader::new(ProgressIo::new(
        child.stdout.take().unwrap(),
        &last_progress,
    ));
    let mut stderr = ProgressIo::new(child.stderr.take().unwrap(), &last_progress);

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
    // Bound a lack of progress, not the scheduling cost of transferring every
    // frame. Spurious polls and buffered writes do not reset this deadline.
    timeout_on_stall(Duration::from_secs(5), &last_progress, exchange)
        .await
        .expect("framed child stdio exchange stalled");
    println!("process::framed_stdio_test PASS");
}
