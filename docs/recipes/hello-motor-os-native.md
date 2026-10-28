# Hello Motor OS, natively

Build and run the [Hello Motor OS](hello-motor-os.md) web server entirely
inside a Motor OS developer VM using Lorry.

You need the developer image, `motor-os-dev.qcow2`; see
[Building Motor OS](../build.md).

## Start the VM

Stop any other Motor OS VM before starting the developer image; the launch
scripts share a VM lock and network configuration. On the host, start from
the Motor OS checkout:

```sh
cd vm_images/release
./run-dev.sh
```

The terminal that runs `run-dev.sh` becomes the VM's console, with a `rush`
prompt. You can type the commands below there. Or open an SSH session from a
second host terminal, again starting from the Motor OS checkout:

```sh
cd vm_images/release
./ssh-into-motor-os-vm.sh
```

Either shell works for every step, including pasting the files.

## Create the project

In the VM:

```sh
cd /devtools/src
lorry new hello
cd hello
```

`/devtools/src` is the developer image's writable workspace. `lorry new`
writes `Cargo.toml`, `Cargo.lock`, and `src/main.rs`.

## The program

Paste each block below into the VM's shell. Each one is a here-document that
writes one file. The code is the one from Hello Motor OS: the Rust Book's
server, listening on `0.0.0.0:5542` instead of `127.0.0.1:7878`, so that the
host can reach it.

`src/main.rs`:

```sh
cat > src/main.rs <<'EOF'
use hello::ThreadPool;
use std::fs;
use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:5542").unwrap();
    let pool = ThreadPool::new(4);

    for stream in listener.incoming().take(2) {
        let stream = stream.unwrap();

        pool.execute(|| {
            handle_connection(stream);
        });
    }

    println!("Shutting down.");
}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    let get = b"GET / HTTP/1.1\r\n";
    let sleep = b"GET /sleep HTTP/1.1\r\n";

    let (status_line, filename) = if buffer.starts_with(get) {
        ("HTTP/1.1 200 OK", "hello.html")
    } else if buffer.starts_with(sleep) {
        thread::sleep(Duration::from_secs(5));
        ("HTTP/1.1 200 OK", "hello.html")
    } else {
        ("HTTP/1.1 404 NOT FOUND", "404.html")
    };

    let contents = fs::read_to_string(filename).unwrap();

    let response = format!(
        "{}\r\nContent-Length: {}\r\n\r\n{}",
        status_line,
        contents.len(),
        contents
    );

    stream.write_all(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}
EOF
```

`src/lib.rs`, exactly as in the Rust Book:

```sh
cat > src/lib.rs <<'EOF'
use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    /// Create a new ThreadPool.
    ///
    /// The size is the number of threads in the pool.
    ///
    /// # Panics
    ///
    /// The `new` function will panic if the size is zero.
    pub fn new(size: usize) -> ThreadPool {
        assert!(size > 0);

        let (sender, receiver) = mpsc::channel();

        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }

        ThreadPool {
            workers,
            sender: Some(sender),
        }
    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.as_ref().unwrap().send(job).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        drop(self.sender.take());

        for worker in &mut self.workers {
            println!("Shutting down worker {}", worker.id);

            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv();

            match message {
                Ok(job) => {
                    println!("Worker {id} got a job; executing.");

                    job();
                }
                Err(_) => {
                    println!("Worker {id} disconnected; shutting down.");
                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}
EOF
```

The two pages the server reads, next to `Cargo.toml`:

```sh
cat > hello.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Hello!</title>
  </head>
  <body>
    <h1>Hello!</h1>
    <p>Hi from Motor OS</p>
  </body>
</html>
EOF
```

```sh
cat > 404.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Hello!</title>
  </head>
  <body>
    <h1>Oops!</h1>
    <p>Sorry, I don't know what you're asking for.</p>
  </body>
</html>
EOF
```

## Build it

```sh
lorry build --release
```

The build is offline. This package has no dependencies, so there is nothing
to vendor. A package with dependencies needs one `lorry vendor`, with network
access, before its first build; see Lorry's
[README](../../src/bin/lorry/README.md). The program is
`target/lorry/release/hello`.

## Run it

```sh
lorry run --release
```

`lorry run` starts the program in the current directory, where its two pages
are. `./target/lorry/release/hello`, run from the same directory, does the
same.

On the host, open `http://192.168.4.2:5542/`, or fetch the page:

```sh
wget -qO- http://192.168.4.2:5542/
```

The page contains `Hi from Motor OS`.

As in the book, the server accepts two connections and then exits. A browser
may open more than one connection per page, so it can exit sooner than you
expect. Run `lorry run --release` again in the VM to restart it.
