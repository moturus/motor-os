# Hello Motor OS

In this example, we will compile and run the final project
([a multithreaded web server](https://doc.rust-lang.org/book/ch20-00-final-project-a-web-server.html))
from [Rust Book](https://doc.rust-lang.org/book/title-page.html) inside a Motor VM, with minor changes.

First, make sure that you can [build and run Motor OS](https://github.com/moturus/motor-os/blob/main/docs/build.md).

Create the example below the Motor OS checkout so the repository's exact
toolchain selector applies:

```sh
cd "$MOTORH/motor-os"
mkdir -p build/examples
cargo new build/examples/hello
cd build/examples/hello
```

Replace ```src/main.rs``` with this:

```Rust
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
```

This code is the same as in Rust Book, with a single change: instead of
```TcpListener::bind("127.0.0.1:7878")``` we call ```TcpListener::bind("0.0.0.0:5542")```.

The address is changed because the host connects to the VM's TAP address, not
to the guest loopback interface.

Then create ```src/lib.rs```:

```Rust
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
```

This code is exactly the same as in Rust Book.

Now build the web server for Motor OS:

```sh
cargo build --release \
  --target x86_64-unknown-motor
```

Create the following two files in the project directory.

Filename: ```hello.html```:

```html
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
```

Filename: ```404.html```:

```html
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
```

Boot the already-built standard image in one terminal:

```sh
cd "$MOTORH/motor-os/vm_images/release"
./run-qemu.sh
```

In another terminal, upload the executable and its data files:

```sh
cd "$MOTORH/motor-os"
SSH_KEY=src/tests/test.key
ssh -p 2222 -o IdentitiesOnly=yes -i "$SSH_KEY" \
  motor@192.168.4.2 /system/bin/mkdir /user/tmp/hello
scp -P 2222 -o IdentitiesOnly=yes -i "$SSH_KEY" \
  build/examples/hello/target/x86_64-unknown-motor/release/hello \
  build/examples/hello/hello.html \
  build/examples/hello/404.html \
  motor@192.168.4.2:/user/tmp/hello/
ssh -p 2222 -o IdentitiesOnly=yes -i "$SSH_KEY" \
  motor@192.168.4.2 /system/bin/chmod 755 /user/tmp/hello/hello
```

Start the server through SSH or from a Motor shell:

```sh
ssh -p 2222 -o IdentitiesOnly=yes -i "$SSH_KEY" \
  motor@192.168.4.2 \
  /system/bin/rush -c 'cd /user/tmp/hello && ./hello'
```

On the host, open `http://192.168.4.2:5542/`. The server accepts two requests
and then exits, as specified by the example's `.take(2)` loop.
