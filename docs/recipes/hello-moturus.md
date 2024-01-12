# Hello Motūrus

In this example, we will compile and run the final project
([a multithreaded web server](https://doc.rust-lang.org/book/ch20-00-final-project-a-web-server.html))
from [Rust Book](https://doc.rust-lang.org/book/title-page.html) inside a Motūrus VM, with minor changes.

First, make sure that you can [build and run Motūrus OS](https://github.com/moturus/motor-os/blob/main/docs/build.md).

Then run

```
$ cd ~
$ cargo new hello
     Created binary (application) `hello` project
$ cd hello
```

Replace ```src.main.rs``` with this:

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

The port is changed because our ```vm_images/release/run-qemu-full.sh``` script
forwards port 5542 from inside the VM to the host port 10023. The address is
changed because we would like to bind the listener not only to the loopback
address, but also to the IP address that Qemu assigns to the VM.

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

Now build the web server for Motūrus OS:

```
cargo +dev-x86_64-unknown-moturus build --release \
  --target x86_64-unknown-moturus
```

Now add the web server to the Motūrus OS image:

```
mkdir $MOTORH/img_files/full/hello

cp ./target/x86_64-unknown-moturus/release/hello \
    $MOTORH/img_files/full/hello/

```

Now add the following two files to the ```$MOTORH/img_files/full/hello```:

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
    <p>Hi from Motūrus OS</p>
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

Now build a new Motūrus OS VM image:

```
cd $MOTORH
cargo make boot_img_release
```

Run Motūrus OS:

```
$ cd $MOTORH/motor-os/vm_images/release
$ ./run-qemu-web.sh
```

Inside Motūrus OS shell:

```
rush /$: cd hello
rush /hello$: hello
```

This will start the hello web server. On your host/desktop, navigate to
http://localhost:10023, you should see the hello.html from above.