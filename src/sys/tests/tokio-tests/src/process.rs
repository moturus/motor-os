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
    } else if cfg!(target_os = "moturus") {
        cmd = Command::new("rush");
        cmd.arg("-c");
    } else {
        cmd = Command::new("sh");
        cmd.arg("-c");
    }

    #[cfg(not(target_os = "moturus"))]
    let mut child = cmd.arg("exit 2").spawn().unwrap();

    #[cfg(target_os = "moturus")]
    let mut child = cmd.arg("exit").arg("2").spawn().unwrap();

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

pub fn run_all_tests() {
    let rt = rt();
    rt.block_on(smoke_test());

    println!("process PASS");
}
