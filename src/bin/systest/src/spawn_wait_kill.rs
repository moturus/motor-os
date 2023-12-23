use crate::subcommand;

pub fn test() {
    // Normal exit.
    let mut child = subcommand::spawn();
    let start = std::time::Instant::now();
    let spin_time = std::time::Duration::from_micros(10_000);
    child.spin(spin_time);

    assert!(child.try_wait().unwrap().is_none()); // Still running.

    child.do_exit(1234);
    assert_eq!(1234, child.wait().unwrap().code().unwrap());
    assert!(start.elapsed() > spin_time);

    // kill.
    let mut child = subcommand::spawn();
    assert!(child.try_wait().unwrap().is_none()); // Still running.
    child.kill();
    assert_eq!(-1, child.wait().unwrap().code().unwrap());

    println!("spawn_wait_kill test PASS");
}
