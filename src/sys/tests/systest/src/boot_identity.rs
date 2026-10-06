pub fn run_tests() -> u64 {
    let expected = moto_sys::KernelStaticPage::get().boot_random_id;
    assert_ne!(expected, 0, "kernel did not initialize its boot identity");

    let readers: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(|| moto_sys::KernelStaticPage::get().boot_random_id))
        .collect();
    for reader in readers {
        assert_eq!(reader.join().unwrap(), expected);
    }

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("boot-random-id")
        .output()
        .unwrap();
    assert!(output.status.success());
    let actual =
        u64::from_str_radix(std::str::from_utf8(&output.stdout).unwrap().trim(), 16).unwrap();
    assert_eq!(
        actual, expected,
        "processes disagree on their boot identity"
    );
    println!("test_boot_identity PASS id={expected:016x}");
    expected
}
