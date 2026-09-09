pub fn run_tests() {
    virtio_async::test_descriptor_waiters();
    for kind in ["block", "network"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("test-virtio-premature-drop")
            .arg(kind)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr
                .contains("virtio completion dropped while the device still owns its DMA buffers"),
            "unexpected premature-drop failure: {stderr}"
        );
    }
    println!("virtio descriptor tests PASS");
}
