use std::path::PathBuf;

fn temp_dir() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("systest");
    path
}

fn create_dir_with_children(root: &std::path::Path, depth: u8) {
    assert!(!std::fs::exists(root).unwrap());
    std::fs::create_dir_all(root).unwrap();
    assert!(std::fs::exists(root).unwrap());
    let stats = std::fs::metadata(root).unwrap();
    assert!(stats.is_dir());

    if depth == 0 {
        return;
    }

    for i in 0..2 {
        let mut child = root.to_owned();
        child.push(format!("child 1.{i}"));
        create_dir_with_children(&child, depth - 1);

        std::fs::create_dir(PathBuf::from(root).join(format!("child 2.{i}"))).unwrap();
        std::fs::write(
            PathBuf::from(root).join(format!("file_{i}")),
            b"foo bar baz",
        )
        .unwrap();
    }
}

fn remove_dir_all_test() {
    let root = temp_dir();
    let _ = std::fs::remove_dir_all(&root);

    create_dir_with_children(&root, 2);

    assert!(std::fs::exists(&root).unwrap());
    let stats = std::fs::metadata(&root).unwrap();
    assert!(stats.is_dir());
    std::fs::remove_dir_all(&root).unwrap();

    assert!(!std::fs::exists(&root).unwrap());

    println!("    ---- FS: remove_dir_all_test PASS");
}

pub fn smoke_test() {
    if std::fs::metadata("/foo").is_ok() {
        std::fs::remove_file("/foo").unwrap();
    }
    if std::fs::metadata("/bar").is_ok() {
        std::fs::remove_file("/bar").unwrap();
    }

    assert_eq!(
        std::fs::metadata("/foo").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata("/bar").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::write("/foo", "bar").expect("async write failed");
    let bytes = std::fs::read("/foo").expect("async read failed");
    assert_eq!(bytes.as_slice(), "bar".as_bytes());

    let mut bytes = vec![0_u8; 1024 * 1024 * 11 + 1001];
    // let mut bytes = vec![0_u8; 1024 * 1024 * 2 + 1001];
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    let ts0 = std::time::Instant::now();
    std::fs::write("/bar", bytes.as_slice()).unwrap();
    let ts1 = std::time::Instant::now();
    let bytes_back = std::fs::read("/bar").unwrap();
    let dur_read = ts1.elapsed();
    let dur_write = ts1 - ts0;

    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(bytes_back.as_slice())
    );

    let write_mbps = (bytes.len() as f64) / dur_write.as_secs_f64() / (1024.0 * 1024.0);
    let read_mbps = (bytes.len() as f64) / dur_read.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "async FS smoke test: write {:.3} mbps; read: {:.3} mbps",
        write_mbps, read_mbps
    );

    let metadata = std::fs::metadata("/bar").unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), bytes.len() as u64);

    std::fs::remove_file("/foo").unwrap();
    std::fs::remove_file("/bar").unwrap();

    assert_eq!(
        std::fs::metadata("/foo").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(
        std::fs::metadata("/bar").err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    println!("    ---- FS: smoke_test PASS");
}

pub fn run_tests() {
    println!("running FS tests ...");
    smoke_test();
    remove_dir_all_test();
    println!("FS tests PASS");
}
