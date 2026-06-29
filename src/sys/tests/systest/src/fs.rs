use std::{io::Seek, path::PathBuf};

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

fn copy_test() {
    let root = temp_dir();
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let src = root.join("copy_src");
    let dst = root.join("copy_dst");

    // Generate some random source data larger than a single block to exercise
    // the copy loop.
    const LEN: usize = 1024 * 1024 * 3 + 333;
    let mut bytes = Vec::with_capacity(LEN);
    bytes.resize(LEN, 0u8);
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    std::fs::write(&src, bytes.as_slice()).unwrap();

    // Copy to a fresh destination.
    let copied = std::fs::copy(&src, &dst).unwrap();
    assert_eq!(copied, LEN as u64);

    assert!(std::fs::exists(&dst).unwrap());
    let dst_meta = std::fs::metadata(&dst).unwrap();
    assert!(dst_meta.is_file());
    assert_eq!(dst_meta.len(), LEN as u64);

    let dst_bytes = std::fs::read(&dst).unwrap();
    assert_eq!(dst_bytes.len(), LEN);
    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(dst_bytes.as_slice())
    );

    // The source must be left untouched.
    let src_meta = std::fs::metadata(&src).unwrap();
    assert!(src_meta.is_file());
    assert_eq!(src_meta.len(), LEN as u64);

    // Copying over an existing file must truncate/overwrite it: first write a
    // smaller file at the destination, then copy a larger one over it.
    /*
    let small = b"small contents";
    std::fs::write(&dst, small).unwrap();
    assert_eq!(std::fs::metadata(&dst).unwrap().len(), small.len() as u64);

    let copied = std::fs::copy(&src, &dst).unwrap();
    assert_eq!(copied, LEN as u64);
    assert_eq!(std::fs::metadata(&dst).unwrap().len(), LEN as u64);
    let dst_bytes = std::fs::read(&dst).unwrap();
    assert_eq!(
        moto_rt::fnv1a_hash_64(bytes.as_slice()),
        moto_rt::fnv1a_hash_64(dst_bytes.as_slice())
    );
    */

    // Copying a non-existent source must fail with NotFound.
    let missing = root.join("does_not_exist");
    assert_eq!(
        std::fs::copy(&missing, &dst).err().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );

    // Copying an empty file must succeed and produce an empty file.
    let empty_src = root.join("empty_src");
    let empty_dst = root.join("empty_dst");
    std::fs::write(&empty_src, b"").unwrap();
    let copied = std::fs::copy(&empty_src, &empty_dst).unwrap();
    assert_eq!(copied, 0);
    assert_eq!(std::fs::metadata(&empty_dst).unwrap().len(), 0);

    std::fs::remove_dir_all(&root).unwrap();
    assert!(!std::fs::exists(&root).unwrap());

    println!("    ---- FS: copy_test PASS");
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

    const LEN: usize = 1024 * 1024 * 19 + 1001;

    let mut bytes = Vec::with_capacity(LEN);
    bytes.resize(LEN, 0);
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    let ts0 = std::time::Instant::now();
    std::fs::write("/bar", bytes.as_slice()).unwrap();
    let cpu_usage_write = crate::mpmc::get_cpu_usage();
    let ts1 = std::time::Instant::now();
    let bytes_back = std::fs::read("/bar").unwrap();
    let dur_read = ts1.elapsed();
    let cpu_usage_read = crate::mpmc::get_cpu_usage();
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

    print!("\tcpu usage writing: ");
    for n in &cpu_usage_write {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();
    print!("\tcpu usage reading: ");
    for n in &cpu_usage_read {
        print!("{: >5.1}% ", (*n) * 100.0);
    }
    println!();
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

fn resize_test() {
    println!("    ---- FS: resize_test starting...");
    const LEN: usize = 1024 * 1024 * 7 + 131;

    let mut bytes = Vec::with_capacity(LEN);
    bytes.resize(LEN, 0);
    for byte in &mut bytes {
        *byte = std::random::random(..);
    }

    std::fs::write("/baz", bytes.as_slice()).unwrap();
    let file = std::fs::File::open("/baz").unwrap();
    assert_eq!(file.metadata().unwrap().len(), LEN as u64);

    println!("    ---- FS: resize_test resizing...");
    file.set_len(8192 + 11).unwrap();

    drop(file);
    std::fs::remove_file("/baz").unwrap();
    println!("    ---- FS: resize_test PASS");
}

pub fn run_tests() {
    println!("running FS tests ...");
    smoke_test();
    copy_test();
    remove_dir_all_test();
    resize_test();

    println!("FS tests PASS");
}
