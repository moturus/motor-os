fn test_stdio_pipe_basic() {
    use moto_sys::syscalls::*;
    std::thread::sleep(std::time::Duration::from_millis(1000));

    let (d1, d2) = moto_ipc::stdio_pipe::make_pair(SysHandle::SELF, SysHandle::SELF).unwrap();

    let mut reader = unsafe { moto_ipc::stdio_pipe::Reader::new(d1) };
    let mut writer = unsafe { moto_ipc::stdio_pipe::Writer::new(d2) };

    let reader_thread = std::thread::spawn(move || {
        let mut step = 1_usize;
        loop {
            let mut buf: Vec<u8> = vec![0; step % 8176 + 17];

            let read = reader.read(buf.as_mut_slice()).unwrap();
            assert!(read > 0);
            if buf[read - 1] == 0 {
                break;
            }

            step += 1;
        }

        reader.total_read()
    });

    let writer_thread = std::thread::spawn(move || {
        for step in 1_usize..8000_usize {
            let mut buf = vec![];

            for _idx in 0..step {
                buf.push(7_u8);
            }
            assert_eq!(writer.write(buf.as_slice()).unwrap(), step);
        }

        assert_eq!(1, writer.write(&[0_u8; 1]).unwrap());
        writer.total_written()
    });

    let read = reader_thread.join().unwrap();
    let written = writer_thread.join().unwrap();

    assert_eq!(read, written);

    println!("test_stdio_pipe_basic PASS");
}

pub fn run_all_tests() {
    test_stdio_pipe_basic();
}
