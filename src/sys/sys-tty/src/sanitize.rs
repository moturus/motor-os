const ESC_REPLACEMENT: &[u8] = b"[UNSAFE ASCII ESCAPE SEQUENCE DETECTED]";
const C1_REPLACEMENT: &[u8] = b"[UNSAFE C1 CONTROL CHARACTER DETECTED]";

pub(crate) fn for_console(record: &[u8]) -> Vec<u8> {
    let mut sanitized = Vec::with_capacity(record.len());
    let mut position = 0;
    while position < record.len() {
        if record[position] == 0x1b {
            sanitized.extend_from_slice(ESC_REPLACEMENT);
            position += 1;
        } else if position + 1 < record.len()
            && record[position] == 0xc2
            && (0x80..=0x9f).contains(&record[position + 1])
        {
            sanitized.extend_from_slice(C1_REPLACEMENT);
            position += 2;
        } else {
            sanitized.push(record[position]);
            position += 1;
        }
    }
    sanitized
}

pub(crate) fn run_self_tests() {
    for position in 0..=3 {
        let mut record = b"abc".to_vec();
        record.insert(position, 0x1b);
        let original = record.clone();

        let mut expected = b"abc".to_vec();
        expected.splice(position..position, ESC_REPLACEMENT.iter().copied());
        assert_eq!(for_console(&record), expected);
        assert_eq!(record, original);
    }

    for control in 0x80..=0x9f {
        let record = [b'x', 0xc2, control, b'y'];
        let mut expected = b"x".to_vec();
        expected.extend_from_slice(C1_REPLACEMENT);
        expected.push(b'y');
        let sanitized = for_console(&record);
        assert_eq!(sanitized, expected);
        assert!(
            !sanitized
                .windows(2)
                .any(|bytes| { bytes[0] == 0xc2 && (0x80..=0x9f).contains(&bytes[1]) })
        );
    }

    assert_eq!(
        for_console(b"\x1b\xc2\x9b"),
        [ESC_REPLACEMENT, C1_REPLACEMENT].concat()
    );
    assert_eq!(for_console(b"ordinary log"), b"ordinary log");

    println!("sys-tty sanitizer self-test PASS");
}
