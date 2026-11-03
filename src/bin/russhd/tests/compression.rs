use russh::compression::{Compress, Compression, Decompress};

#[test]
fn partial_flush_packets_are_drained_before_the_next_packet() {
    let mut compressor = Compress::None;
    let mut decompressor = Decompress::None;
    Compression::Zlib.init_compress(&mut compressor);
    Compression::Zlib.init_decompress(&mut decompressor);

    // A continuous SSH stream with changing packet sizes exercises buffered
    // output at packet boundaries, including the miniz_oxide 0.9 regression.
    for len in 1..=4096 {
        let payload: Vec<_> = (0..len).map(|i| b"abcdefgh"[i % 8]).collect();
        let mut compressed = vec![0xa5; 4];
        let written = compressor
            .compress_into(&payload, &mut compressed, 4)
            .unwrap();
        assert_eq!(&compressed[..4], &[0xa5; 4]);
        assert_eq!(compressed.len(), written + 4);

        let mut output = Vec::new();
        assert_eq!(
            decompressor
                .decompress(&compressed[4..], &mut output)
                .unwrap(),
            payload,
            "packet of {len} bytes was truncated"
        );
        assert!(
            decompressor
                .decompress(&[], &mut output)
                .unwrap()
                .is_empty(),
            "packet of {len} bytes left decoded output buffered"
        );
    }
}
