fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(arguments, ["first", "two words"]);
    println!("{}", lorry_native_fixture::value());
}

#[cfg(test)]
mod tests {
    #[test]
    fn binary_unit_links_the_library() {
        assert_eq!(
            lorry_native_fixture::value(),
            "registry|build-script|motor-target"
        );
    }
}
