pub fn source() -> &'static str {
    file!()
}

pub fn features() -> (bool, bool) {
    (cfg!(feature = "red"), cfg!(feature = "blue"))
}
