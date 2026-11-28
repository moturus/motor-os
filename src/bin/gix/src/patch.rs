/// The type bits of a mode: a regular file, a link, or a submodule.
pub fn kind(mode: u32) -> u32 {
    mode & 0o170000
}
