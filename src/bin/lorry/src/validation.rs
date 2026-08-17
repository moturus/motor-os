#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    Trusted,
    Strict,
}

impl ValidationMode {
    pub fn is_strict(self) -> bool {
        self == Self::Strict
    }
}
