#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    None,
    R,
    Rw,
    Rx,
    Rwx,
}

impl Access {
    pub const fn bits(self) -> u8 {
        match self {
            Self::None => 0,
            Self::R => 0b100,
            Self::Rw => 0b110,
            Self::Rx => 0b101,
            Self::Rwx => 0b111,
        }
    }

    pub fn from_posix(bits: u8, directory: bool) -> Self {
        let bits = bits & 0b111;
        if bits & 0b100 == 0 {
            return Self::None;
        }
        match (bits & 0b010 != 0, bits & 0b001 != 0) {
            (false, false) => Self::R,
            (true, false) => Self::Rw,
            (false, true) => Self::Rx,
            (true, true) if directory => Self::Rwx,
            (true, true) => Self::Rx,
        }
    }

    pub fn intersect(self, other: Self, directory: bool) -> Self {
        Self::from_posix(self.bits() & other.bits(), directory)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalizedMode {
    pub owner: Access,
    pub public: Access,
}

impl NormalizedMode {
    pub fn from_posix(mode: u32, directory: bool) -> Self {
        let owner = Access::from_posix(((mode >> 6) & 7) as u8, directory);
        let public = Access::from_posix((mode & 7) as u8, directory).intersect(owner, directory);
        Self { owner, public }
    }

    pub fn reported_posix(self) -> u32 {
        let owner = u32::from(self.owner.bits());
        let public = u32::from(self.public.bits());
        owner << 6 | public << 3 | public
    }
}

pub fn unix_mode(mode: u32) -> u32 {
    mode & 0o777
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_posix_triplet_normalizes_to_a_motor_access() {
        let files = [
            Access::None,
            Access::None,
            Access::None,
            Access::None,
            Access::R,
            Access::Rx,
            Access::Rw,
            Access::Rx,
        ];
        let directories = [
            Access::None,
            Access::None,
            Access::None,
            Access::None,
            Access::R,
            Access::Rx,
            Access::Rw,
            Access::Rwx,
        ];
        for bits in 0..8 {
            assert_eq!(Access::from_posix(bits, false), files[bits as usize]);
            assert_eq!(Access::from_posix(bits, true), directories[bits as usize]);
        }
    }

    #[test]
    fn public_access_cannot_exceed_owner() {
        let mode = NormalizedMode::from_posix(0o407, false);
        assert_eq!(mode.owner, Access::R);
        assert_eq!(mode.public, Access::R);

        let mode = NormalizedMode::from_posix(0o604, false);
        assert_eq!(mode.owner, Access::Rw);
        assert_eq!(mode.public, Access::R);

        let mode = NormalizedMode::from_posix(0o077, true);
        assert_eq!(mode.owner, Access::None);
        assert_eq!(mode.public, Access::None);
    }

    #[test]
    fn representative_sftp_modes_match_the_design() {
        let cases = [
            (0o600, false, 0o600),
            (0o644, false, 0o644),
            (0o700, false, 0o500),
            (0o755, false, 0o555),
            (0o400, false, 0o400),
            (0o700, true, 0o700),
            (0o755, true, 0o755),
        ];
        for (input, directory, output) in cases {
            assert_eq!(
                NormalizedMode::from_posix(input, directory).reported_posix(),
                output
            );
        }
    }

    #[test]
    fn unix_modes_keep_all_posix_classes() {
        assert_eq!(unix_mode(0o100600), 0o600);
        assert_eq!(unix_mode(0o40755), 0o755);
    }
}
