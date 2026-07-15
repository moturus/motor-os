//! Shell options (Phase 6): the `set -o` / `set -x` / invocation flag set.
//!
//! One table ([`SPECS`]) is the single source of truth for every option: its
//! `set` letter (if it has one), its `-o` long name (if it has one), and whether
//! the executor enforces it. The [`Options`] struct is a plain bitset over
//! [`Opt`], so the executor's hot paths are a bounds-checked array read.
//!
//! Enforcement lives with the feature it gates, not here:
//! `-e`/`-x`/`-n`/`-C`/`-o pipefail`/`-a` in [`crate::exec`], `-f`/`-u` in
//! [`crate::expand`], `-v` in the input readers ([`crate::lib`]/`exec`).
//!
//! Divergences from dash, deliberate and documented:
//! - **`-o pipefail`** exists here (POSIX.1-2024 added it; dash rejects it).
//! - **`-h`** is accepted as a no-op (POSIX reserves the letter for command
//!   hashing, which rush does not do); dash rejects `-h` outright.
//! - **`$-` letter order** is this table's canonical order rather than dash's
//!   internal one (`set -efu` → `efu` here, `ufe` in dash). POSIX leaves the
//!   order unspecified.
//! - dash's non-POSIX `emacs`/`vi`/`debug`/`privileged` options are omitted;
//!   `vi` is kept (POSIX names it) as an accepted no-op.

/// A shell option. The discriminant indexes [`Options::flags`], so the variants
/// and [`SPECS`] must stay in sync (asserted by a unit test).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Opt {
    AllExport = 0,
    Notify,
    NoClobber,
    ErrExit,
    NoGlob,
    HashAll,
    Interactive,
    Monitor,
    NoExec,
    Stdin,
    NoUnset,
    Verbose,
    XTrace,
    IgnoreEof,
    NoLog,
    Vi,
    PipeFail,
}

/// How faithfully rush implements an option — surfaced only in this module's
/// docs and the plan, but recorded here so the table stays honest.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Support {
    /// The executor enforces it.
    Live,
    /// Accepted and reported in `$-`/`set -o`, but nothing acts on it (the
    /// platform or rush's design makes it meaningless).
    Accepted,
}

pub struct Spec {
    pub opt: Opt,
    /// The `set -X` / invocation letter, if the option has one.
    pub letter: Option<char>,
    /// The `set -o name` long name. Every POSIX option has one.
    pub name: &'static str,
    /// Read only by this module's honesty test; kept in the table so the
    /// support level lives next to the option it describes.
    #[cfg_attr(not(test), allow(dead_code))]
    support: Support,
}

use Support::{Accepted, Live};

/// Every option, in the canonical order used by `$-`, `set -o`, and `set +o`.
pub const SPECS: &[Spec] = &[
    Spec { opt: Opt::AllExport,   letter: Some('a'), name: "allexport",   support: Live },
    Spec { opt: Opt::Notify,      letter: Some('b'), name: "notify",      support: Accepted },
    Spec { opt: Opt::NoClobber,   letter: Some('C'), name: "noclobber",   support: Live },
    Spec { opt: Opt::ErrExit,     letter: Some('e'), name: "errexit",     support: Live },
    Spec { opt: Opt::NoGlob,      letter: Some('f'), name: "noglob",      support: Live },
    Spec { opt: Opt::HashAll,     letter: Some('h'), name: "hashall",     support: Accepted },
    Spec { opt: Opt::Interactive, letter: Some('i'), name: "interactive", support: Live },
    Spec { opt: Opt::Monitor,     letter: Some('m'), name: "monitor",     support: Accepted },
    Spec { opt: Opt::NoExec,      letter: Some('n'), name: "noexec",      support: Live },
    Spec { opt: Opt::Stdin,       letter: Some('s'), name: "stdin",       support: Live },
    Spec { opt: Opt::NoUnset,     letter: Some('u'), name: "nounset",     support: Live },
    Spec { opt: Opt::Verbose,     letter: Some('v'), name: "verbose",     support: Live },
    Spec { opt: Opt::XTrace,      letter: Some('x'), name: "xtrace",      support: Live },
    Spec { opt: Opt::IgnoreEof,   letter: None,      name: "ignoreeof",   support: Accepted },
    Spec { opt: Opt::NoLog,       letter: None,      name: "nolog",       support: Accepted },
    Spec { opt: Opt::Vi,          letter: None,      name: "vi",          support: Accepted },
    Spec { opt: Opt::PipeFail,    letter: None,      name: "pipefail",    support: Live },
];

const N_OPTS: usize = SPECS.len();

#[derive(Clone, Copy)]
pub struct Options {
    flags: [bool; N_OPTS],
}

impl Options {
    pub fn new() -> Self {
        Self {
            flags: [false; N_OPTS],
        }
    }

    /// `get`/`set` run on every command (`-n`, `-x`) and every word (`-f`), so
    /// they index by discriminant rather than searching [`SPECS`]. The
    /// discriminant-equals-position invariant is asserted below.
    pub fn get(&self, opt: Opt) -> bool {
        self.flags[opt as usize]
    }

    pub fn set(&mut self, opt: Opt, on: bool) {
        self.flags[opt as usize] = on;
    }

    pub fn by_letter(letter: char) -> Option<Opt> {
        SPECS
            .iter()
            .find(|s| s.letter == Some(letter))
            .map(|s| s.opt)
    }

    pub fn by_name(name: &str) -> Option<Opt> {
        SPECS.iter().find(|s| s.name == name).map(|s| s.opt)
    }

    /// Whether the option is accepted for compatibility but not acted on. Only
    /// the module's own honesty test consults this; it exists so the table, not
    /// a doc comment, is the source of truth for what rush enforces.
    #[cfg(test)]
    fn is_accepted_only(opt: Opt) -> bool {
        SPECS
            .iter()
            .any(|s| s.opt == opt && s.support == Accepted)
    }

    /// `$-`: the letters of the currently-enabled options that have one.
    pub fn dash_flags(&self) -> String {
        SPECS
            .iter()
            .filter(|s| self.get(s.opt))
            .filter_map(|s| s.letter)
            .collect()
    }

    /// The `set -o` listing: `name<pad>on|off` lines (dash's format).
    pub fn listing(&self) -> Vec<String> {
        SPECS
            .iter()
            .map(|s| {
                let state = if self.get(s.opt) { "on" } else { "off" };
                format!("{:<16}{state}", s.name)
            })
            .collect()
    }

    /// The `set +o` listing: re-inputtable `set -o name` / `set +o name` lines.
    pub fn listing_reinput(&self) -> Vec<String> {
        SPECS
            .iter()
            .map(|s| {
                let sign = if self.get(s.opt) { '-' } else { '+' };
                format!("set {sign}o {}", s.name)
            })
            .collect()
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_are_in_opt_discriminant_order() {
        // The invariant `get`/`set` index on: SPECS[i].opt as usize == i. Adding
        // an `Opt` variant without its spec (or out of order) would silently
        // read the wrong option's flag, so assert it rather than trust it.
        for (i, spec) in SPECS.iter().enumerate() {
            assert_eq!(spec.opt as usize, i, "{} is out of order in SPECS", spec.name);
        }
        // …and that `flags` is exactly as wide as the table.
        assert_eq!(N_OPTS, SPECS.len());
    }

    #[test]
    fn letters_and_names_are_unique() {
        for (i, a) in SPECS.iter().enumerate() {
            for b in &SPECS[i + 1..] {
                assert_ne!(a.name, b.name);
                if a.letter.is_some() {
                    assert_ne!(a.letter, b.letter, "duplicate letter in {}", a.name);
                }
            }
        }
    }

    #[test]
    fn accepted_but_unenforced_options_are_exactly_the_documented_set() {
        // These are inert by design: rush hashes nothing (`hashall`), has no job
        // control or line-editing modes to switch (`monitor`, `notify`, `vi`),
        // keeps no history to elide (`nolog`), and its `^D` handling is Phase 8
        // (`ignoreeof`). Anything else claiming `Accepted` is an unfinished
        // option, and anything here that gains real behavior must move to `Live`.
        let expected = [
            Opt::HashAll,
            Opt::Monitor,
            Opt::Notify,
            Opt::Vi,
            Opt::NoLog,
            Opt::IgnoreEof,
        ];
        for spec in SPECS {
            assert_eq!(
                Options::is_accepted_only(spec.opt),
                expected.contains(&spec.opt),
                "{} changed support level without updating this list",
                spec.name
            );
        }
    }

    #[test]
    fn lookup_round_trips() {
        assert_eq!(Options::by_letter('e'), Some(Opt::ErrExit));
        assert_eq!(Options::by_name("errexit"), Some(Opt::ErrExit));
        assert_eq!(Options::by_letter('z'), None);
        assert_eq!(Options::by_name("bogus"), None);
        // `pipefail` is name-only: no letter, so it never shows in `$-`.
        assert_eq!(Options::by_letter('p'), None);
    }

    #[test]
    fn dash_flags_are_canonically_ordered() {
        let mut o = Options::new();
        assert_eq!(o.dash_flags(), "");
        o.set(Opt::NoUnset, true);
        o.set(Opt::ErrExit, true);
        o.set(Opt::NoGlob, true);
        // Table order, not the order they were set in (dash prints "ufe").
        assert_eq!(o.dash_flags(), "efu");
        o.set(Opt::PipeFail, true);
        assert_eq!(o.dash_flags(), "efu", "a letterless option stays out of $-");
        o.set(Opt::NoGlob, false);
        assert_eq!(o.dash_flags(), "eu");
    }

    #[test]
    fn listings_cover_every_option() {
        let mut o = Options::new();
        o.set(Opt::ErrExit, true);
        assert_eq!(o.listing().len(), SPECS.len());
        assert!(o.listing().contains(&"errexit         on".to_string()));
        assert!(o.listing().contains(&"noglob          off".to_string()));
        assert!(
            o.listing_reinput()
                .contains(&"set -o errexit".to_string())
        );
        assert!(o.listing_reinput().contains(&"set +o noglob".to_string()));
    }
}
