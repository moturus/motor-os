//! Code-owned workflow policy for the four P0 modes.

use super::task::Mode;

/// Increment when a reviewed profile changes its model-facing or enforcement
/// contract. Sessions retain their task mode; requests use this exact version.
pub const VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolPolicy {
    ReadOnly,
    PermissionGatedMutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPolicy {
    Explicit,
    DirectRequestOrApprovedPlan,
    ExplicitOrAfterCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    pub version: u32,
    pub name: &'static str,
    pub mode: Mode,
    pub tools: ToolPolicy,
    pub entry: EntryPolicy,
    pub prompt: &'static str,
}

const ASK: Profile = Profile {
    version: VERSION,
    name: "ask",
    mode: Mode::Ask,
    tools: ToolPolicy::ReadOnly,
    entry: EntryPolicy::Explicit,
    prompt: "Mode: ask. Answer the user's question using inspection when useful. Do not change the workspace. If the user asks for a plan or implementation, make that mode transition explicit.",
};

const PLAN: Profile = Profile {
    version: VERSION,
    name: "plan",
    mode: Mode::Plan,
    tools: ToolPolicy::ReadOnly,
    entry: EntryPolicy::Explicit,
    prompt: "Mode: plan. Inspect the repository and maintain a concrete task plan without changing the workspace. State unresolved decisions. Implementation requires an explicit transition to code.",
};

const CODE: Profile = Profile {
    version: VERSION,
    name: "code",
    mode: Mode::Code,
    tools: ToolPolicy::PermissionGatedMutation,
    entry: EntryPolicy::DirectRequestOrApprovedPlan,
    prompt: "Mode: code. Implement the active task and keep its durable state accurate. Prefer edit_file to replacing a whole file. The run tool executes an argument vector without a shell; prefer build and test to raw toolchain commands. Workspace mutations remain prepared and permission-gated. Verify the resulting work before claiming completion.",
};

const REVIEW: Profile = Profile {
    version: VERSION,
    name: "review",
    mode: Mode::Review,
    tools: ToolPolicy::ReadOnly,
    entry: EntryPolicy::ExplicitOrAfterCode,
    prompt: "Mode: review. Inspect the proposed or applied diff and recorded verification evidence without changing the workspace. Report findings clearly. Fixing a finding requires an explicit transition to code.",
};

pub const fn profile(mode: Mode) -> &'static Profile {
    match mode {
        Mode::Ask => &ASK,
        Mode::Plan => &PLAN,
        Mode::Code => &CODE,
        Mode::Review => &REVIEW,
    }
}

pub fn from_name(name: &str) -> Option<Mode> {
    [Mode::Ask, Mode::Plan, Mode::Code, Mode::Review]
        .into_iter()
        .find(|mode| profile(*mode).name == name)
}

impl ToolPolicy {
    pub const fn allows_mutation(self) -> bool {
        matches!(self, ToolPolicy::PermissionGatedMutation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_versioned_and_match_the_p0_policy() {
        let modes = [Mode::Ask, Mode::Plan, Mode::Code, Mode::Review];
        for mode in modes {
            let profile = profile(mode);
            assert_eq!(profile.version, VERSION);
            assert_eq!(profile.mode, mode);
            assert!(
                profile
                    .prompt
                    .starts_with(&format!("Mode: {}", profile.name))
            );
        }
        assert!(!profile(Mode::Ask).tools.allows_mutation());
        assert!(!profile(Mode::Plan).tools.allows_mutation());
        assert!(profile(Mode::Code).tools.allows_mutation());
        assert!(!profile(Mode::Review).tools.allows_mutation());
        assert_eq!(
            profile(Mode::Code).entry,
            EntryPolicy::DirectRequestOrApprovedPlan
        );
    }

    #[test]
    fn prompt_fragments_are_reviewable_fixtures() {
        assert_eq!(
            profile(Mode::Ask).prompt,
            "Mode: ask. Answer the user's question using inspection when useful. Do not change the workspace. If the user asks for a plan or implementation, make that mode transition explicit."
        );
        assert_eq!(
            profile(Mode::Plan).prompt,
            "Mode: plan. Inspect the repository and maintain a concrete task plan without changing the workspace. State unresolved decisions. Implementation requires an explicit transition to code."
        );
        assert_eq!(
            profile(Mode::Code).prompt,
            "Mode: code. Implement the active task and keep its durable state accurate. Prefer edit_file to replacing a whole file. The run tool executes an argument vector without a shell; prefer build and test to raw toolchain commands. Workspace mutations remain prepared and permission-gated. Verify the resulting work before claiming completion."
        );
        assert_eq!(
            profile(Mode::Review).prompt,
            "Mode: review. Inspect the proposed or applied diff and recorded verification evidence without changing the workspace. Report findings clearly. Fixing a finding requires an explicit transition to code."
        );
    }
}
