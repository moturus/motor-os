//! Tools that cannot work on this platform, registered so they can say so.
//!
//! The step 9 lesson, generalized: a capability that is off should refuse and
//! name the reason rather than be absent. A model that cannot find a tool
//! cannot tell "not allowed" from "not a thing gears does", and improvises
//! with the tools it does have; a refusal costs one round.

use serde_json::{Value, json};

use super::{Tool, schema};
use crate::provider::ToolSpec;

struct UnsupportedTool {
    name: &'static str,
    why: &'static str,
}

/// A tool named `name` whose description and every call say `why` it cannot
/// work here.
pub fn tool(name: &'static str, why: &'static str) -> Box<dyn Tool> {
    Box::new(UnsupportedTool { name, why })
}

impl Tool for UnsupportedTool {
    fn name(&self) -> &'static str {
        self.name
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name,
            format!("Not available here: {}.", self.why),
            schema(json!({}), &[]),
        )
    }

    /// A tool that does nothing changes nothing — and must not cost the user
    /// a permission question on the way to refusing.
    fn mutates(&self) -> bool {
        false
    }

    fn call(&self, _args: &Value) -> Result<String, String> {
        Err(format!("unsupported: {}", self.why))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsupported_tool_refuses_and_says_why() {
        let tool = tool("git_status", "Motor OS v1 has no git");
        assert_eq!(tool.name(), "git_status");
        assert!(!tool.mutates());
        assert!(!tool.gated(&json!({})));
        assert!(tool.spec().function.description.contains("no git"));
        let err = tool.call(&json!({"paths": ["x"]})).unwrap_err();
        assert!(err.starts_with("unsupported:"), "{err}");
        assert!(err.contains("no git"), "{err}");
    }
}
