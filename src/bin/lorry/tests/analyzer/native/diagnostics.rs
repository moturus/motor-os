use std::io;
use std::path::Path;

pub(super) fn validate(stderr: &str, roots: &[&Path], lorry: &Path) -> io::Result<()> {
    // Exact argv coverage belongs to the wrapper contract. Native acceptance
    // checks semantic results and discovery failures without additional tracing.
    let lorry = format!("{lorry:?}");
    for line in stderr.lines() {
        if line.contains(" ERROR ")
            || (line.contains(" WARN ")
                && !(line.contains("Failed to parse `")
                    && line.contains(&lorry)
                    && line.contains("as a semver version")))
        {
            return Err(io::Error::other(format!(
                "unexpected native analyzer diagnostic: {line}"
            )));
        }
    }
    for root in roots {
        let prefix = format!(
            "{}/generated-dependency/Cargo.toml: BuildScriptOutput",
            root.display()
        );
        let out = format!("{}/target/rust-analyzer/lorry/", root.display());
        if !stderr.lines().any(|line| {
            line.contains(&prefix)
                && line.contains("cfgs: [Flag(\"generated_fixture\")]")
                && line.contains("\"GENERATED_ENV\": \"from-build-script\"")
                && line.contains(&out)
        }) {
            return Err(io::Error::other(format!(
                "missing native build-script data for {}",
                root.display()
            )));
        }
    }
    Ok(())
}
