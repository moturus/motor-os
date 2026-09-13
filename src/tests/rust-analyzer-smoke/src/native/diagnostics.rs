use std::io;
use std::path::Path;

pub(super) fn validate(stderr: &str, roots: &[&Path]) -> io::Result<()> {
    // Exact argv coverage belongs to the host Lorry contract. Native acceptance
    // checks semantic results and discovery failures without additional tracing.
    for line in stderr.lines() {
        if line.contains(" ERROR ")
            || (line.contains(" WARN ")
                && !(line.contains("Failed to parse `")
                    && line.contains("/devtools/bin/lorry")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn output(root: &Path) -> String {
        format!(
            "INFO {}/generated-dependency/Cargo.toml: BuildScriptOutput cfgs: [Flag(\"generated_fixture\")] \"GENERATED_ENV\": \"from-build-script\" {}/target/rust-analyzer/lorry/",
            root.display(),
            root.display()
        )
    }

    #[test]
    fn both_project_build_outputs_are_required() {
        let first = Path::new("/first project");
        let second = Path::new("/second");
        let input = format!("{}\n{}", output(first), output(second));
        validate(&input, &[first, second]).unwrap();
        for bad in [
            output(first),
            input.replace("from-build-script", "wrong"),
            format!("{input}\n ERROR cfg fallback"),
            format!("{input}\n WARN query fallback"),
        ] {
            assert!(validate(&bad, &[first, second]).is_err());
        }
        validate(&format!("{input}\n WARN Failed to parse `/devtools/bin/lorry --version` output as a semver version"), &[first, second]).unwrap();
    }
}
