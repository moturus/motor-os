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
        let lorry = Path::new("/none/tmp/analyzer-test/lorry");
        let input = format!("{}\n{}", output(first), output(second));
        validate(&input, &[first, second], lorry).unwrap();
        for bad in [
            output(first),
            input.replace("from-build-script", "wrong"),
            format!("{input}\n ERROR cfg fallback"),
            format!("{input}\n WARN query fallback"),
            format!("{input}\n WARN Failed to parse `\"/another/lorry\" --version` output as a semver version"),
        ] {
            assert!(validate(&bad, &[first, second], lorry).is_err());
        }
        validate(&format!("{input}\n WARN Failed to parse `{lorry:?} --version` output as a semver version"), &[first, second], lorry).unwrap();
    }
}
