#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::file_uri;
    use serde_json::json;

    #[test]
    fn generated_definition_belongs_to_the_selected_project() {
        let root = Path::new("/user/tmp/first");
        let path = root.join("target/rust-analyzer/build/out/generated.rs");
        for result in [
            json!([{"uri": file_uri(&path)}]),
            json!([{"targetUri": file_uri(&path)}]),
        ] {
            require_generated_definition(&result, root).unwrap();
            assert!(require_generated_definition(&result, Path::new("/user/tmp/second")).is_err());
        }
        for result in [
            Value::Null,
            json!([]),
            json!([{"uri": file_uri(&root.join("generated.rs"))}]),
        ] {
            assert!(require_generated_definition(&result, root).is_err());
        }
    }

    #[test]
    fn completion_accepts_both_lsp_shapes_and_requires_the_exact_label() {
        for result in [
            json!([{"label": "GENERATED"}]),
            json!({"items": [{"label": "GENERATED"}]}),
        ] {
            require_completion(&result, "GENERATED").unwrap();
            assert!(require_completion(&result, "GENERATED_MISSING").is_err());
        }
        assert!(require_completion(&Value::Null, "GENERATED").is_err());
    }
}
