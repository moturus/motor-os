use std::io;
use std::path::Path;

use crate::semantic::uri_path;
use serde_json::Value;

pub(super) fn require_generated_definition(definition: &Value, root: &Path) -> io::Result<()> {
    let location = definition
        .as_array()
        .and_then(|locations| locations.first())
        .unwrap_or(definition);
    let uri = location["uri"]
        .as_str()
        .or_else(|| location["targetUri"].as_str())
        .ok_or_else(|| io::Error::other(format!("missing generated definition: {definition}")))?;
    let path = uri_path(uri)?;
    if !path.starts_with(root.join("target/rust-analyzer"))
        || path.file_name().is_none_or(|name| name != "generated.rs")
    {
        return Err(io::Error::other(format!(
            "wrong generated definition: {definition}"
        )));
    }
    Ok(())
}

pub(super) fn require_completion(completion: &Value, label: &str) -> io::Result<()> {
    let items = completion
        .as_array()
        .or_else(|| completion["items"].as_array());
    if !items.is_some_and(|items| items.iter().any(|item| item["label"] == label)) {
        return Err(io::Error::other(format!(
            "missing {label} completion: {completion}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::file_uri;
    use serde_json::json;

    #[test]
    fn generated_definition_belongs_to_the_selected_project() {
        let root = Path::new("/devtools/tmp/first");
        let path = root.join("target/rust-analyzer/build/out/generated.rs");
        for result in [
            json!([{"uri": file_uri(&path)}]),
            json!([{"targetUri": file_uri(&path)}]),
        ] {
            require_generated_definition(&result, root).unwrap();
            assert!(
                require_generated_definition(&result, Path::new("/devtools/tmp/second")).is_err()
            );
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
