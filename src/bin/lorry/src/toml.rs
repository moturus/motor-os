use std::fs::File;
use std::io::Read;
use std::ops::Range;
use std::path::Path;

use toml_edit::{ImDocument, Item, Table, Value};

use crate::diagnostic::{Error, Result};

pub const DOCUMENT_LIMITS: Limits = Limits {
    max_bytes: 4 * 1024 * 1024,
    max_depth: 64,
    max_nodes: 100_000,
};

// Cargo serializes TOML metadata directly, including datetime's private
// serde wrapper. Parsed documents already bound recursion and node counts.
pub fn json(item: &Item) -> serde_json::Value {
    fn table(table: &Table) -> serde_json::Value {
        serde_json::Value::Object(
            table
                .iter()
                .map(|(key, item)| (key.to_owned(), json(item)))
                .collect(),
        )
    }
    fn json_value(value: &Value) -> serde_json::Value {
        match value {
            Value::String(value) => value.value().clone().into(),
            Value::Integer(value) => (*value.value()).into(),
            Value::Float(value) => (*value.value()).into(),
            Value::Boolean(value) => (*value.value()).into(),
            Value::Datetime(value) => {
                serde_json::json!({ "$__toml_private_datetime": value.value().to_string() })
            }
            Value::Array(array) => serde_json::Value::Array(array.iter().map(json_value).collect()),
            Value::InlineTable(table) => serde_json::Value::Object(
                table
                    .iter()
                    .map(|(key, item)| (key.to_owned(), json_value(item)))
                    .collect(),
            ),
        }
    }
    match item {
        Item::None => serde_json::Value::Null,
        Item::Value(item) => json_value(item),
        Item::Table(item) => table(item),
        Item::ArrayOfTables(items) => serde_json::Value::Array(items.iter().map(table).collect()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
}

#[derive(Debug)]
pub struct Document {
    source: String,
    parsed: ImDocument<String>,
}

impl Document {
    pub fn load(path: &Path, context: &str) -> Result<Self> {
        let mut file = File::open(path).map_err(|error| {
            Error::failure(format!("failed to read `{}`: {error}", path.display()))
        })?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(DOCUMENT_LIMITS.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                Error::failure(format!("failed to read `{}`: {error}", path.display()))
            })?;
        if bytes.len() > DOCUMENT_LIMITS.max_bytes {
            return Err(limit_error(
                path,
                1,
                context,
                "byte",
                DOCUMENT_LIMITS.max_bytes,
            ));
        }
        let source = String::from_utf8(bytes).map_err(|error| {
            Error::failure(format!(
                "{context} `{}` is not valid UTF-8 at byte {}",
                path.display(),
                error.utf8_error().valid_up_to()
            ))
        })?;
        Self::parse_with_limits(path, context, source, DOCUMENT_LIMITS)
    }

    pub fn parse(path: &Path, context: &str, source: String) -> Result<Self> {
        Self::parse_with_limits(path, context, source, DOCUMENT_LIMITS)
    }

    fn parse_with_limits(
        path: &Path,
        context: &str,
        source: String,
        limits: Limits,
    ) -> Result<Self> {
        if source.len() > limits.max_bytes {
            return Err(limit_error(path, 1, context, "byte", limits.max_bytes));
        }
        let parsed = ImDocument::parse(source.clone()).map_err(|error| {
            let line = error
                .span()
                .map_or(1, |span| line_for_offset(&source, span.start));
            Error::at(
                path,
                line,
                format!("invalid TOML 1.0 in {context}: {error}"),
                "fix the TOML syntax; TOML 1.1-only syntax is not supported",
            )
        })?;
        let mut count = 0;
        count_table(
            path,
            context,
            &source,
            parsed.as_table(),
            0,
            limits,
            &mut count,
        )?;
        Ok(Self { source, parsed })
    }

    pub fn root(&self) -> &Table {
        self.parsed.as_table()
    }

    pub fn line_of_item(&self, item: &Item) -> usize {
        line_for_span(&self.source, item_span(item))
    }

    pub fn line_of_table(&self, table: &Table) -> usize {
        line_for_span(&self.source, table_span(table))
    }

    pub fn line_of_value(&self, value: &Value) -> usize {
        line_for_span(&self.source, value.span())
    }
}

fn count_table(
    path: &Path,
    context: &str,
    source: &str,
    table: &Table,
    depth: usize,
    limits: Limits,
    count: &mut usize,
) -> Result<()> {
    check_depth(path, context, source, table.span(), depth, limits.max_depth)?;
    for (_, item) in table.iter() {
        add_node(path, context, source, item.span(), limits.max_nodes, count)?;
        count_item(path, context, source, item, depth + 1, limits, count)?;
    }
    Ok(())
}

fn count_item(
    path: &Path,
    context: &str,
    source: &str,
    item: &Item,
    depth: usize,
    limits: Limits,
    count: &mut usize,
) -> Result<()> {
    check_depth(path, context, source, item.span(), depth, limits.max_depth)?;
    match item {
        Item::None => Ok(()),
        Item::Table(table) => count_table(path, context, source, table, depth, limits, count),
        Item::ArrayOfTables(tables) => {
            for table in tables.iter() {
                add_node(path, context, source, table.span(), limits.max_nodes, count)?;
                count_table(path, context, source, table, depth, limits, count)?;
            }
            Ok(())
        }
        Item::Value(value) => count_value(path, context, source, value, depth, limits, count),
    }
}

fn count_value(
    path: &Path,
    context: &str,
    source: &str,
    value: &Value,
    depth: usize,
    limits: Limits,
    count: &mut usize,
) -> Result<()> {
    check_depth(path, context, source, value.span(), depth, limits.max_depth)?;
    match value {
        Value::Array(array) => {
            for value in array.iter() {
                add_node(path, context, source, value.span(), limits.max_nodes, count)?;
                count_value(path, context, source, value, depth + 1, limits, count)?;
            }
        }
        Value::InlineTable(table) => {
            for (_, value) in table.iter() {
                add_node(path, context, source, value.span(), limits.max_nodes, count)?;
                count_value(path, context, source, value, depth + 1, limits, count)?;
            }
        }
        Value::String(_)
        | Value::Integer(_)
        | Value::Float(_)
        | Value::Boolean(_)
        | Value::Datetime(_) => {}
    }
    Ok(())
}

fn add_node(
    path: &Path,
    context: &str,
    source: &str,
    span: Option<Range<usize>>,
    limit: usize,
    count: &mut usize,
) -> Result<()> {
    *count = count.saturating_add(1);
    if *count > limit {
        return Err(limit_error(
            path,
            line_for_span(source, span),
            context,
            "node",
            limit,
        ));
    }
    Ok(())
}

fn check_depth(
    path: &Path,
    context: &str,
    source: &str,
    span: Option<Range<usize>>,
    depth: usize,
    limit: usize,
) -> Result<()> {
    if depth > limit {
        return Err(limit_error(
            path,
            line_for_span(source, span),
            context,
            "nesting-depth",
            limit,
        ));
    }
    Ok(())
}

fn limit_error(path: &Path, line: usize, context: &str, kind: &str, limit: usize) -> Error {
    Error::at(
        path,
        line,
        format!("{context} exceeds the TOML {kind} limit of {limit}"),
        "reduce the document before invoking Lorry",
    )
}

/// An implicit table, such as `a` in `[a.b]`, has no span of its own. It
/// starts where its first explicit descendant starts.
fn table_span(table: &Table) -> Option<Range<usize>> {
    table.span().or_else(|| {
        table
            .iter()
            .filter_map(|(_, item)| item_span(item))
            .min_by_key(|span| span.start)
    })
}

fn item_span(item: &Item) -> Option<Range<usize>> {
    match item {
        Item::Table(table) => table_span(table),
        _ => item.span(),
    }
}

fn line_for_span(source: &str, span: Option<Range<usize>>) -> usize {
    span.map_or(1, |span| line_for_offset(source, span.start))
}

fn line_for_offset(source: &str, offset: usize) -> usize {
    1 + source
        .as_bytes()
        .iter()
        .take(offset.min(source.len()))
        .filter(|byte| **byte == b'\n')
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LIMITS: Limits = Limits {
        max_bytes: 128,
        max_depth: 3,
        max_nodes: 5,
    };

    #[test]
    fn parses_toml_1_0_and_retains_source_spans() {
        let source = "[package]\nname = \"demo\"\nauthors = [\n  \"A\",\n  \"B\",\n]\n".to_owned();
        let document = Document::parse(Path::new("Cargo.toml"), "manifest", source).unwrap();
        let package = document.root().get("package").unwrap().as_table().unwrap();
        assert_eq!(document.line_of_table(package), 1);
        assert_eq!(document.line_of_item(package.get("name").unwrap()), 2);
        assert_eq!(
            package
                .get("authors")
                .and_then(Item::as_array)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn implicit_tables_start_at_their_first_explicit_descendant() {
        let source = "config-version = 1\n\n[a.b.c]\nkey = 1\n[a.d]\n".to_owned();
        let document = Document::parse(Path::new("lorry.toml"), "configuration", source).unwrap();
        let a = document.root().get("a").unwrap();
        assert_eq!(document.line_of_item(a), 3);
        let b = a.as_table().unwrap().get("b").unwrap();
        assert_eq!(document.line_of_table(b.as_table().unwrap()), 3);
    }

    #[test]
    fn rejects_duplicate_and_truncated_toml_with_a_source_line() {
        for source in [
            "[package]\nname = \"one\"\nname = \"two\"\n",
            "[package]\nname = [\"unfinished\"\n",
        ] {
            let error = Document::parse(Path::new("Cargo.toml"), "manifest", source.to_owned())
                .unwrap_err();
            let rendered = error.render();
            assert!(rendered.contains("invalid TOML 1.0"));
            assert!(rendered.contains("Cargo.toml:"));
        }
    }

    #[test]
    fn enforces_byte_depth_and_node_limits() {
        let byte_error = Document::parse_with_limits(
            Path::new("config.toml"),
            "configuration",
            "x".repeat(TEST_LIMITS.max_bytes + 1),
            TEST_LIMITS,
        )
        .unwrap_err();
        assert!(byte_error.to_string().contains("byte limit"));

        let depth_error = Document::parse_with_limits(
            Path::new("config.toml"),
            "configuration",
            "value = { a = { b = { c = 1 } } }\n".to_owned(),
            TEST_LIMITS,
        )
        .unwrap_err();
        assert!(depth_error.to_string().contains("nesting-depth limit"));

        let node_error = Document::parse_with_limits(
            Path::new("config.toml"),
            "configuration",
            "a=1\nb=2\nc=3\nd=4\ne=5\nf=6\n".to_owned(),
            TEST_LIMITS,
        )
        .unwrap_err();
        assert!(node_error.to_string().contains("node limit"));
    }
}
