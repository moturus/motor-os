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

    #[cfg(test)]
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
        line_for_span(&self.source, item.span())
    }

    pub fn line_of_table(&self, table: &Table) -> usize {
        line_for_span(&self.source, table.span())
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
