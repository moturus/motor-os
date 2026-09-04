use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct Metadata {
    pub packages: Vec<Package>,
    pub workspace_members: Vec<String>,
    pub workspace_default_members: Vec<String>,
    pub resolve: Option<Resolve>,
    pub workspace_root: String,
    pub target_directory: String,
    pub build_directory: String,
    pub workspace_metadata: serde_json::Value,
    pub version: u8,
}

#[derive(Debug)]
pub struct Resolve {
    pub nodes: Vec<Node>,
    pub root: Option<String>,
}

#[derive(Debug)]
pub struct Node {
    pub id: String,
    pub deps: Vec<NodeDep>,
    pub dependencies: Vec<String>,
    pub features: Vec<String>,
}

#[derive(Debug)]
pub struct NodeDep {
    pub name: String,
    pub pkg: String,
    pub dep_kinds: Vec<DepKindInfo>,
}

#[derive(Debug)]
pub struct DepKindInfo {
    pub kind: Option<DependencyKind>,
    pub target: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum DependencyKind {
    Dev,
    Build,
}

#[derive(Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub authors: Vec<String>,
    pub id: String,
    pub source: Option<String>,
    pub description: Option<String>,
    pub dependencies: Vec<Dependency>,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub targets: Vec<Target>,
    pub features: BTreeMap<String, Vec<String>>,
    pub manifest_path: String,
    pub categories: Vec<String>,
    pub keywords: Vec<String>,
    pub readme: Option<String>,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
    pub edition: String,
    pub metadata: serde_json::Value,
    pub links: Option<String>,
    pub publish: Option<Vec<String>>,
    pub default_run: Option<String>,
    pub rust_version: Option<String>,
}

#[derive(Debug)]
pub struct Dependency {
    pub name: String,
    pub source: Option<String>,
    pub req: String,
    pub kind: Option<DependencyKind>,
    pub optional: bool,
    pub uses_default_features: bool,
    pub features: Vec<String>,
    pub target: Option<String>,
    pub rename: Option<String>,
    pub registry: Option<String>,
    pub path: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub kind: Vec<String>,
    pub crate_types: Vec<String>,
    pub required_features: Vec<String>,
    pub src_path: String,
    pub edition: String,
    pub doctest: bool,
    pub test: bool,
    pub doc: bool,
}

macro_rules! serialize_wire_struct {
    ($type:ty, $name:literal, $count:literal, $( $json:literal => $field:ident ),+ $(,)?) => {
        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut value = serializer.serialize_struct($name, $count)?;
                $(value.serialize_field($json, &self.$field)?;)+
                value.end()
            }
        }
    };
}

serialize_wire_struct!(Metadata, "Metadata", 9,
    "packages" => packages,
    "workspace_members" => workspace_members,
    "workspace_default_members" => workspace_default_members,
    "resolve" => resolve,
    "workspace_root" => workspace_root,
    "target_directory" => target_directory,
    "build_directory" => build_directory,
    "metadata" => workspace_metadata,
    "version" => version,
);
serialize_wire_struct!(Resolve, "Resolve", 2, "nodes" => nodes, "root" => root);
serialize_wire_struct!(Node, "Node", 4,
    "id" => id,
    "deps" => deps,
    "dependencies" => dependencies,
    "features" => features,
);
serialize_wire_struct!(NodeDep, "NodeDep", 3,
    "name" => name,
    "pkg" => pkg,
    "dep_kinds" => dep_kinds,
);
serialize_wire_struct!(DepKindInfo, "DepKindInfo", 2,
    "kind" => kind,
    "target" => target,
);
serialize_wire_struct!(Package, "Package", 24,
    "name" => name,
    "version" => version,
    "authors" => authors,
    "id" => id,
    "source" => source,
    "description" => description,
    "dependencies" => dependencies,
    "license" => license,
    "license_file" => license_file,
    "targets" => targets,
    "features" => features,
    "manifest_path" => manifest_path,
    "categories" => categories,
    "keywords" => keywords,
    "readme" => readme,
    "repository" => repository,
    "homepage" => homepage,
    "documentation" => documentation,
    "edition" => edition,
    "metadata" => metadata,
    "links" => links,
    "publish" => publish,
    "default_run" => default_run,
    "rust_version" => rust_version,
);
serialize_wire_struct!(Dependency, "Dependency", 11,
    "name" => name,
    "source" => source,
    "req" => req,
    "kind" => kind,
    "optional" => optional,
    "uses_default_features" => uses_default_features,
    "features" => features,
    "target" => target,
    "rename" => rename,
    "registry" => registry,
    "path" => path,
);
serialize_wire_struct!(Target, "Target", 9,
    "name" => name,
    "kind" => kind,
    "crate_types" => crate_types,
    "required-features" => required_features,
    "src_path" => src_path,
    "edition" => edition,
    "doctest" => doctest,
    "test" => test,
    "doc" => doc,
);

impl Serialize for DependencyKind {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match self {
            Self::Dev => "dev",
            Self::Build => "build",
        })
    }
}

pub fn render(metadata: &Metadata) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec(metadata)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_ID: &str = "path+file:///workspace#app@0.1.0";
    const DEP_ID: &str = "registry+https://github.com/rust-lang/crates.io-index#dep@1.2.3";
    const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn root_package() -> Package {
        Package {
            name: "app".into(),
            version: "0.1.0".into(),
            authors: vec!["U. Lasiotus".into()],
            id: ROOT_ID.into(),
            source: None,
            description: Some("metadata fixture".into()),
            dependencies: vec![Dependency {
                name: "dep".into(),
                source: Some(REGISTRY.into()),
                req: "^1.2".into(),
                kind: None,
                optional: false,
                uses_default_features: true,
                features: vec!["extra".into()],
                target: Some("cfg(target_os = \"motor\")".into()),
                rename: Some("renamed-dep".into()),
                registry: None,
                path: None,
            }],
            license: Some("MIT".into()),
            license_file: Some("/workspace/LICENSE".into()),
            targets: vec![Target {
                name: "app".into(),
                kind: vec!["bin".into()],
                crate_types: vec!["bin".into()],
                required_features: Vec::new(),
                src_path: "/workspace/src/main.rs".into(),
                edition: "2024".into(),
                doctest: false,
                test: true,
                doc: true,
            }],
            features: BTreeMap::from([
                ("default".into(), vec!["dep/default".into()]),
                ("extra".into(), Vec::new()),
            ]),
            manifest_path: "/workspace/Cargo.toml".into(),
            categories: Vec::new(),
            keywords: Vec::new(),
            readme: Some("/workspace/README.md".into()),
            repository: Some("https://example.invalid/app".into()),
            homepage: Some("https://example.invalid".into()),
            documentation: Some("https://docs.example.invalid/app".into()),
            edition: "2024".into(),
            metadata: serde_json::Value::Null,
            links: Some("native-app".into()),
            publish: None,
            default_run: Some("app".into()),
            rust_version: Some("1.85".into()),
        }
    }

    fn dependency_package() -> Package {
        Package {
            name: "dep".into(),
            version: "1.2.3".into(),
            authors: Vec::new(),
            id: DEP_ID.into(),
            source: Some(REGISTRY.into()),
            description: None,
            dependencies: Vec::new(),
            license: Some("Apache-2.0".into()),
            license_file: None,
            targets: vec![Target {
                name: "dep".into(),
                kind: vec!["lib".into()],
                crate_types: vec!["lib".into()],
                required_features: Vec::new(),
                src_path: "/cache/dep/src/lib.rs".into(),
                edition: "2021".into(),
                doctest: true,
                test: true,
                doc: true,
            }],
            features: BTreeMap::from([("extra".into(), Vec::new())]),
            manifest_path: "/cache/dep/Cargo.toml".into(),
            categories: Vec::new(),
            keywords: Vec::new(),
            readme: None,
            repository: None,
            homepage: None,
            documentation: None,
            edition: "2021".into(),
            metadata: serde_json::Value::Null,
            links: None,
            publish: None,
            default_run: None,
            rust_version: None,
        }
    }

    fn fixture(with_dependencies: bool) -> Metadata {
        let packages = if with_dependencies {
            vec![root_package(), dependency_package()]
        } else {
            vec![root_package()]
        };
        let resolve = with_dependencies.then(|| Resolve {
            nodes: vec![
                Node {
                    id: ROOT_ID.into(),
                    deps: vec![NodeDep {
                        name: "renamed_dep".into(),
                        pkg: DEP_ID.into(),
                        dep_kinds: vec![DepKindInfo {
                            kind: None,
                            target: Some("cfg(target_os = \"motor\")".into()),
                        }],
                    }],
                    dependencies: vec![DEP_ID.into()],
                    features: vec!["default".into()],
                },
                Node {
                    id: DEP_ID.into(),
                    deps: Vec::new(),
                    dependencies: Vec::new(),
                    features: vec!["extra".into()],
                },
            ],
            root: Some(ROOT_ID.into()),
        });
        Metadata {
            packages,
            workspace_members: vec![ROOT_ID.into()],
            workspace_default_members: vec![ROOT_ID.into()],
            resolve,
            workspace_root: "/workspace".into(),
            target_directory: "/workspace/target".into(),
            build_directory: "/workspace/target".into(),
            workspace_metadata: serde_json::Value::Null,
            version: 1,
        }
    }

    #[test]
    fn golden_documents_match_serializer() {
        assert_eq!(
            render(&fixture(true)).unwrap(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/metadata-schema/golden/resolved.json"
            ))
        );
        assert_eq!(
            render(&fixture(false)).unwrap(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/metadata-schema/golden/no-deps.json"
            ))
        );
    }
}
