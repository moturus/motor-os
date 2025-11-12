use std::{collections::HashMap, fs, path::PathBuf};
use yaml_rust::YamlLoader;

pub(crate) type ImageSetName = String;
pub(crate) type BinaryList = Vec<String>;

#[derive(Debug)]
pub(crate) struct ImageInfo {
    pub(crate) name: String,
    pub(crate) fs_partition_name: String,
    pub(crate) part3_fs: String,
}

#[derive(Debug)]
pub(crate) struct ImageSetConfig {
    pub(crate) binaries: BinaryList,
    pub(crate) images: Vec<ImageInfo>,
}

pub(crate) struct ImagerConfig {
    img_out_dir: PathBuf,
    static_files_dir: PathBuf,
    image_sets: HashMap<ImageSetName, ImageSetConfig>,
}

impl ImagerConfig {
    pub(crate) fn load(path: &PathBuf) -> Option<Self> {
        let contents = fs::read_to_string(path).ok()?;
        Some(contents.into())
    }

    pub(crate) fn img_out_dir(&self) -> &PathBuf {
        &self.img_out_dir
    }

    pub(crate) fn static_files_dir(&self) -> &PathBuf {
        &self.static_files_dir
    }

    pub(crate) fn image_sets(&self) -> &HashMap<ImageSetName, ImageSetConfig> {
        &self.image_sets
    }

    pub(crate) fn get_image_set(&self, name: &str) -> Option<&ImageSetConfig> {
        self.image_sets.get(name)
    }

    pub(crate) fn get_binaries(&self, name: &str) -> Option<&BinaryList> {
        self.image_sets.get(name).map(|s| &s.binaries)
    }

    pub(crate) fn get_images(&self, name: &str) -> Option<&Vec<ImageInfo>> {
        self.image_sets.get(name).map(|s| &s.images)
    }
}

impl From<String> for ImagerConfig {
    fn from(src: String) -> Self {
        let docs = YamlLoader::load_from_str(&src).unwrap();
        let doc = &docs[0];

        // Parse paths
        let paths = doc["paths"].as_hash().unwrap();
        let img_out_dir = paths[&yaml_rust::Yaml::from_str("img_out_dir")]
            .as_str()
            .unwrap()
            .to_string();
        let static_files_dir = paths[&yaml_rust::Yaml::from_str("static_files_dir")]
            .as_str()
            .unwrap()
            .to_string();

        // Parse image_sets section
        let image_sets_yaml = doc["image_sets"].as_hash().unwrap();
        let mut image_sets: HashMap<ImageSetName, ImageSetConfig> = HashMap::new();

        for (set_name_yaml, set_value_yaml) in image_sets_yaml {
            let set_name = set_name_yaml.as_str().unwrap().to_string();
            let inner = set_value_yaml.as_hash().unwrap();

            // binaries
            let binaries = inner[&yaml_rust::Yaml::from_str("binaries")]
                .as_vec()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect::<BinaryList>();

            let images = inner
                .get(&yaml_rust::Yaml::from_str("images"))
                .and_then(|i| i.as_vec())
                .map(|v| {
                    v.iter()
                        .map(|entry| {
                            let e = entry.as_hash().unwrap();
                            ImageInfo {
                                name: e[&yaml_rust::Yaml::from_str("name")]
                                    .as_str()
                                    .unwrap()
                                    .to_string(),
                                fs_partition_name: e[&yaml_rust::Yaml::from_str("fs_partition_name")]
                                    .as_str()
                                    .unwrap()
                                    .to_string(),
                                part3_fs: e[&yaml_rust::Yaml::from_str("part3_fs")]
                                    .as_str()
                                    .unwrap()
                                    .to_string(),
                            }
                        })
                        .collect::<Vec<ImageInfo>>()
                })
                .unwrap_or_default();

            image_sets.insert(set_name, ImageSetConfig { binaries, images });
        }

        Self {
            img_out_dir: PathBuf::from(img_out_dir),
            static_files_dir: PathBuf::from(static_files_dir),
            image_sets,
        }
    }
}

impl Default for ImagerConfig {
    fn default() -> Self {
        let file_path = PathBuf::from(file!());
        let config_path = file_path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("config.yaml");

        Self::load(&config_path).expect("Expected config.yaml at the root of the imager crate")
    }
}
