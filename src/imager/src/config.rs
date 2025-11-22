use std::{fs, path::PathBuf};
use yaml_rust::{Yaml, YamlLoader};

pub(crate) struct ImageConfig {
    pub(crate) img_files: String,
    pub(crate) binaries: Vec<String>,
    pub(crate) fs_type: String,
    pub(crate) fs_partition_name: String,
    pub(crate) filename: String,
}

pub(crate) struct ImagerConfig {
    img_out_dir: PathBuf,
    static_files_dir: PathBuf,
    image: ImageConfig,
}

impl ImagerConfig {
    pub(crate) fn load(path: &PathBuf) -> Option<Self> {
        if !path.exists() {
            // check for it on the imager folder
            let mut alt_path = get_crate_root();
            alt_path.push(path);
            if !alt_path.exists() {
                return None;
            }
            return Self::load(&alt_path);
        }
        let contents = fs::read_to_string(path).ok()?;
        Some(contents.into())
    }

    pub(crate) fn img_out_dir(&self) -> &PathBuf {
        &self.img_out_dir
    }

    pub(crate) fn static_files_dir(&self) -> &PathBuf {
        &self.static_files_dir
    }

    pub(crate) fn image(&self) -> &ImageConfig {
        &self.image
    }
}

impl From<String> for ImagerConfig {
    fn from(src: String) -> Self {
        let docs = YamlLoader::load_from_str(&src).unwrap();
        let doc = &docs[0];

        // constants
        let constants = doc["constants"].as_hash().unwrap();
        let img_out_dir = constants[&Yaml::String("img_out_dir".into())].as_str().unwrap().to_string();
        let static_files_dir = constants[&Yaml::String("static_files_dir".into())].as_str().unwrap().to_string();
        
        // top-level name
        let img_files = doc["img_files"].as_str().unwrap().to_string();

        // binaries
        let binaries = doc["binaries"]
            .as_vec()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<String>>();

        // filesystem block
        let fs = doc["filesystem"].as_hash().unwrap();

        let fs_type = fs[&Yaml::String("type".into())].as_str().unwrap().to_string();
        let filename = fs[&Yaml::String("filename".into())].as_str().unwrap().to_string();
        let fs_partition_name = fs[&Yaml::String("partition_name".into())].as_str().unwrap().to_string();

        let image = ImageConfig {
            img_files,
            binaries,
            fs_type,
            fs_partition_name,
            filename,
        };

        Self {
            img_out_dir: PathBuf::from(img_out_dir),
            static_files_dir: PathBuf::from(static_files_dir),
            image,
        }
    }
}

fn get_crate_root() -> PathBuf {
    let file_path = PathBuf::from(file!());
    file_path.parent().unwrap().parent().unwrap().to_path_buf()
}

impl Default for ImagerConfig {
    fn default() -> Self {
        let config_path = get_crate_root()
            .join("full.config.yaml");

        Self::load(&config_path).expect("Expected full.config.yaml at the root of the imager crate")
    }
}
