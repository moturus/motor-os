use std::{env, fs, path::Path};
use yaml_rust::YamlLoader;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    let yaml_path = Path::new(&manifest_dir).join("config.yaml");
    let contents = fs::read_to_string(yaml_path).unwrap();

    let parsed = parse_yaml(&contents);
    let code = format!(
        "pub const BIN_FULL: &[&str] = &{:?};\n\
         pub const BIN_WEB: &[&str] = &{:?};\n\
         pub const IMG_OUT_DIR: &str = {:?};\n\
         pub const IMG_FILES_DIR: &str = {:?};\n\
        ",
        parsed.bin_full, parsed.bin_web, parsed.img_out_dir, parsed.img_files_dir
    );
    fs::write(Path::new(&out_dir).join("imagerconsts.rs"), code).unwrap();
}

struct ImagerConfig {
    bin_full: Vec<String>,
    bin_web: Vec<String>,
    img_out_dir: String,
    img_files_dir: String,
}

fn parse_yaml(src: &str) -> ImagerConfig {
    let docs = YamlLoader::load_from_str(src).unwrap();
    let doc = &docs[0];

    let bin_full = doc["bin_full"]
        .as_vec()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect::<Vec<_>>();

    let bin_web = doc["bin_web"]
        .as_vec()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect::<Vec<_>>();

    let img_out_dir = doc["img_out_dir"].as_str().unwrap().to_string();
    let img_files_dir = doc["img_files_dir"].as_str().unwrap().to_string();

    ImagerConfig { bin_full, bin_web, img_out_dir, img_files_dir }
}
