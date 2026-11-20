use crate::support::{Scratch, command, interactive, output, success};
use std::fs;
use std::path::Path;

pub fn input(name: &str) -> &'static str {
    INPUTS.iter().find(|(key, _)| *key == name).unwrap().1
}

fn formatted(root: &Path, name: &str, expected: &str) {
    success(
        command(root, "/user/bin/dev/rustfmt").args(["--edition", "2024", name]),
        b"",
    );
    assert_eq!(
        fs::read_to_string(root.join(name)).unwrap(),
        input(expected)
    );
}

pub fn run() {
    let scratch = Scratch::new("rustfmt");
    let root = &scratch.0;
    let stdin = success(
        command(root, "/user/bin/dev/rustfmt").args(["--edition", "2024"]),
        input("stdin.in.rs").as_bytes(),
    );
    assert_eq!(stdin.stdout, input("stdin.expected.rs").as_bytes());
    scratch.write("in place/input.rs", input("in-place.in.rs"));
    formatted(root, "in place/input.rs", "in-place.expected.rs");
    formatted(root, "in place/input.rs", "in-place.expected.rs");
    scratch.write("project config/input.rs", input("width.in.rs"));
    scratch.write("project config/rustfmt.toml", input("width.toml"));
    formatted(root, "project config/input.rs", "width.expected.rs");

    if interactive() {
        // These are the two user configuration locations in Motor's formatter.
        // The disposable image must start with neither present.
        for path in ["/user/cfg/rustfmt/rustfmt.toml", "/user/rustfmt.toml"] {
            assert!(
                !Path::new(path).exists(),
                "unexpected user configuration: {path}"
            );
            let parent = Path::new(path).parent().unwrap();
            if !parent.is_dir() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, input("width.toml")).unwrap();
            scratch.write("user config/input.rs", input("width.in.rs"));
            formatted(root, "user config/input.rs", "width.expected.rs");
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir("/user/cfg/rustfmt").unwrap();
    }
    scratch.write("env/input.rs", input("width.in.rs"));
    scratch.write("env/home/rustfmt.toml", input("width.toml"));
    scratch.write("env/xdg/rustfmt/rustfmt.toml", input("width.toml"));
    success(
        command(root, "/user/lib/rust/bin/rustfmt")
            .env("HOME", root.join("env/home"))
            .env("XDG_CONFIG_HOME", root.join("env/xdg"))
            .args(["--edition", "2024", "env/input.rs"]),
        b"",
    );
    assert_eq!(
        fs::read_to_string(root.join("env/input.rs")).unwrap(),
        input("width.default.expected.rs")
    );

    scratch.write("edition.rs", input("edition.in.rs"));
    let bad = output(
        command(root, "/user/bin/dev/rustfmt").args(["--edition", "2015", "edition.rs"]),
        b"",
    );
    assert_eq!(bad.status.code(), Some(1), "{bad:?}");
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("error"),
        "{bad:?}"
    );
    formatted(root, "edition.rs", "edition.expected.rs");
    scratch.write("macro.rs", input("macro.in.rs"));
    formatted(root, "macro.rs", "macro.expected.rs");
    for (kind, code) in [("lexer", 101), ("parser", 1)] {
        let name = format!("{kind}-error.rs");
        scratch.write(&name, input(&name));
        let bad = output(
            command(root, "/user/bin/dev/rustfmt").args(["--edition", "2024", &name]),
            b"",
        );
        assert_eq!(bad.status.code(), Some(code), "{bad:?}");
        assert!(
            String::from_utf8_lossy(&bad.stderr).contains("error"),
            "{bad:?}"
        );
        assert_eq!(fs::read_to_string(root.join(&name)).unwrap(), input(&name));
        let good = success(
            command(root, "/user/bin/dev/rustfmt").args(["--edition", "2024"]),
            input("stdin.in.rs").as_bytes(),
        );
        assert_eq!(good.stdout, input("stdin.expected.rs").as_bytes());
    }
    println!("rustfmt: PASS");
}

const INPUTS: &[(&str, &str)] = &[
    (
        "edition.expected.rs",
        r####"pub async fn fetch() {
    let result = async { 42 }.await;
    println!("{result}");
}
"####,
    ),
    (
        "edition.in.rs",
        r####"pub async fn fetch(){let result=async{42}.await;println!("{result}");}
"####,
    ),
    (
        "in-place.expected.rs",
        r####"pub fn calculate(value: i32) -> i32 {
    if value > 0 { value * 2 } else { 0 }
}
"####,
    ),
    (
        "in-place.in.rs",
        r####"pub fn calculate(value:i32)->i32{if value>0{value*2}else{0}}
"####,
    ),
    (
        "lexer-error.rs",
        r####"fn main() { let value = r###"unterminated; }
"####,
    ),
    (
        "macro.expected.rs",
        r####"fn main() {
    custom_macro!(
        alpha + beta,
        if ready {
            compute(1, 2, 3)
        } else {
            compute(4, 5, 6)
        }
    );
}
"####,
    ),
    (
        "macro.in.rs",
        r####"fn main(){custom_macro!(alpha+beta,if ready{compute(1,2,3)}else{compute(4,5,6)});}
"####,
    ),
    (
        "parser-error.rs",
        r####"fn main() { let value = ; }
"####,
    ),
    (
        "stdin.expected.rs",
        r####"fn main() {
    let values = vec![3, 1, 2];
    println!("{:?}", values);
}
"####,
    ),
    (
        "stdin.in.rs",
        r####"fn main(){let values=vec![3,1,2];println!("{:?}",values);}
"####,
    ),
    (
        "width.default.expected.rs",
        r####"pub fn describe(first: &str, second: &str, third: &str, fourth: &str) -> String {
    format!("{}:{}:{}:{}", first, second, third, fourth)
}
"####,
    ),
    (
        "width.expected.rs",
        r####"pub fn describe(
    first: &str,
    second: &str,
    third: &str,
    fourth: &str,
) -> String {
    format!("{}:{}:{}:{}", first, second, third, fourth)
}
"####,
    ),
    (
        "width.in.rs",
        r####"pub fn describe(first: &str, second: &str, third: &str, fourth: &str) -> String { format!("{}:{}:{}:{}", first, second, third, fourth) }
"####,
    ),
    (
        "width.toml",
        r####"max_width = 60
"####,
    ),
];
