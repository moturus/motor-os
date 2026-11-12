// A network-free curl fixture: two redirects to one site, then a distinct
// terminal response. The native test must approve the site exactly once.
fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    let option = |name: &str| {
        let position = arguments.iter().position(|value| value == name).unwrap();
        arguments[position + 1].as_str()
    };
    let url = option("--url");
    let nonce = option("--write-out")
        .split_once("LORRY-CURL-1 ")
        .unwrap()
        .1
        .lines()
        .next()
        .unwrap();
    let (status, redirect) = match url {
        "https://lorry-redirect.invalid/first" => (302, "https://lorry-redirect.invalid/final"),
        "https://lorry-redirect.invalid/final" => (404, ""),
        _ => (302, "https://lorry-redirect.invalid/first"),
    };
    eprint!(
        "\nLORRY-CURL-1 {nonce}\nstatus={status}\nurl={url}\nredirect={redirect}\nsize=0\nEND-LORRY-CURL-1 {nonce}\n"
    );
}
