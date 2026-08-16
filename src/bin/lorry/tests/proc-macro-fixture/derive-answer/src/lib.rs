extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro_derive(Answer)]
pub fn derive_answer(_: TokenStream) -> TokenStream {
    macro_helper::implementation().parse().unwrap()
}

#[proc_macro]
pub fn add_one(input: TokenStream) -> TokenStream {
    println!("proc-macro stdout is preserved");
    format!("({input} + 1)").parse().unwrap()
}

#[proc_macro_attribute]
pub fn answer_value(_: TokenStream, item: TokenStream) -> TokenStream {
    format!("{item} impl Attributed {{ fn answer() -> u32 {{ 41 }} }}")
        .parse()
        .unwrap()
}

#[proc_macro]
pub fn intentional_failure(_: TokenStream) -> TokenStream {
    panic!("intentional proc-macro failure")
}
