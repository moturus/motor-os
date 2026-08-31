extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro]
pub fn define_marker(_input: TokenStream) -> TokenStream {
    "pub struct GeneratedByProcMacro;".parse().unwrap()
}
