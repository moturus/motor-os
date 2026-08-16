extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro_derive(Answer)]
pub fn derive_answer(_: TokenStream) -> TokenStream {
    macro_helper::implementation().parse().unwrap()
}

