/// A log snapshot can end in the middle of a formatted write, including an address.
pub(super) fn complete_output<'a>(output: &'a str, text: &str) -> Option<&'a str> {
    let end = output.rfind('\n')?;
    let complete = &output[..=end];
    complete.contains(text).then_some(complete)
}
