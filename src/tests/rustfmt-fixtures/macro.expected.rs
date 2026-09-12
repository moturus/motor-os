fn main() {
    custom_macro!(
        alpha + beta,
        if ready {
            compute(1, 2, 3)
        } else {
            compute(4, 5, 6)
        }
    );
}
