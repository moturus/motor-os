use derive_answer::{Answer, add_one, answer_value};

#[derive(Answer)]
struct Value;

#[answer_value]
struct Attributed;

fn main() {
    println!("{}", Value::answer() + add_one!(0) + Attributed::answer());
}
