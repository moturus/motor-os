use derive_answer::Answer;

#[derive(Answer)]
struct Value;

fn main() {
    println!("{}", Value::answer());
}

