#![feature(motor_ext)]

mod greeting;

fn main() {
    let answer: u32 = greeting::ANSWER;
    println!("Hello from Motor OS! The answer is {answer}.");
    println!("Runtime version: {}", std::os::motor::rt_version());
}
