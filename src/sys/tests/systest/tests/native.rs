// The cases share process and kernel state and retain their established order.
// A custom harness also dispatches the subprocess helpers through current_exe.
fn main() {
    systest::run();
}
