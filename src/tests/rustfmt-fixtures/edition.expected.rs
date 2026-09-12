pub async fn fetch() {
    let result = async { 42 }.await;
    println!("{result}");
}
