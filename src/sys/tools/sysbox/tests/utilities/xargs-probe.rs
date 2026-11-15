use std::io::Read;

pub fn probe() {
    let args: Vec<_> = std::env::args().skip(2).collect();
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    assert!(input.is_empty(), "xargs child must receive EOF on stdin");
    match args[0].as_str() {
        "args" => println!("{:?}", &args[1..]),
        "count" => {
            assert!(args[1..].iter().all(|argument| argument == "ab"));
            assert!(
                std::env::args()
                    .map(|argument| argument.len() + 1)
                    .sum::<usize>()
                    < 128 * 1024
            );
            println!("{}", args.len() - 1);
        }
        "status" => {
            println!("ran");
            std::process::exit(args[1].parse().unwrap());
        }
        _ => panic!("unknown xargs test probe"),
    }
}
