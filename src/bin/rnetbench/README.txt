In the Motor-OS VM (qemu), run

$ sys/rnetbench -s -p 5542


On the host, in $MOTORH/src/bin/rnetbench dir, run

$ cargo run --release -- -c localhost:10023