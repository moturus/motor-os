use core::arch::asm;
use core::fmt;

fn write_to_port(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

struct SerialPort {}

impl SerialPort {
    pub fn send(&mut self, data: u8) {
        write_to_port(0x3F8, data)
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.send(byte);
        }
        Ok(())
    }
}

#[allow(unused)]
pub fn write_serial_args(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    SerialPort {}.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! write_serial {
    ($($arg:tt)*) => {
        $crate::serial::write_serial_args(format_args!($($arg)*))
    };
}

#[allow(unused)]
pub use write_serial;
