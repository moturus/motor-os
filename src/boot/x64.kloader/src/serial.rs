use core::fmt;

struct SerialPort {}

impl SerialPort {
    pub fn write_byte(&mut self, data: u8) {
        crate::util::write_to_port(0x3F8, data)
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                // CHV needs CR.
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}

#[doc(hidden)]
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

pub use write_serial;
