use core::fmt;

use x86_64::instructions::port::{Port, PortReadOnly};

const INPUT_FULL: u8 = 1;
const OUTPUT_EMPTY: u8 = 1 << 5;

macro_rules! wait_for {
    ($cond:expr) => {
        while !$cond {
            core::hint::spin_loop()
        }
    };
}

pub struct SerialPort {
    data: Port<u8>,
    line_sts: PortReadOnly<u8>,
}

impl SerialPort {
    pub const unsafe fn new(base: u16) -> Self {
        Self {
            data: Port::new(base),
            line_sts: PortReadOnly::new(base + 5),
        }
    }

    fn line_sts(&mut self) -> u8 {
        unsafe { self.line_sts.read() }
    }

    pub fn send(&mut self, data: u8) {
        unsafe {
            match data {
                8 | 0x7F => {
                    wait_for!(self.line_sts() & OUTPUT_EMPTY != 0);
                    self.data.write(8);
                    wait_for!(self.line_sts() & OUTPUT_EMPTY != 0);
                    self.data.write(b' ');
                    wait_for!(self.line_sts() & OUTPUT_EMPTY != 0);
                    self.data.write(8)
                }
                b'\n' => {
                    // On CHV we need to add \r.
                    wait_for!(self.line_sts() & OUTPUT_EMPTY != 0);
                    self.data.write(data);
                    wait_for!(self.line_sts() & OUTPUT_EMPTY != 0);
                    self.data.write(b'\r');
                }
                _ => {
                    wait_for!(self.line_sts() & OUTPUT_EMPTY != 0);
                    self.data.write(data);
                }
            }
        }
    }

    pub fn read(&mut self) -> Option<u8> {
        if self.line_sts() & INPUT_FULL != 0 {
            unsafe { Some(self.data.read()) }
        } else {
            None
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        for byte in data {
            self.send(*byte);
        }
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

static SERIAL1: std::sync::Mutex<SerialPort> =
    std::sync::Mutex::new(unsafe { SerialPort::new(0x3F8) });

pub fn read_serial() -> Option<u8> {
    SERIAL1.lock().unwrap().read()
}

#[doc(hidden)]
pub fn write_serial_raw(data: &[u8]) {
    SERIAL1.lock().unwrap().write(data);
}

#[doc(hidden)]
pub fn write_serial_args(args: ::core::fmt::Arguments) {
    use core::fmt::Write;
    SERIAL1
        .lock()
        .unwrap()
        .write_fmt(args)
        .expect("Printing to serial failed");
}

#[macro_export]
macro_rules! write_serial {
    ($($arg:tt)*) => {
        $crate::serial::write_serial_args(format_args!($($arg)*))
    };
}

#[allow(unused)]
pub use write_serial;
