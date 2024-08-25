use core::fmt;

pub fn write_to_port(port: u16, value: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

struct SimpleSerialPort {}

impl SimpleSerialPort {
    pub fn write_byte(&mut self, data: u8) {
        write_to_port(0x3F8, data)
    }
}

impl fmt::Write for SimpleSerialPort {
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
    SimpleSerialPort {}.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! write_serial_ {
    ($($arg:tt)*) => {
        $crate::arch::x64::serial::write_serial_args(format_args!($($arg)*))
    };
}

pub use write_serial_;

// from uart_16550 = "0.2.15"
use x86_64::instructions::port::{Port, PortWriteOnly};

pub struct SerialPort {
    data: Port<u8>,
    int_en: PortWriteOnly<u8>,
    fifo_ctrl: PortWriteOnly<u8>,
    line_ctrl: PortWriteOnly<u8>,
    modem_ctrl: PortWriteOnly<u8>,
}

impl SerialPort {
    /// Creates a new serial port interface on the given I/O port.
    ///
    /// This function is unsafe because the caller must ensure that the given base address
    /// really points to a serial port device.
    pub const unsafe fn new(base: u16) -> Self {
        Self {
            data: Port::new(base),
            int_en: PortWriteOnly::new(base + 1),
            fifo_ctrl: PortWriteOnly::new(base + 2),
            line_ctrl: PortWriteOnly::new(base + 3),
            modem_ctrl: PortWriteOnly::new(base + 4),
            // line_sts: PortReadOnly::new(base + 5),
        }
    }

    /// Initializes the serial port.
    ///
    /// The default configuration of [38400/8-N-1](https://en.wikipedia.org/wiki/8-N-1) is used.
    pub fn init(&mut self) {
        unsafe {
            // Disable interrupts
            self.int_en.write(0x00);

            // Enable DLAB
            self.line_ctrl.write(0x80);

            // Set maximum speed to 38400 bps by configuring DLL and DLM
            self.data.write(0x03);
            self.int_en.write(0x00);

            // Disable DLAB and set data word length to 8 bits
            self.line_ctrl.write(0x03);

            // Enable FIFO, clear TX/RX queues and
            // set interrupt watermark at 14 bytes
            self.fifo_ctrl.write(0xC7);

            // Mark data terminal ready, signal request to send
            // and enable auxilliary output #2 (used as interrupt line for CPU)
            self.modem_ctrl.write(0x0B);

            // Enable interrupts
            self.int_en.write(0x01);
        }
    }
}

pub fn init() {
    let mut serial_port = unsafe { SerialPort::new(0x3F8) };
    serial_port.init(); // Needed to enable serial/console interrupts.
}
