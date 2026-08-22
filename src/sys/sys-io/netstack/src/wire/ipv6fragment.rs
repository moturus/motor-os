use super::{Error, IpProtocol, Result};
use core::fmt;

use byteorder::{ByteOrder, NetworkEndian};

/// A read/write wrapper around an IPv6 Fragment Header.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Header<T: AsRef<[u8]>> {
    buffer: T,
}

// Format of the Fragment Header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Identification                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc8200#section-4.5 for details.
//
mod field {
    use crate::wire::field::*;

    pub const NEXT_HEADER: usize = 0;
    pub const RESERVED: usize = 1;
    // 16-bit field containing the fragment offset, reserved and more fragments values.
    pub const FR_OF_M: Field = 2..4;
    // 32-bit field identifying the fragmented packet
    pub const IDENT: Field = 4..8;
    /// 1 bit flag indicating if there are more fragments coming.
    pub const M: usize = 3;
}

impl<T: AsRef<[u8]>> Header<T> {
    /// Create a raw octet buffer with an IPv6 Fragment Header structure.
    pub const fn new_unchecked(buffer: T) -> Header<T> {
        Header { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Header<T>> {
        let header = Self::new_unchecked(buffer);
        header.check_len()?;
        Ok(header)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    pub fn check_len(&self) -> Result<()> {
        let data = self.buffer.as_ref();
        let len = data.len();

        if len < field::IDENT.end {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Consume the header, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the protocol contained in the fragmentable part.
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buffer.as_ref()[field::NEXT_HEADER])
    }

    /// Return whether either reserved field is nonzero.
    #[inline]
    pub fn has_nonzero_reserved(&self) -> bool {
        let data = self.buffer.as_ref();
        data[field::RESERVED] != 0 || data[field::M] & 0x06 != 0
    }

    /// Return the fragment offset field, in octets.
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FR_OF_M]) & 0xfff8
    }

    /// Return more fragment flag field.
    #[inline]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        (data[field::M] & 0x1) == 1
    }

    /// Return the fragment identification value field.
    #[inline]
    pub fn ident(&self) -> u32 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u32(&data[field::IDENT])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Header<T> {
    /// Set the protocol contained in the fragmentable part.
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buffer.as_mut()[field::NEXT_HEADER] = value.into();
    }

    /// Set reserved fields.
    ///
    /// Set 8-bit reserved field after the next header field.
    /// Set 2-bit reserved field between fragment offset and more fragments.
    #[inline]
    pub fn clear_reserved(&mut self) {
        let data = self.buffer.as_mut();
        data[field::RESERVED] = 0;
        data[field::M] &= 0xf9;
    }

    /// Set the fragment offset field, in octets.
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        // Retain the lower order 3 bits
        let raw = (value & 0xfff8) | ((data[field::M] & 0x7) as u16);
        NetworkEndian::write_u16(&mut data[field::FR_OF_M], raw);
    }

    /// Set the more fragments flag field.
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        // Retain the high order 7 bits
        let raw = (data[field::M] & 0xfe) | (value as u8 & 0x1);
        data[field::M] = raw;
    }

    /// Set the fragmentation identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u32(&mut data[field::IDENT], value);
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for Header<&T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match Repr::parse(self) {
            Ok(repr) => write!(f, "{repr}"),
            Err(err) => {
                write!(f, "IPv6 Fragment ({err})")?;
                Ok(())
            }
        }
    }
}

/// A high-level representation of an IPv6 Fragment header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Repr {
    /// The protocol contained in the fragmentable part.
    pub next_header: IpProtocol,
    /// The offset of the data following this header, relative to the start of the Fragmentable
    /// Part of the original packet.
    pub frag_offset: u16,
    /// When there are more fragments following this header
    pub more_frags: bool,
    /// The identification for every packet that is fragmented.
    pub ident: u32,
}

impl Repr {
    /// Parse an IPv6 Fragment Header and return a high-level representation.
    pub fn parse<T>(header: &Header<&T>) -> Result<Repr>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        header.check_len()?;
        if header.has_nonzero_reserved() {
            return Err(Error);
        }

        Ok(Repr {
            next_header: header.next_header(),
            frag_offset: header.frag_offset(),
            more_frags: header.more_frags(),
            ident: header.ident(),
        })
    }

    /// Return the length, in bytes, of a header that will be emitted from this high-level
    /// representation.
    pub const fn buffer_len(&self) -> usize {
        field::IDENT.end
    }

    /// Emit a high-level representation into an IPv6 Fragment Header.
    pub fn emit<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized>(&self, header: &mut Header<&mut T>) {
        header.set_next_header(self.next_header);
        header.clear_reserved();
        header.set_frag_offset(self.frag_offset);
        header.set_more_frags(self.more_frags);
        header.set_ident(self.ident);
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "IPv6 Fragment next-header={} offset={} more={} ident={}",
            self.next_header, self.frag_offset, self.more_frags, self.ident
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    static BYTES_HEADER_MORE_FRAG: [u8; 8] = [0x11, 0x00, 0x00, 0x01, 0x00, 0x00, 0x30, 0x39];
    static BYTES_HEADER_LAST_FRAG: [u8; 8] = [0x06, 0x00, 0x01, 0x40, 0x00, 0x01, 0x09, 0x32];

    #[test]
    fn test_check_len() {
        assert_eq!(
            Err(Error),
            Header::new_unchecked(&BYTES_HEADER_MORE_FRAG[..7]).check_len()
        );
        assert_eq!(
            Ok(()),
            Header::new_unchecked(&BYTES_HEADER_MORE_FRAG).check_len()
        );
    }

    #[test]
    fn test_header_deconstruct() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        assert_eq!(header.next_header(), IpProtocol::Udp);
        assert!(!header.has_nonzero_reserved());
        assert_eq!(header.frag_offset(), 0);
        assert!(header.more_frags());
        assert_eq!(header.ident(), 12345);

        let header = Header::new_unchecked(&BYTES_HEADER_LAST_FRAG);
        assert_eq!(header.next_header(), IpProtocol::Tcp);
        assert!(!header.has_nonzero_reserved());
        assert_eq!(header.frag_offset(), 320);
        assert!(!header.more_frags());
        assert_eq!(header.ident(), 67890);
    }

    #[test]
    fn test_repr_parse_validates_reserved_fields() {
        let header = Header::new_unchecked(&BYTES_HEADER_MORE_FRAG);
        assert_eq!(
            Repr::parse(&header),
            Ok(Repr {
                next_header: IpProtocol::Udp,
                frag_offset: 0,
                more_frags: true,
                ident: 12345,
            })
        );

        let mut bytes = BYTES_HEADER_MORE_FRAG;
        bytes[field::RESERVED] = 1;
        assert_eq!(Repr::parse(&Header::new_unchecked(&bytes)), Err(Error));

        let mut bytes = BYTES_HEADER_MORE_FRAG;
        bytes[field::M] |= 0x02;
        assert_eq!(Repr::parse(&Header::new_unchecked(&bytes)), Err(Error));
    }

    #[test]
    fn test_repr_emit() {
        let cases = [
            (
                Repr {
                    next_header: IpProtocol::Udp,
                    frag_offset: 0,
                    more_frags: true,
                    ident: 12345,
                },
                BYTES_HEADER_MORE_FRAG,
            ),
            (
                Repr {
                    next_header: IpProtocol::Tcp,
                    frag_offset: 320,
                    more_frags: false,
                    ident: 67890,
                },
                BYTES_HEADER_LAST_FRAG,
            ),
        ];

        for (repr, expected) in cases {
            let mut bytes = [0xa5; 8];
            let mut header = Header::new_unchecked(&mut bytes);
            repr.emit(&mut header);
            assert_eq!(header.into_inner(), &expected);
            assert_eq!(repr.buffer_len(), expected.len());
        }
    }
}
