#![allow(unused)]

use core::fmt;

use managed::{ManagedMap, ManagedSlice};

use crate::config::{FRAGMENTATION_BUFFER_SIZE, REASSEMBLY_BUFFER_COUNT, REASSEMBLY_BUFFER_SIZE};
use crate::storage::Assembler;
use crate::time::{Duration, Instant};
use crate::wire::*;

use core::result::Result;

type Buffer = alloc::vec::Vec<u8>;

/// Result of adding information to a packet assembly.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum AssemblerOutcome {
    Incomplete,
    Complete,
    Duplicate,
}

/// Reason a packet assembly was rejected.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum AssemblerError {
    Invalid,
    SizeLimit,
    FinalSize,
    Overlap,
    RangeLimit,
    Allocation,
    Poisoned,
}

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AssemblerError {}

/// Packet assembler is full.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerFullError;

impl fmt::Display for AssemblerFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerFullError")
    }
}

impl std::error::Error for AssemblerFullError {}

/// Assemblies reclaimed after reaching their deadline.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpirationOutcome {
    pub(crate) incomplete: usize,
    pub(crate) poisoned: usize,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ipv4ReassemblyContext {
    pub(crate) repr: Ipv4Repr,
    pub(crate) header_len: usize,
}

#[cfg(feature = "proto-ipv6-fragmentation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Ipv6FragKey {
    pub(crate) src_addr: Ipv6Address,
    pub(crate) dst_addr: Ipv6Address,
    pub(crate) ident: u32,
}

#[cfg(feature = "proto-ipv6-fragmentation")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ipv6ReassemblyContext {
    pub(crate) repr: Option<Ipv6Repr>,
    pub(crate) next_header: IpProtocol,
    pub(crate) unfragmentable_len: usize,
}

/// Holds the bounded state for one fragmented packet.
#[derive(Debug)]
pub struct PacketAssembler<K> {
    key: Option<K>,
    buffer: Buffer,
    assembler: Assembler,
    total_size: Option<usize>,
    expires_at: Instant,
    poisoned: bool,
    #[cfg(feature = "proto-ipv4-fragmentation")]
    ipv4_context: Option<Ipv4ReassemblyContext>,
    #[cfg(feature = "proto-ipv6-fragmentation")]
    ipv6_context: Option<Ipv6ReassemblyContext>,
}

impl<K> PacketAssembler<K> {
    /// Create a new empty fragment buffer.
    pub const fn new() -> Self {
        Self {
            key: None,
            buffer: Buffer::new(),
            assembler: Assembler::new(),
            total_size: None,
            expires_at: Instant::ZERO,
            poisoned: false,
            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4_context: None,
            #[cfg(feature = "proto-ipv6-fragmentation")]
            ipv6_context: None,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.key = None;
        self.assembler.clear();
        self.total_size = None;
        self.expires_at = Instant::ZERO;
        self.poisoned = false;
        #[cfg(feature = "proto-ipv4-fragmentation")]
        {
            self.ipv4_context = None;
        }
        #[cfg(feature = "proto-ipv6-fragmentation")]
        {
            self.ipv6_context = None;
        }
    }

    fn outcome(&self) -> AssemblerOutcome {
        if self.is_complete() {
            AssemblerOutcome::Complete
        } else {
            AssemblerOutcome::Incomplete
        }
    }

    fn reject(&mut self, error: AssemblerError) -> AssemblerError {
        if self.assembler.is_empty() {
            self.reset();
        } else {
            self.assembler.clear();
            self.buffer.clear();
            self.total_size = None;
            self.poisoned = true;
            #[cfg(feature = "proto-ipv4-fragmentation")]
            {
                self.ipv4_context = None;
            }
            #[cfg(feature = "proto-ipv6-fragmentation")]
            {
                self.ipv6_context = None;
            }
        }
        error
    }

    fn reject_existing(&mut self, error: AssemblerError) -> AssemblerError {
        if self.poisoned {
            AssemblerError::Poisoned
        } else {
            self.reject(error)
        }
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(crate) fn set_ipv4_context(&mut self, context: Ipv4ReassemblyContext) {
        if self.ipv4_context.is_none() {
            self.ipv4_context = Some(context);
        }
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(crate) fn ipv4_context(&self) -> Option<Ipv4ReassemblyContext> {
        self.ipv4_context
    }

    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fn observe_ipv6_context(
        &mut self,
        repr: Ipv6Repr,
        next_header: IpProtocol,
        unfragmentable_len: usize,
        is_first: bool,
    ) -> Result<(), AssemblerError> {
        if self.poisoned {
            return Err(AssemblerError::Poisoned);
        }

        if self.ipv6_context.is_some_and(|context| {
            context.next_header != next_header || context.unfragmentable_len != unfragmentable_len
        }) {
            return Err(self.reject(AssemblerError::Invalid));
        }

        let context = self.ipv6_context.get_or_insert(Ipv6ReassemblyContext {
            repr: None,
            next_header,
            unfragmentable_len,
        });
        if is_first && context.repr.is_none() {
            context.repr = Some(repr);
        }
        Ok(())
    }

    #[cfg(feature = "proto-ipv6-fragmentation")]
    pub(crate) fn ipv6_context(&self) -> Option<Ipv6ReassemblyContext> {
        self.ipv6_context
    }

    pub(crate) fn enforce_max_size(
        &mut self,
        max_size: usize,
        incoming_end: usize,
    ) -> Result<(), AssemblerError> {
        if self.poisoned {
            return Err(AssemblerError::Poisoned);
        }
        if incoming_end > max_size
            || self.total_size.is_some_and(|size| size > max_size)
            || self.assembler.iter_data().any(|(_, end)| end > max_size)
        {
            return Err(self.reject(AssemblerError::SizeLimit));
        }
        Ok(())
    }

    fn ensure_len(&mut self, len: usize) -> Result<(), AssemblerError> {
        if len > REASSEMBLY_BUFFER_SIZE {
            return Err(self.reject(AssemblerError::SizeLimit));
        }
        if self.buffer.len() < len {
            if self
                .buffer
                .try_reserve_exact(len - self.buffer.len())
                .is_err()
            {
                return Err(self.reject(AssemblerError::Allocation));
            }
            self.buffer.resize(len, 0);
        }
        Ok(())
    }

    /// Set the final size claimed by the last fragment.
    pub(crate) fn set_total_size(
        &mut self,
        size: usize,
    ) -> Result<AssemblerOutcome, AssemblerError> {
        if self.poisoned {
            return Err(AssemblerError::Poisoned);
        }
        if let Some(old_size) = self.total_size
            && old_size != size
        {
            return Err(self.reject(AssemblerError::FinalSize));
        }
        if self.assembler.iter_data().any(|(_, end)| end > size) {
            return Err(self.reject(AssemblerError::FinalSize));
        }

        self.ensure_len(size)?;
        self.total_size = Some(size);
        Ok(self.outcome())
    }

    /// Return the instant when the assembler expires.
    pub(crate) fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Produce and add a fragment without exposing the assembly buffer.
    pub(crate) fn add_with(
        &mut self,
        offset: usize,
        f: impl Fn(&mut [u8]) -> Result<usize, AssemblerError>,
    ) -> Result<AssemblerOutcome, AssemblerError> {
        if self.poisoned {
            return Err(AssemblerError::Poisoned);
        }
        let Some(available) = self.buffer.len().checked_sub(offset) else {
            return Err(self.reject(AssemblerError::SizeLimit));
        };

        if self.assembler.is_empty() {
            let len = match f(&mut self.buffer[offset..]) {
                Ok(len) if len <= available => len,
                Ok(_) => return Err(self.reject(AssemblerError::SizeLimit)),
                Err(error) => return Err(self.reject(error)),
            };
            let end = offset + len;
            if self.total_size.is_some_and(|size| end > size) {
                return Err(self.reject(AssemblerError::FinalSize));
            }
            if self.assembler.add(offset, len).is_err() {
                return Err(self.reject(AssemblerError::RangeLimit));
            }
            return Ok(self.outcome());
        }

        // Isolate the producer from bytes accepted earlier so duplicates keep
        // the first arrival. This compatibility path is used by 6LoWPAN only.
        let mut scratch = Buffer::new();
        if scratch.try_reserve_exact(available).is_err() {
            return Err(self.reject(AssemblerError::Allocation));
        }
        scratch.resize(available, 0);
        let len = match f(&mut scratch) {
            Ok(len) if len <= available => len,
            Ok(_) => return Err(self.reject(AssemblerError::SizeLimit)),
            Err(error) => return Err(self.reject(error)),
        };
        self.add(&scratch[..len], offset)
    }

    /// Add a fragment while preserving bytes from the first arrival.
    pub(crate) fn add(
        &mut self,
        data: &[u8],
        offset: usize,
    ) -> Result<AssemblerOutcome, AssemblerError> {
        if self.poisoned {
            return Err(AssemblerError::Poisoned);
        }
        let Some(end) = offset.checked_add(data.len()) else {
            return Err(self.reject(AssemblerError::SizeLimit));
        };
        if self.total_size.is_some_and(|size| end > size) {
            return Err(self.reject(AssemblerError::FinalSize));
        }

        match self.range_relation(offset, end) {
            RangeRelation::Duplicate => return Ok(AssemblerOutcome::Duplicate),
            RangeRelation::Overlap => return Err(self.reject(AssemblerError::Overlap)),
            RangeRelation::Disjoint => {}
        }

        self.ensure_len(end)?;
        if self.assembler.add(offset, data.len()).is_err() {
            return Err(self.reject(AssemblerError::RangeLimit));
        }
        self.buffer[offset..end].copy_from_slice(data);

        net_debug!(
            "frag assembler: receiving {} octets at offset {}",
            data.len(),
            offset
        );
        Ok(self.outcome())
    }

    fn range_relation(&self, offset: usize, end: usize) -> RangeRelation {
        for (received_start, received_end) in self.assembler.iter_data() {
            if received_start <= offset && end <= received_end {
                return RangeRelation::Duplicate;
            }
            if offset < received_end && received_start < end {
                return RangeRelation::Overlap;
            }
        }
        RangeRelation::Disjoint
    }

    /// Get the packet data if reassembly is complete, freeing its slot.
    pub(crate) fn assemble(&mut self) -> Option<&'_ [u8]> {
        if !self.is_complete() {
            return None;
        }

        let total_size = self.total_size.unwrap();
        self.reset();
        Some(&self.buffer[..total_size])
    }

    /// Return whether every byte through the agreed final size is present.
    pub(crate) fn is_complete(&self) -> bool {
        !self.poisoned && self.total_size == Some(self.assembler.peek_front())
    }

    /// Return whether the packet assembler is free to use.
    fn is_free(&self) -> bool {
        self.key.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeRelation {
    Disjoint,
    Duplicate,
    Overlap,
}

/// Set holding multiple [`PacketAssembler`].
#[derive(Debug)]
pub struct PacketAssemblerSet<K: Eq + Copy> {
    assemblers: [PacketAssembler<K>; REASSEMBLY_BUFFER_COUNT],
}

impl<K: Eq + Copy> PacketAssemblerSet<K> {
    const NEW_PA: PacketAssembler<K> = PacketAssembler::new();

    /// Create a new set of packet assemblers.
    pub fn new() -> Self {
        Self {
            assemblers: [Self::NEW_PA; REASSEMBLY_BUFFER_COUNT],
        }
    }

    /// Get a [`PacketAssembler`] for a specific key.
    ///
    /// If it doesn't exist, it is created, with the `expires_at` timestamp.
    ///
    /// If the assembler set is full, in which case an error is returned.
    pub(crate) fn get(
        &mut self,
        key: &K,
        expires_at: Instant,
    ) -> Result<&mut PacketAssembler<K>, AssemblerFullError> {
        let mut empty_slot = None;
        for slot in &mut self.assemblers {
            if slot.key.as_ref() == Some(key) {
                return Ok(slot);
            }
            if slot.is_free() && empty_slot.is_none() {
                empty_slot = Some(slot)
            }
        }

        let slot = empty_slot.ok_or(AssemblerFullError)?;
        slot.key = Some(*key);
        slot.expires_at = expires_at;
        Ok(slot)
    }

    /// Reject a fragment without allocating state for a new key.
    pub(crate) fn reject_existing(&mut self, key: &K, error: AssemblerError) -> AssemblerError {
        self.assemblers
            .iter_mut()
            .find(|slot| slot.key.as_ref() == Some(key))
            .map_or(error, |slot| slot.reject_existing(error))
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.assemblers
            .iter()
            .any(|slot| slot.key.as_ref() == Some(key))
    }

    /// Remove expired assemblers and classify the reclaimed state.
    pub fn remove_expired(&mut self, timestamp: Instant) -> ExpirationOutcome {
        let mut outcome = ExpirationOutcome::default();
        for frag in &mut self.assemblers {
            if !frag.is_free() && frag.expires_at < timestamp {
                if frag.poisoned {
                    outcome.poisoned += 1;
                } else {
                    outcome.incomplete += 1;
                }
                frag.reset();
            }
        }
        outcome
    }
}

// Max len of non-fragmented packets after decompression (including ipv6 header and payload)
// TODO: lower. Should be (6lowpan mtu) - (min 6lowpan header size) + (max ipv6 header size)
pub(crate) const MAX_DECOMPRESSED_LEN: usize = 1500;

#[cfg(feature = "_proto-fragmentation")]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum FragKey {
    #[cfg(feature = "proto-ipv4-fragmentation")]
    Ipv4(Ipv4FragKey),
    #[cfg(feature = "proto-ipv6-fragmentation")]
    Ipv6(Ipv6FragKey),
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    Sixlowpan(SixlowpanFragKey),
}

pub(crate) struct FragmentsBuffer {
    #[cfg(feature = "proto-sixlowpan")]
    pub decompress_buf: [u8; MAX_DECOMPRESSED_LEN],

    #[cfg(feature = "_proto-fragmentation")]
    pub assembler: PacketAssemblerSet<FragKey>,

    #[cfg(feature = "_proto-fragmentation")]
    pub reassembly_timeout: Duration,
}

#[cfg(not(feature = "_proto-fragmentation"))]
pub(crate) struct Fragmenter {}

#[cfg(not(feature = "_proto-fragmentation"))]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[cfg(feature = "_proto-fragmentation")]
pub(crate) struct Fragmenter {
    /// The buffer that holds the unfragmented 6LoWPAN packet.
    pub buffer: [u8; FRAGMENTATION_BUFFER_SIZE],
    /// The size of the packet without the IEEE802.15.4 header and the fragmentation headers.
    pub packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    pub sent_bytes: usize,

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub ipv4: Ipv4Fragmenter,
    #[cfg(feature = "proto-sixlowpan-fragmentation")]
    pub sixlowpan: SixlowpanFragmenter,
}

#[cfg(feature = "proto-ipv4-fragmentation")]
pub(crate) struct Ipv4Fragmenter {
    /// The IPv4 representation.
    pub repr: Ipv4Repr,
    /// The destination hardware address.
    #[cfg(feature = "medium-ethernet")]
    pub dst_hardware_addr: EthernetAddress,
    /// The offset of the next fragment.
    pub frag_offset: u16,
    /// The identifier of the stream.
    pub ident: u16,
}

#[cfg(feature = "proto-sixlowpan-fragmentation")]
pub(crate) struct SixlowpanFragmenter {
    /// The datagram size that is used for the fragmentation headers.
    pub datagram_size: u16,
    /// The datagram tag that is used for the fragmentation headers.
    pub datagram_tag: u16,
    pub datagram_offset: usize,

    /// The size of the FRAG_N packets.
    pub fragn_size: usize,

    /// The link layer IEEE802.15.4 source address.
    pub ll_dst_addr: Ieee802154Address,
    /// The link layer IEEE802.15.4 source address.
    pub ll_src_addr: Ieee802154Address,
}

#[cfg(feature = "_proto-fragmentation")]
impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {
            buffer: [0u8; FRAGMENTATION_BUFFER_SIZE],
            packet_len: 0,
            sent_bytes: 0,

            #[cfg(feature = "proto-ipv4-fragmentation")]
            ipv4: Ipv4Fragmenter {
                repr: Ipv4Repr {
                    src_addr: Ipv4Address::new(0, 0, 0, 0),
                    dst_addr: Ipv4Address::new(0, 0, 0, 0),
                    next_header: IpProtocol::Unknown(0),
                    payload_len: 0,
                    hop_limit: 0,
                },
                #[cfg(feature = "medium-ethernet")]
                dst_hardware_addr: EthernetAddress::default(),
                frag_offset: 0,
                ident: 0,
            },

            #[cfg(feature = "proto-sixlowpan-fragmentation")]
            sixlowpan: SixlowpanFragmenter {
                datagram_size: 0,
                datagram_tag: 0,
                datagram_offset: 0,
                fragn_size: 0,
                ll_dst_addr: Ieee802154Address::Absent,
                ll_src_addr: Ieee802154Address::Absent,
            },
        }
    }

    /// Return `true` when everything is transmitted.
    #[inline]
    pub(crate) fn finished(&self) -> bool {
        self.packet_len == self.sent_bytes
    }

    /// Returns `true` when there is nothing to transmit.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.packet_len == 0
    }

    // Reset the buffer.
    pub(crate) fn reset(&mut self) {
        self.packet_len = 0;
        self.sent_bytes = 0;

        #[cfg(feature = "proto-ipv4-fragmentation")]
        {
            self.ipv4.repr = Ipv4Repr {
                src_addr: Ipv4Address::new(0, 0, 0, 0),
                dst_addr: Ipv4Address::new(0, 0, 0, 0),
                next_header: IpProtocol::Unknown(0),
                payload_len: 0,
                hop_limit: 0,
            };
            #[cfg(feature = "medium-ethernet")]
            {
                self.ipv4.dst_hardware_addr = EthernetAddress::default();
            }
        }

        #[cfg(feature = "proto-sixlowpan-fragmentation")]
        {
            self.sixlowpan.datagram_size = 0;
            self.sixlowpan.datagram_tag = 0;
            self.sixlowpan.fragn_size = 0;
            self.sixlowpan.ll_dst_addr = Ieee802154Address::Absent;
            self.sixlowpan.ll_src_addr = Ieee802154Address::Absent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ASSEMBLER_MAX_SEGMENT_COUNT;

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    struct Key(usize);

    #[test]
    fn packet_assembler_reports_progress_and_assembles_out_of_order() {
        let mut assembler = PacketAssembler::<Key>::new();
        assert_eq!(
            assembler.set_total_size(12),
            Ok(AssemblerOutcome::Incomplete)
        );
        assert_eq!(
            assembler.add(b"World!", 6),
            Ok(AssemblerOutcome::Incomplete)
        );
        assert_eq!(assembler.assemble(), None);
        assert_eq!(assembler.add(b"Hello ", 0), Ok(AssemblerOutcome::Complete));
        assert_eq!(assembler.assemble(), Some(&b"Hello World!"[..]));
    }

    #[test]
    fn packet_assembler_ignores_contained_duplicates_first_arrival_wins() {
        let mut assembler = PacketAssembler::<Key>::new();
        assembler.set_total_size(6).unwrap();
        assert_eq!(
            assembler.add_with(0, |buffer| {
                buffer[..4].copy_from_slice(b"Rust");
                Ok(4)
            }),
            Ok(AssemblerOutcome::Incomplete)
        );
        assert_eq!(assembler.add(b"XXXX", 0), Ok(AssemblerOutcome::Duplicate));
        assert_eq!(
            assembler.add_with(1, |scratch| {
                scratch[..2].copy_from_slice(b"YY");
                Ok(2)
            }),
            Ok(AssemblerOutcome::Duplicate)
        );
        assert_eq!(assembler.add(b"!!", 4), Ok(AssemblerOutcome::Complete));
        assert_eq!(assembler.assemble(), Some(&b"Rust!!"[..]));
    }

    #[test]
    fn packet_assembler_partial_overlap_poison_is_a_tombstone() {
        let key = Key(1);
        let expiry = Instant::from_secs(10);
        let mut set = PacketAssemblerSet::new();

        let assembler = set.get(&key, expiry).unwrap();
        assembler.set_total_size(6).unwrap();
        assembler.add(b"Rust", 0).unwrap();
        assert_eq!(assembler.add(b"XX", 3), Err(AssemblerError::Overlap));
        assert!(assembler.poisoned);
        assert!(assembler.buffer.is_empty());

        let assembler = set.get(&key, Instant::from_secs(20)).unwrap();
        assert_eq!(assembler.expires_at(), expiry);
        assert_eq!(assembler.add(b"new", 0), Err(AssemblerError::Poisoned));
    }

    #[test]
    fn packet_assembler_rejects_inconsistent_final_sizes() {
        let mut assembler = PacketAssembler::<Key>::new();
        assembler.add(b"late", 4).unwrap();
        assert_eq!(assembler.set_total_size(7), Err(AssemblerError::FinalSize));
        assert!(assembler.poisoned);

        let mut assembler = PacketAssembler::<Key>::new();
        assembler.set_total_size(4).unwrap();
        assert_eq!(assembler.add(b"XX", 3), Err(AssemblerError::FinalSize));
        assert!(!assembler.poisoned);

        let mut assembler = PacketAssembler::<Key>::new();
        assembler.add(b"data", 0).unwrap();
        assembler.set_total_size(6).unwrap();
        assert_eq!(assembler.set_total_size(7), Err(AssemblerError::FinalSize));
        assert!(assembler.poisoned);
    }

    #[test]
    fn packet_assembler_enforces_byte_and_offset_bounds() {
        let mut assembler = PacketAssembler::<Key>::new();
        assert_eq!(
            assembler.add(&[1], REASSEMBLY_BUFFER_SIZE - 1),
            Ok(AssemblerOutcome::Incomplete)
        );
        assert_eq!(assembler.buffer.len(), REASSEMBLY_BUFFER_SIZE);

        let mut assembler = PacketAssembler::<Key>::new();
        assert_eq!(
            assembler.add(&[1], REASSEMBLY_BUFFER_SIZE),
            Err(AssemblerError::SizeLimit)
        );
        assert!(assembler.buffer.is_empty());
        assert_eq!(
            assembler.add(&[1], usize::MAX),
            Err(AssemblerError::SizeLimit)
        );
    }

    #[test]
    fn packet_assembler_enforces_a_late_protocol_size_limit() {
        let mut assembler = PacketAssembler::<Key>::new();
        assembler.add(b"data", 8).unwrap();
        assembler.set_total_size(12).unwrap();

        assert_eq!(
            assembler.enforce_max_size(10, 8),
            Err(AssemblerError::SizeLimit)
        );
        assert!(assembler.poisoned);
        assert!(assembler.buffer.is_empty());
    }

    #[test]
    #[cfg(feature = "proto-ipv6-fragmentation")]
    fn packet_assembler_retains_ipv6_offset_zero_context() {
        let mut assembler = PacketAssembler::<Key>::new();
        let mut repr = Ipv6Repr {
            src_addr: Ipv6Address::LOCALHOST,
            dst_addr: Ipv6Address::UNSPECIFIED,
            next_header: IpProtocol::Ipv6Frag,
            payload_len: 16,
            hop_limit: 64,
        };

        assembler
            .observe_ipv6_context(repr, IpProtocol::Udp, 0, false)
            .unwrap();
        assert_eq!(assembler.ipv6_context().unwrap().repr, None);

        repr.hop_limit = 63;
        assembler
            .observe_ipv6_context(repr, IpProtocol::Udp, 0, true)
            .unwrap();
        assert_eq!(assembler.ipv6_context().unwrap().repr, Some(repr));

        let retained = repr;
        repr.hop_limit = 62;
        assembler
            .observe_ipv6_context(repr, IpProtocol::Udp, 0, true)
            .unwrap();
        assert_eq!(assembler.ipv6_context().unwrap().repr, Some(retained));
    }

    #[test]
    #[cfg(feature = "proto-ipv6-fragmentation")]
    fn packet_assembler_poisoned_by_ipv6_context_mismatch() {
        let mut assembler = PacketAssembler::<Key>::new();
        let repr = Ipv6Repr {
            src_addr: Ipv6Address::LOCALHOST,
            dst_addr: Ipv6Address::UNSPECIFIED,
            next_header: IpProtocol::Ipv6Frag,
            payload_len: 16,
            hop_limit: 64,
        };
        assembler
            .observe_ipv6_context(repr, IpProtocol::Udp, 0, false)
            .unwrap();
        assembler.add(b"fragment", 8).unwrap();

        assert_eq!(
            assembler.observe_ipv6_context(repr, IpProtocol::Tcp, 0, true),
            Err(AssemblerError::Invalid)
        );
        assert!(assembler.poisoned);
        assert_eq!(
            assembler.observe_ipv6_context(repr, IpProtocol::Udp, 0, true),
            Err(AssemblerError::Poisoned)
        );
    }

    #[test]
    fn packet_assembler_poisoned_on_the_range_limit() {
        let mut assembler = PacketAssembler::<Key>::new();
        for range in 0..ASSEMBLER_MAX_SEGMENT_COUNT {
            assert_eq!(
                assembler.add(&[range as u8], range * 2),
                Ok(AssemblerOutcome::Incomplete)
            );
        }
        assert_eq!(
            assembler.add(&[0], ASSEMBLER_MAX_SEGMENT_COUNT * 2),
            Err(AssemblerError::RangeLimit)
        );
        assert!(assembler.poisoned);
        assert!(assembler.buffer.is_empty());
        assert_eq!(assembler.add(&[0], 0), Err(AssemblerError::Poisoned));
    }

    #[test]
    fn packet_assembler_set_is_bounded_and_reuses_completed_slots() {
        let mut set = PacketAssemblerSet::new();
        for id in 0..REASSEMBLY_BUFFER_COUNT {
            set.get(&Key(id), Instant::ZERO).unwrap();
        }
        assert_eq!(
            set.get(&Key(REASSEMBLY_BUFFER_COUNT), Instant::ZERO)
                .map(|_| ()),
            Err(AssemblerFullError)
        );

        let assembler = set.get(&Key(0), Instant::ZERO).unwrap();
        assembler.set_total_size(2).unwrap();
        assembler.add(b"ok", 0).unwrap();
        assert_eq!(assembler.assemble(), Some(&b"ok"[..]));
        assert!(
            set.get(&Key(REASSEMBLY_BUFFER_COUNT), Instant::ZERO)
                .is_ok()
        );
    }

    #[test]
    fn packet_assembler_set_uses_first_free_slot() {
        let mut set = PacketAssemblerSet::new();
        set.get(&Key(1), Instant::ZERO).unwrap();
        set.get(&Key(2), Instant::ZERO).unwrap();

        assert_eq!(set.assemblers[0].key, Some(Key(1)));
        assert_eq!(set.assemblers[1].key, Some(Key(2)));
        assert!(set.assemblers[2..].iter().all(PacketAssembler::is_free));
    }

    #[test]
    fn packet_assembler_invalid_first_fragment_retains_no_state() {
        let mut set = PacketAssemblerSet::new();
        for id in 0..REASSEMBLY_BUFFER_COUNT {
            let assembler = set.get(&Key(id), Instant::from_secs(10)).unwrap();
            assert_eq!(
                assembler.add(&[0], REASSEMBLY_BUFFER_SIZE),
                Err(AssemblerError::SizeLimit)
            );
        }
        assert!(set.assemblers.iter().all(PacketAssembler::is_free));
    }

    #[test]
    fn packet_assembler_expiry_classifies_incomplete_state() {
        let expiry = Instant::from_secs(10);
        let mut set = PacketAssemblerSet::new();
        set.get(&Key(1), expiry).unwrap().add(b"data", 0).unwrap();

        assert_eq!(set.remove_expired(expiry), ExpirationOutcome::default());
        assert_eq!(
            set.remove_expired(expiry + Duration::from_millis(1)),
            ExpirationOutcome {
                incomplete: 1,
                poisoned: 0,
            }
        );
        assert!(set.get(&Key(2), expiry).is_ok());
    }

    #[test]
    fn packet_assembler_tombstone_expires_and_is_reusable() {
        let key = Key(1);
        let expiry = Instant::from_secs(10);
        let mut set = PacketAssemblerSet::new();
        let assembler = set.get(&key, expiry).unwrap();
        assembler.add(b"data", 0).unwrap();
        assert_eq!(assembler.add(b"XX", 3), Err(AssemblerError::Overlap));

        assert_eq!(set.remove_expired(expiry), ExpirationOutcome::default());
        assert_eq!(
            set.get(&key, Instant::from_secs(20))
                .unwrap()
                .add(b"new", 0),
            Err(AssemblerError::Poisoned)
        );
        assert_eq!(
            set.remove_expired(expiry + Duration::from_millis(1)),
            ExpirationOutcome {
                incomplete: 0,
                poisoned: 1,
            }
        );
        assert_eq!(
            set.get(&key, Instant::from_secs(20))
                .unwrap()
                .add(b"new", 0),
            Ok(AssemblerOutcome::Incomplete)
        );
    }
}
