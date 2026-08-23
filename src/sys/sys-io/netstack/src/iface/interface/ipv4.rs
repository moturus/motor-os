use super::*;

#[cfg(feature = "proto-ipv4-fragmentation")]
const IPV4_FRAGMENT_ID_BUCKETS: usize = 256;

#[cfg(feature = "proto-ipv4-fragmentation")]
pub(super) struct Ipv4FragmentIds {
    key: SipHasher24,
    counters: [u16; IPV4_FRAGMENT_ID_BUCKETS],
    initialized: [u64; IPV4_FRAGMENT_ID_BUCKETS / u64::BITS as usize],
}

#[cfg(feature = "proto-ipv4-fragmentation")]
impl Ipv4FragmentIds {
    pub(super) const fn new(key: [u8; 16]) -> Self {
        Self {
            key: SipHasher24::new(key),
            counters: [0; IPV4_FRAGMENT_ID_BUCKETS],
            initialized: [0; IPV4_FRAGMENT_ID_BUCKETS / u64::BITS as usize],
        }
    }

    pub(super) fn next(
        &mut self,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        protocol: IpProtocol,
    ) -> u16 {
        let mut tuple = [0_u8; 10];
        tuple[1..5].copy_from_slice(&src_addr.octets());
        tuple[5..9].copy_from_slice(&dst_addr.octets());
        tuple[9] = protocol.into();
        let bucket = self.key.hash(&tuple) as u8 as usize;
        let word = bucket / u64::BITS as usize;
        let bit = 1_u64 << (bucket % u64::BITS as usize);

        if self.initialized[word] & bit == 0 {
            let initial = self.key.hash(&[1, bucket as u8]) as u16;
            self.counters[bucket] = if initial == 0 { 1 } else { initial };
            self.initialized[word] |= bit;
        }

        let ident = self.counters[bucket];
        self.counters[bucket] = ident.wrapping_add(1);
        ident
    }
}

#[cfg(all(test, feature = "proto-ipv4-fragmentation"))]
mod fragment_id_tests {
    use super::*;

    const KEY: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn bucket(
        ids: &Ipv4FragmentIds,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        protocol: IpProtocol,
    ) -> usize {
        let mut tuple = [0_u8; 10];
        tuple[1..5].copy_from_slice(&src_addr.octets());
        tuple[5..9].copy_from_slice(&dst_addr.octets());
        tuple[9] = protocol.into();
        ids.key.hash(&tuple) as u8 as usize
    }

    #[test]
    fn fragment_ids_follow_the_keyed_lazy_bucket_contract() {
        let src_addr = Ipv4Address::new(192, 0, 2, 1);
        let dst_addr = Ipv4Address::new(198, 51, 100, 9);
        let mut ids = Ipv4FragmentIds::new(KEY);

        let bucket_index = ids.key.hash(&[0, 192, 0, 2, 1, 198, 51, 100, 9, 17]) as u8 as usize;
        let raw_initial = ids.key.hash(&[1, bucket_index as u8]) as u16;
        let initial = if raw_initial == 0 { 1 } else { raw_initial };
        assert_eq!(ids.next(src_addr, dst_addr, IpProtocol::Udp), initial);
        assert_eq!(
            ids.next(src_addr, dst_addr, IpProtocol::Udp),
            initial.wrapping_add(1)
        );
        assert_eq!(
            ids.initialized
                .iter()
                .map(|word| word.count_ones())
                .sum::<u32>(),
            1
        );

        let collision = (0..=u16::MAX)
            .map(|tail| Ipv4Address::new(203, 0, (tail >> 8) as u8, tail as u8))
            .find(|candidate| bucket(&ids, src_addr, *candidate, IpProtocol::Udp) == bucket_index)
            .expect("the exhaustive candidate set has no bucket collision");
        assert_eq!(
            ids.next(src_addr, collision, IpProtocol::Udp),
            initial.wrapping_add(2)
        );

        ids.counters[bucket_index] = u16::MAX;
        assert_eq!(ids.next(src_addr, dst_addr, IpProtocol::Udp), u16::MAX);
        assert_eq!(ids.next(src_addr, dst_addr, IpProtocol::Udp), 0);
    }
}

#[cfg(feature = "proto-ipv4-fragmentation")]
fn validate_ipv4_fragment(packet: &Ipv4Packet<&[u8]>) -> Result<(), AssemblerError> {
    let payload = packet.payload();
    let offset = packet.frag_offset() as usize;

    if packet.reserved() || packet.dont_frag() {
        return Err(AssemblerError::Invalid);
    }
    if packet.more_frags() && (payload.is_empty() || !payload.len().is_multiple_of(8)) {
        return Err(AssemblerError::Invalid);
    }

    let end = offset
        .checked_add(payload.len())
        .ok_or(AssemblerError::SizeLimit)?;
    let header_len = if offset == 0 {
        packet.header_len() as usize
    } else {
        IPV4_HEADER_LEN
    };
    if end > u16::MAX as usize - header_len {
        return Err(AssemblerError::SizeLimit);
    }

    if offset == 0 && packet.more_frags() {
        let header_complete = match packet.next_header() {
            IpProtocol::Tcp => TcpPacket::new_checked(payload).is_ok(),
            IpProtocol::Udp | IpProtocol::Icmp => payload.len() >= UDP_HEADER_LEN,
            _ => true,
        };
        if !header_complete {
            return Err(AssemblerError::Invalid);
        }
    }

    Ok(())
}

impl Interface {
    /// Process fragments that still need to be sent for IPv4 packets.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(super) fn ipv4_egress(&mut self, device: &mut (impl Device + ?Sized)) -> bool {
        // Reset the buffer when we transmitted everything.
        if self.fragmenter.finished() {
            self.fragmenter.reset();
        }

        if self.fragmenter.is_empty() {
            return false;
        }

        let repr = self.fragmenter.ipv4.repr;
        let path_mtu = self.inner.ip_mtu_for(repr.dst_addr.into());
        if path_mtu < self.fragmenter.ipv4.path_mtu {
            self.fragmenter.sent_bytes = 0;
            self.fragmenter.ipv4.frag_offset = 0;
            self.fragmenter.ipv4.path_mtu = path_mtu;
            self.fragmenter.ipv4.ident =
                self.inner
                    .ipv4_fragment_ids
                    .next(repr.src_addr, repr.dst_addr, repr.next_header);
        }

        let pkt = &self.fragmenter;
        if pkt.packet_len > pkt.sent_bytes
            && let Some(tx_token) = device.transmit(self.inner.now)
        {
            self.inner
                .dispatch_ipv4_frag(tx_token, &mut self.fragmenter);
            if self.fragmenter.finished() {
                self.fragmenter.reset();
            }
            return true;
        }

        false
    }
}

impl InterfaceInner {
    /// Get an IPv4 source address based on a destination address.
    ///
    /// This function tries to find the first IPv4 address from the interface
    /// that is in the same subnet as the destination address. If no such
    /// address is found, the first IPv4 address from the interface is returned.
    #[allow(unused)]
    pub(crate) fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        let mut first_ipv4 = None;
        for cidr in self.ip_addrs.iter() {
            #[allow(irrefutable_let_patterns)] // if only ipv4 is enabled
            if let IpCidr::Ipv4(cidr) = cidr {
                // Return immediately if we find an address in the same subnet
                if cidr.contains_addr(dst_addr) {
                    return Some(cidr.address());
                }

                // Remember the first IPv4 address as fallback
                if first_ipv4.is_none() {
                    first_ipv4 = Some(cidr.address());
                }
            }
        }
        first_ipv4
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    pub(crate) fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        if address.is_broadcast() {
            return true;
        }

        self.ip_addrs
            .iter()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                #[cfg(feature = "proto-ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.x_is_unicast() && !self.is_broadcast_v4(address)
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    fn accepts_ipv4_fragment_destination(&self, address: Ipv4Address) -> bool {
        self.has_ip_addr(address)
            || self.has_multicast_group(address)
            || self.is_broadcast_v4(address)
            || (address.x_is_unicast()
                && self
                    .routes
                    .lookup(&IpAddress::Ipv4(address), self.now)
                    .is_some_and(|router_addr| self.has_ip_addr(router_addr)))
    }

    /// Get the first IPv4 address of the interface.
    pub fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.ip_addrs.iter().find_map(|addr| match *addr {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    pub(super) fn process_ipv4<'a>(
        &mut self,
        sockets: &mut SocketSet,
        meta: PacketMeta,
        source_hardware_addr: HardwareAddress,
        ipv4_packet: &Ipv4Packet<&'a [u8]>,
        frag: &'a mut FragmentsBuffer,
    ) -> Option<Packet<'a>> {
        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        let _ = frag;

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let mut ipv4_repr = check!(Ipv4Repr::parse(ipv4_packet, &self.caps.checksum));
        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        let ipv4_repr = check!(Ipv4Repr::parse(ipv4_packet, &self.caps.checksum));
        let src_unspecified = ipv4_repr.src_addr.is_unspecified();
        if !self.is_unicast_v4(ipv4_repr.src_addr) && !src_unspecified {
            net_debug!("non-unicast source address");
            return None;
        }

        // 127/8 names this machine, so off a loopback interface such a frame is
        // spoofed or misrouted. The source is the dangerous half: it survives
        // the checks above, and a peer that could hold it would reach every
        // local program that trusts its counterparty for being on loopback.
        if !self.loopback && (ipv4_repr.src_addr.is_loopback() || ipv4_repr.dst_addr.is_loopback())
        {
            net_debug!("loopback address on a non-loopback interface");
            self.rx_loopback_dropped = self.rx_loopback_dropped.wrapping_add(1);
            return None;
        }

        #[cfg(feature = "proto-ipv4-fragmentation")]
        let (ip_payload, meta) = {
            if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 || ipv4_packet.reserved()
            {
                self.ip_packet_stats.ipv4_fragments_rx =
                    self.ip_packet_stats.ipv4_fragments_rx.wrapping_add(1);
                let key = FragKey::Ipv4(ipv4_packet.get_key());

                if !self.accepts_ipv4_fragment_destination(ipv4_repr.dst_addr) {
                    return None;
                }
                if let Err(error) = validate_ipv4_fragment(ipv4_packet) {
                    let error = frag.assembler.reject_existing(&key, error);
                    self.count_reassembly_error(error);
                    net_debug!("fragmentation error: {:?}", error);
                    return None;
                }

                let f = match frag.assembler.get(&key, self.now + frag.reassembly_timeout) {
                    Ok(f) => f,
                    Err(_) => {
                        let counter = &mut self.ip_packet_stats.reassembly_no_slot_drops;
                        *counter = counter.wrapping_add(1);
                        net_debug!("No available packet assembler for fragmented packet");
                        return None;
                    }
                };

                let offset = ipv4_packet.frag_offset() as usize;
                let incoming_end = offset + ipv4_packet.payload().len();
                if offset == 0 {
                    f.set_ipv4_context(Ipv4ReassemblyContext {
                        repr: ipv4_repr,
                        header_len: ipv4_packet.header_len() as usize,
                    });
                }
                let header_len = f
                    .ipv4_context()
                    .map_or(IPV4_HEADER_LEN, |context| context.header_len);
                if let Err(error) = f.enforce_max_size(u16::MAX as usize - header_len, incoming_end)
                {
                    self.count_reassembly_error(error);
                    net_debug!("fragmentation error: {:?}", error);
                    return None;
                }

                if !ipv4_packet.more_frags()
                    && let Err(error) = f.set_total_size(incoming_end)
                {
                    self.count_reassembly_error(error);
                    net_debug!("fragmentation error: {:?}", error);
                    return None;
                }

                match f.add(ipv4_packet.payload(), offset) {
                    Ok(AssemblerOutcome::Duplicate) => {
                        let counter = &mut self.ip_packet_stats.reassembly_duplicates;
                        *counter = counter.wrapping_add(1);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        self.count_reassembly_error(error);
                        net_debug!("fragmentation error: {:?}", error);
                        return None;
                    }
                }
                if !f.is_complete() {
                    return None;
                }
                let context = match f.ipv4_context() {
                    Some(context) => context,
                    None => {
                        f.reset();
                        return None;
                    }
                };
                let payload = f.assemble()?;
                self.ip_packet_stats.reassemblies_completed =
                    self.ip_packet_stats.reassemblies_completed.wrapping_add(1);
                ipv4_repr = context.repr;
                ipv4_repr.payload_len = payload.len();
                // A reassembled datagram is not one frame, so no single frame's
                // header vouches for its L4 checksum.
                (payload, meta.with_l4_csum_vouched(false))
            } else {
                (ipv4_packet.payload(), meta)
            }
        };

        #[cfg(not(feature = "proto-ipv4-fragmentation"))]
        let ip_payload = ipv4_packet.payload();

        let ip_repr = IpRepr::Ipv4(ipv4_repr);

        #[cfg(feature = "socket-raw")]
        let handled_by_raw_socket =
            !src_unspecified && self.raw_socket_filter(sockets, &ip_repr, ip_payload);
        #[cfg(not(feature = "socket-raw"))]
        let handled_by_raw_socket = false;

        #[cfg(feature = "socket-dhcpv4")]
        {
            use crate::socket::dhcpv4::Socket as Dhcpv4Socket;

            if ipv4_repr.next_header == IpProtocol::Udp
                && matches!(self.caps.medium, Medium::Ethernet)
            {
                let udp_packet = check!(UdpPacket::new_checked(ip_payload));
                if let Some(dhcp_socket) = sockets
                    .items_mut()
                    .find_map(|i| Dhcpv4Socket::downcast_mut(&mut i.socket))
                {
                    // First check for source and dest ports, then do `UdpRepr::parse` if they match.
                    // This way we avoid validating the UDP checksum twice for all non-DHCP UDP packets (one here, one in `process_udp`)
                    if udp_packet.src_port() == dhcp_socket.server_port
                        && udp_packet.dst_port() == dhcp_socket.client_port
                    {
                        let udp_repr = check!(UdpRepr::parse(
                            &udp_packet,
                            &ipv4_repr.src_addr.into(),
                            &ipv4_repr.dst_addr.into(),
                            &self.caps.checksum.rx_vouched(meta.l4_csum_vouched)
                        ));
                        dhcp_socket.process(self, &ipv4_repr, &udp_repr, udp_packet.payload());
                        return None;
                    }
                }
            }
        }

        if src_unspecified {
            net_debug!("unspecified source address outside DHCP");
            return None;
        }

        if !self.has_ip_addr(ipv4_repr.dst_addr)
            && !self.has_multicast_group(ipv4_repr.dst_addr)
            && !self.is_broadcast_v4(ipv4_repr.dst_addr)
        {
            // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.

            if !ipv4_repr.dst_addr.x_is_unicast() {
                net_trace!(
                    "Rejecting IPv4 packet; {} is not a unicast address",
                    ipv4_repr.dst_addr
                );
                return None;
            }

            if self
                .routes
                .lookup(&IpAddress::Ipv4(ipv4_repr.dst_addr), self.now)
                .is_none_or(|router_addr| !self.has_ip_addr(router_addr))
            {
                net_trace!("Rejecting IPv4 packet; no matching routes");

                return None;
            }

            net_trace!("Rejecting IPv4 packet; no assigned address");
            return None;
        }

        #[cfg(feature = "medium-ethernet")]
        if self.is_unicast_v4(ipv4_repr.dst_addr) {
            self.neighbor_cache.reset_expiry_if_existing(
                IpAddress::Ipv4(ipv4_repr.src_addr),
                source_hardware_addr,
                self.now,
            );
        }

        match ipv4_repr.next_header {
            IpProtocol::Icmp => self.process_icmpv4(sockets, ipv4_repr, ip_payload),

            #[cfg(feature = "multicast")]
            IpProtocol::Igmp => self.process_igmp(ipv4_repr, ip_payload),

            #[cfg(any(feature = "socket-udp", feature = "socket-dns"))]
            IpProtocol::Udp => {
                self.process_udp(sockets, meta, handled_by_raw_socket, ip_repr, ip_payload)
            }

            #[cfg(feature = "socket-tcp")]
            IpProtocol::Tcp => {
                self.process_tcp(sockets, meta, handled_by_raw_socket, ip_repr, ip_payload)
            }

            _ if handled_by_raw_socket => None,

            _ => {
                // Send back as much of the original payload as we can.
                let payload_len =
                    icmp_reply_payload_len(ip_payload.len(), IPV4_MIN_MTU, ipv4_repr.buffer_len());
                let icmp_reply_repr = Icmpv4Repr::DstUnreachable {
                    reason: Icmpv4DstUnreachable::ProtoUnreachable,
                    next_hop_mtu: None,
                    header: ipv4_repr,
                    data: &ip_payload[0..payload_len],
                };
                self.icmpv4_reply(ipv4_repr, icmp_reply_repr)
            }
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(super) fn process_arp<'frame>(
        &mut self,
        timestamp: Instant,
        eth_frame: &EthernetFrame<&'frame [u8]>,
    ) -> Option<EthernetPacket<'frame>> {
        let arp_packet = check!(ArpPacket::new_checked(eth_frame.payload()));
        let arp_repr = check!(ArpRepr::parse(&arp_packet));

        match arp_repr {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_protocol_addr,
                ..
            } => {
                // Only process ARP packets for us.
                if !self.has_ip_addr(target_protocol_addr) {
                    return None;
                }

                // Only process REQUEST and RESPONSE.
                if let ArpOperation::Unknown(_) = operation {
                    net_debug!("arp: unknown operation code");
                    return None;
                }

                // Discard packets with non-unicast source addresses.
                if !source_protocol_addr.x_is_unicast() || !source_hardware_addr.is_unicast() {
                    net_debug!("arp: non-unicast source address");
                    return None;
                }

                if !self.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
                    net_debug!("arp: source IP address not in same network as us");
                    return None;
                }

                // Fill the ARP cache from any ARP packet aimed at us (both request or response).
                // We fill from requests too because if someone is requesting our address they
                // are probably going to talk to us, so we avoid having to request their address
                // when we later reply to them.
                //
                // A request is unsolicited, though: any peer on the segment can send one, so it
                // may take a free slot or refresh a mapping but may never displace one. A reply
                // may evict only when it matches a live record of a request we sent; an
                // uncorrelated reply is subject to the same non-evicting admission policy.
                let protocol_addr = IpAddress::Ipv4(source_protocol_addr);
                if operation == ArpOperation::Request {
                    self.fill_neighbor_unsolicited(
                        protocol_addr,
                        source_hardware_addr.into(),
                        timestamp,
                    );
                } else if self.neighbor_cache.take_probe(&protocol_addr, timestamp) {
                    self.fill_neighbor_solicited(
                        protocol_addr,
                        source_hardware_addr.into(),
                        timestamp,
                    );
                } else {
                    self.fill_neighbor_unsolicited(
                        protocol_addr,
                        source_hardware_addr.into(),
                        timestamp,
                    );
                }

                if operation == ArpOperation::Request {
                    let src_hardware_addr = self.hardware_addr.ethernet_or_panic();

                    Some(EthernetPacket::Arp(ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: src_hardware_addr,
                        source_protocol_addr: target_protocol_addr,
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr,
                    }))
                } else {
                    None
                }
            }
        }
    }

    pub(super) fn process_icmpv4<'frame>(
        &mut self,
        sockets: &mut SocketSet,
        ip_repr: Ipv4Repr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let icmp_packet = check!(Icmpv4Packet::new_checked(ip_payload));
        let icmp_repr = check!(Icmpv4Repr::parse(&icmp_packet, &self.caps.checksum));

        #[cfg(feature = "socket-icmp")]
        let mut handled_by_icmp_socket = false;

        #[cfg(all(feature = "socket-icmp", feature = "proto-ipv4"))]
        for icmp_socket in sockets
            .items_mut()
            .filter_map(|i| icmp::Socket::downcast_mut(&mut i.socket))
        {
            if icmp_socket.accepts_v4(self, &ip_repr, &icmp_repr) {
                icmp_socket.process_v4(self, &ip_repr, &icmp_repr);
                handled_by_icmp_socket = true;
            }
        }

        match icmp_repr {
            // Respond to echo requests.
            Icmpv4Repr::EchoRequest {
                ident,
                seq_no,
                data,
            } if self.auto_icmp_echo_reply => {
                let icmp_reply_repr = Icmpv4Repr::EchoReply {
                    ident,
                    seq_no,
                    data,
                };
                self.icmpv4_reply(ip_repr, icmp_reply_repr)
            }

            // Ignore any echo replies.
            Icmpv4Repr::EchoReply { .. } => None,

            Icmpv4Repr::DstUnreachable {
                reason: Icmpv4DstUnreachable::FragRequired,
                next_hop_mtu: Some(mtu),
                ..
            } => {
                let accepted = super::pmtu::parse_ipv4(icmp_packet.data()).is_some_and(|quote| {
                    self.update_pmtu_from_quote(sockets, quote, usize::from(mtu))
                });
                self.count_pmtu_message(accepted);
                None
            }

            // Don't report an error if a packet with unknown type
            // has been handled by an ICMP socket
            #[cfg(feature = "socket-icmp")]
            _ if handled_by_icmp_socket => None,

            // FIXME: do something correct here?
            // By doing nothing, this arm handles the case when auto echo replies are disabled.
            _ => None,
        }
    }

    pub(super) fn icmpv4_reply<'frame, 'icmp: 'frame>(
        &mut self,
        ipv4_repr: Ipv4Repr,
        icmp_repr: Icmpv4Repr<'icmp>,
    ) -> Option<Packet<'frame>> {
        let is_error = matches!(
            icmp_repr,
            Icmpv4Repr::DstUnreachable { .. } | Icmpv4Repr::TimeExceeded { .. }
        );
        if !self.is_unicast_v4(ipv4_repr.src_addr) {
            // Do not send ICMP replies to non-unicast sources
            None
        } else if self.is_unicast_v4(ipv4_repr.dst_addr) {
            if is_error && !self.icmp_error_permitted() {
                return None;
            }
            // Reply as normal when src_addr and dst_addr are both unicast
            let ipv4_reply_repr = Ipv4Repr {
                src_addr: ipv4_repr.dst_addr,
                dst_addr: ipv4_repr.src_addr,
                next_header: IpProtocol::Icmp,
                payload_len: icmp_repr.buffer_len(),
                hop_limit: 64,
            };
            Some(Packet::new_ipv4(
                ipv4_reply_repr,
                IpPayload::Icmpv4(icmp_repr),
            ))
        } else {
            None
        }
    }

    #[cfg(feature = "proto-ipv4-fragmentation")]
    pub(super) fn dispatch_ipv4_frag<Tx: TxToken>(&mut self, tx_token: Tx, frag: &mut Fragmenter) {
        let caps = self.caps.clone();

        let payload_mtu = frag.ipv4.path_mtu - frag.ipv4.repr.buffer_len();
        let max_fragment_size = payload_mtu - payload_mtu % IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;
        let payload_len = (frag.packet_len - frag.sent_bytes).min(max_fragment_size);
        let ip_len = payload_len + frag.ipv4.repr.buffer_len();

        let more_frags = (frag.packet_len - frag.sent_bytes) != payload_len;
        frag.ipv4.repr.payload_len = payload_len;
        frag.sent_bytes += payload_len;

        let mut tx_len = ip_len;
        #[cfg(feature = "medium-ethernet")]
        if matches!(caps.medium, Medium::Ethernet) {
            tx_len += EthernetFrame::<&[u8]>::header_len();
        }

        // Emit function for the Ethernet header.
        #[cfg(feature = "medium-ethernet")]
        let emit_ethernet = |repr: &IpRepr, tx_buffer: &mut [u8]| {
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);
            frame.set_dst_addr(frag.ipv4.dst_hardware_addr);

            match repr.version() {
                #[cfg(feature = "proto-ipv4")]
                IpVersion::Ipv4 => frame.set_ethertype(EthernetProtocol::Ipv4),
                #[cfg(feature = "proto-ipv6")]
                IpVersion::Ipv6 => frame.set_ethertype(EthernetProtocol::Ipv6),
            }
        };

        tx_token.consume(tx_len, |mut tx_buffer| {
            #[cfg(feature = "medium-ethernet")]
            if matches!(self.caps.medium, Medium::Ethernet) {
                emit_ethernet(&IpRepr::Ipv4(frag.ipv4.repr), tx_buffer);
                tx_buffer = &mut tx_buffer[EthernetFrame::<&[u8]>::header_len()..];
            }

            let mut packet =
                Ipv4Packet::new_unchecked(&mut tx_buffer[..frag.ipv4.repr.buffer_len()]);
            frag.ipv4.repr.emit(&mut packet, &caps.checksum);
            packet.set_ident(frag.ipv4.ident);
            packet.set_more_frags(more_frags);
            packet.set_dont_frag(false);
            packet.set_frag_offset(frag.ipv4.frag_offset);

            if caps.checksum.ipv4.tx() {
                packet.fill_checksum();
            }

            tx_buffer[frag.ipv4.repr.buffer_len()..][..payload_len]
                .copy_from_slice(&frag.buffer[frag.ipv4.frag_offset as usize..][..payload_len]);

            // Update the frag offset for the next fragment.
            frag.ipv4.frag_offset += payload_len as u16;
        });
        self.ip_packet_stats.ipv4_fragments_tx =
            self.ip_packet_stats.ipv4_fragments_tx.wrapping_add(1);
    }
}
