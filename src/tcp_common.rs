use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;
use core::net::Ipv4Addr;
use core::ops::{Deref, DerefMut};
use core::ptr;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;

use crate::connections::{ConnectionNode, FlowKey, TcpState};
use wabrix_api::headers::check::ipv4_checksum;
use wabrix_api::headers::{
    new_ipv4_header, update_ipv4_checksum,
};
use wabrix_api::packet::Packet;
use zerocopy::IntoBytes;

// Standard TCP Flags
pub const FLAG_FIN: u8 = 0x01;
pub const FLAG_SYN: u8 = 0x02;
pub const FLAG_RST: u8 = 0x04;
pub const FLAG_ACK: u8 = 0x10;

pub const PORT_START_RANGE: u16 = 10000;
pub const PORT_END_RANGE: u16 = 65535;
pub const MAX_CONNECTIONS: usize = 1_048_576;
pub const MAX_TIMEOUTS: usize = 262_144;

// Telemetry Stat Indices
pub const STAT_SENT_SYN: usize = 0;
pub const STAT_SENT_SYNACK: usize = 1;
pub const STAT_SENT_SYNACK2: usize = 2;
pub const STAT_SENT_FIN: usize = 3;
pub const STAT_SENT_FIN_PSSV: usize = 4;
pub const STAT_SENT_ACK4FIN: usize = 5;
pub const STAT_SENT_ACK: usize = 6;
pub const STAT_SENT_RST: usize = 7;
pub const STAT_RECV_SYN: usize = 8;
pub const STAT_RECV_SYNACK: usize = 9;
pub const STAT_RECV_SYNACK2: usize = 10;
pub const STAT_RECV_FIN: usize = 11;
pub const STAT_RECV_FIN_PSSV: usize = 12;
pub const STAT_RECV_ACK4FIN: usize = 13;
pub const STAT_RECV_ACK: usize = 14;
pub const STAT_RECV_RST: usize = 15;
pub const STAT_UNEXPECTED: usize = 16;
pub const STAT_RECV_PAYLOAD: usize = 17;
pub const STAT_SENT_PAYLOAD: usize = 18;
pub const STAT_TICK_DROP: usize = 19;
pub const STAT_TO_LINUX: usize = 20;
pub const STAT_DROP: usize = 21;
pub const STAT_COUNT: usize = 22;
pub const TCP_WATERMARK_INDEX: usize = STAT_COUNT;
pub const TCP_TELEMETRY_LEN: usize = STAT_COUNT + 1;

/// Recomputes the TCP checksum for an IPv4 packet segment.
#[inline]
pub fn update_tcp_checksum(tcp_segment: &mut [u8], ip_src: u32, ip_dst: u32) {
    let checksum = ipv4_checksum(
        tcp_segment.as_mut_ptr(),
        tcp_segment.len(),
        8,
        &[],
        ip_src,
        ip_dst,
        6,
    );
    tcp_segment[16..18].copy_from_slice(&checksum.to_be_bytes());
}

/// Stable route meanings used by native and Wasm TCP engines.
pub const TCP_ROUTE_TX: u32 = 0;
pub const TCP_ROUTE_LINUX: u32 = 1;
pub const TCP_ROUTE_DROP: u32 = 2;

/// Stable counter order for `get-telemetry()` and native telemetry mirrors.
pub const TCP_STAT_NAMES: [&str; STAT_COUNT] = [
    "sent_syn",
    "sent_synack",
    "sent_synack2",
    "sent_fin",
    "sent_fin_pssv",
    "sent_ack4fin",
    "sent_ack",
    "sent_rst",
    "recv_syn",
    "recv_synack",
    "recv_synack2",
    "recv_fin",
    "recv_fin_pssv",
    "recv_ack4fin",
    "recv_ack",
    "recv_rst",
    "unexpected",
    "recv_payload",
    "sent_payload",
    "tick_drop",
    "to_linux",
    "drop",
];

/// Creates a zeroed TCP header for packet construction.
#[inline]
pub fn new_tcp_header() -> TcpHdr {
    TcpHdr {
        source: [0; 2],
        dest: [0; 2],
        seq: [0; 4],
        ack_seq: [0; 4],
        _bitfield_align_1: [],
        _bitfield_1: TcpHdr::new_bitfield_1(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        window: [0; 2],
        check: [0; 2],
        urg_ptr: [0; 2],
    }
}

/// Converts the TCP flag bitfield to the conventional wire flag byte.
#[inline]
pub fn tcp_flags(header: &TcpHdr) -> u8 {
    (header.fin() as u8)
        | ((header.syn() as u8) << 1)
        | ((header.rst() as u8) << 2)
        | ((header.psh() as u8) << 3)
        | ((header.ack() as u8) << 4)
        | ((header.urg() as u8) << 5)
        | ((header.ece() as u8) << 6)
        | ((header.cwr() as u8) << 7)
}

/// Sets the standard TCP flags from their conventional wire flag byte.
#[inline]
pub fn set_tcp_flags(header: &mut TcpHdr, flags: u8) {
    header.set_fin((flags & 0x01) as u16);
    header.set_syn(((flags >> 1) & 1) as u16);
    header.set_rst(((flags >> 2) & 1) as u16);
    header.set_psh(((flags >> 3) & 1) as u16);
    header.set_ack(((flags >> 4) & 1) as u16);
    header.set_urg(((flags >> 5) & 1) as u16);
    header.set_ece(((flags >> 6) & 1) as u16);
    header.set_cwr(((flags >> 7) & 1) as u16);
}




/// Builds the shared telemetry vector: all packet counters followed by the
/// connection arena high-water mark.
pub fn tcp_telemetry(stats: &[u64; STAT_COUNT], watermark: u64) -> Vec<u64> {
    let mut values = stats.to_vec();
    values.push(watermark);
    values
}

#[cfg(test)]
mod tests {
    use super::{
        tcp_telemetry, FlowKey, TimeoutStack, STAT_COUNT, TCP_ROUTE_DROP,
        TCP_ROUTE_LINUX, TCP_ROUTE_TX, TCP_STAT_NAMES, TCP_TELEMETRY_LEN, TCP_WATERMARK_INDEX,
    };

    #[test]
    fn telemetry_contract_has_stable_order_and_watermark() {
        assert_eq!(TCP_STAT_NAMES.len(), STAT_COUNT);
        assert_eq!(TCP_TELEMETRY_LEN, STAT_COUNT + 1);
        assert_eq!(TCP_WATERMARK_INDEX, STAT_COUNT);
        assert_eq!((TCP_ROUTE_TX, TCP_ROUTE_LINUX, TCP_ROUTE_DROP), (0, 1, 2));

        let stats = [7; STAT_COUNT];
        let telemetry = tcp_telemetry(&stats, 99);
        assert_eq!(telemetry.len(), TCP_TELEMETRY_LEN);
        assert_eq!(telemetry[TCP_WATERMARK_INDEX], 99);
        assert_eq!(TCP_STAT_NAMES[0], "sent_syn");
        assert_eq!(TCP_STAT_NAMES[STAT_COUNT - 1], "drop");
    }

    #[test]
    fn boxed_timeout_stack_is_heap_backed() {
        let mut stack = TimeoutStack::new_boxed();
        assert_eq!(stack.available_capacity(), super::MAX_TIMEOUTS);
        stack.push(FlowKey::empty());
        assert!(stack.pop().is_some());
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GeneratorProtocol {
    #[default]
    Syn,
    Udp,
}

impl GeneratorProtocol {
    #[inline]
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("SYN") {
            Some(Self::Syn)
        } else if value.eq_ignore_ascii_case("UDP") {
            Some(Self::Udp)
        } else {
            None
        }
    }
}

#[derive(Clone, Default)]
pub struct CommonEngineConfig {
    pub name: Option<String>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub src_ip: Option<[u8; 4]>,
    pub dst_ip: Option<[u8; 4]>,
    pub rng_seed: Option<u32>,
    pub tsc_frequency: u64,
    pub bypass: bool,
}

#[derive(Clone, Default)]
pub struct TcpEngineConfig {
    pub common: CommonEngineConfig,
    pub generation_rate: Option<u64>,
    pub syn_limit: Option<u64>,
    pub close_timeout_millis: Option<u64>,
    /// Timeout converted to TSC cycles during configuration, not on the timer hot path.
    pub timeout_cycles: Option<u64>,
}

impl TcpEngineConfig {
    pub fn refresh_timeout_cycles(&mut self) {
        self.timeout_cycles = self.close_timeout_millis.map(|timeout_millis| {
            ((timeout_millis as u128 * self.tsc_frequency as u128) / 1_000) as u64
        });
    }
}

impl Deref for TcpEngineConfig {
    type Target = CommonEngineConfig;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for TcpEngineConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[derive(Clone, Default)]
pub struct GeneratorConfig {
    pub common: CommonEngineConfig,
    pub protocol: GeneratorProtocol,
    pub generation_rate: Option<u64>,
    pub generation_limit: Option<u64>,
}

impl Deref for GeneratorConfig {
    type Target = CommonEngineConfig;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for GeneratorConfig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

pub struct PacketGenerator {
    pub last_tsc: u64,
    pub cycle_accumulator: u64,
    pub port_counter: u16,
    pub ip_offset: u32,
    pub prng_state: u32,
    pub packets_sent: u64,
    pub activated: bool,
}

impl Default for PacketGenerator {
    fn default() -> Self {
        Self {
            last_tsc: 0,
            cycle_accumulator: 0,
            port_counter: PORT_START_RANGE,
            ip_offset: 0,
            prng_state: 1,
            packets_sent: 0,
            activated: false,
        }
    }
}

pub struct TimeoutStack {
    items: [FlowKey; MAX_TIMEOUTS],
    len: usize,
}

impl TimeoutStack {
    pub const fn new() -> Self {
        Self {
            items: [FlowKey::empty(); MAX_TIMEOUTS],
            len: 0,
        }
    }

    /// Allocates the fixed-capacity timeout storage on the heap. Native nodes
    /// use this during construction so the multi-megabyte backing array does
    /// not pass through the main thread's stack.
    pub fn new_boxed() -> alloc::boxed::Box<Self> {
        let mut boxed = alloc::boxed::Box::<Self>::new_uninit();
        unsafe {
            let ptr = boxed.as_mut_ptr();
            core::ptr::write_bytes(
                core::ptr::addr_of_mut!((*ptr).items) as *mut FlowKey,
                0,
                MAX_TIMEOUTS,
            );
            core::ptr::addr_of_mut!((*ptr).len).write(0);
            boxed.assume_init()
        }
    }

    pub fn push(&mut self, key: FlowKey) {
        if self.len < MAX_TIMEOUTS {
            self.items[self.len] = key;
            self.len += 1;
        }
    }

    pub fn pop(&mut self) -> Option<FlowKey> {
        if self.len > 0 {
            self.len -= 1;
            Some(self.items[self.len])
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    // Returns the exact number of slots currently free
    pub fn available_capacity(&self) -> usize {
        MAX_TIMEOUTS - self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for TimeoutStack {
    fn default() -> Self {
        Self::new()
    }
}

impl core::iter::Extend<FlowKey> for TimeoutStack {
    fn extend<T: IntoIterator<Item = FlowKey>>(&mut self, iter: T) {
        for key in iter {
            if self.len < MAX_TIMEOUTS {
                self.items[self.len] = key;
                self.len += 1;
            } else {
                break;
            }
        }
    }
}

/// Formats outbound Ethernet/IPv4/TCP headers directly into the frame buffer.
/// Returns the total byte length of the written headers.
///
#[allow(clippy::too_many_arguments)]
pub fn write_tcp_packet(
    packet: &mut Packet,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
) -> u32 {
    let mac = EthHdr::new(dst_mac, src_mac, EtherType::Ipv4);

    let mut ip = new_ipv4_header();
    ip.set_src_addr(Ipv4Addr::from(src_ip));
    ip.set_dst_addr(Ipv4Addr::from(dst_ip));
    ip.ttl = 64;
    ip.set_vihl(4, Ipv4Hdr::LEN as u8);
    ip.set_proto(IpProto::Tcp);
    ip.set_tot_len(40);
    ip.set_frags(0x2, 0);
    update_ipv4_checksum(&mut ip);

    let mut tcp = new_tcp_header();
    set_tcp_flags(&mut tcp, flags);
    tcp.source = src_port.to_be_bytes();
    tcp.dest = dst_port.to_be_bytes();
    tcp.set_doff(5);
    tcp.seq = seq_num.to_be_bytes();
    tcp.ack_seq = ack_num.to_be_bytes();
    tcp.window = 64240u16.to_be_bytes();
    update_tcp_checksum(tcp.as_mut_bytes(), src_ip, dst_ip);

    packet.write_eth_ipv4_tcp_headers(&mac, &ip, &tcp)
}

/// Formats an Ethernet/IPv4/UDP packet with the supplied payload.
/// Returns the total byte length of the written packet.
#[allow(clippy::too_many_arguments)]
pub fn write_udp_packet(
    packet: &mut Packet,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    src_port: u16,
    dst_ip: u32,
    dst_port: u16,
    payload: &[u8],
) -> u32 {
    let mac_size = EthHdr::LEN;
    let ip_size = Ipv4Hdr::LEN;
    let udp_size = size_of::<UdpHdr>();

    let udp_len = (udp_size + payload.len()) as u16;
    let ip_len = (ip_size + udp_len as usize) as u16;

    let mac = EthHdr::new(dst_mac, src_mac, EtherType::Ipv4);

    let mut ip = new_ipv4_header();
    ip.set_src_addr(Ipv4Addr::from(src_ip));
    ip.set_dst_addr(Ipv4Addr::from(dst_ip));
    ip.ttl = 64;
    ip.set_vihl(4, Ipv4Hdr::LEN as u8);
    ip.set_proto(IpProto::Udp);
    ip.set_tot_len(ip_len);
    ip.set_frags(0x2, 0);
    update_ipv4_checksum(&mut ip);

    let mut udp = UdpHdr {
        src: [0; 2],
        dst: [0; 2],
        len: [0; 2],
        check: [0; 2],
    };
    udp.set_src_port(src_port);
    udp.set_dst_port(dst_port);
    udp.set_len(udp_len);

    let header_len = packet.write_eth_ipv4_udp_headers(&mac, &ip, &udp);
    let udp_ptr = unsafe { packet.data_ptr_mut().add(mac_size + ip_size) };
    let payload_ptr = unsafe { packet.data_ptr_mut().add(header_len as usize) };

    // The frame is exclusively owned by this packet view.
    unsafe {
        ptr::copy_nonoverlapping(payload.as_ptr(), payload_ptr, payload.len());
    }

    let checksum = ipv4_checksum(udp_ptr, udp_len as usize, 3, &[], src_ip, dst_ip, 17);
    unsafe {
        (*(udp_ptr as *mut UdpHdr)).set_checksum(checksum);
    }

    let packet_len = (mac_size + ip_size + udp_len as usize) as u32;
    packet.resize_payload(packet_len);
    packet_len
}

/// RFC 793 state machine. Returns the reply flags/seq/ack on a transition that
/// requires sending a packet, or `None` to silently drop.
pub fn run_tcp_state_machine(
    conn: &mut ConnectionNode,
    tcp_flags: u8,
    seq_num: u32,
    ack_num: u32,
    payload_len: u32,
    stats: &mut [u64; STAT_COUNT],
) -> Option<(u8, u32, u32)> {
    macro_rules! inc_stat {
        ($stat:expr) => {
            stats[$stat] += 1
        };
    }
    macro_rules! reply {
        ($flags:expr) => {
            Some(($flags, conn.snd_nxt, conn.rcv_nxt))
        };
    }

    if tcp_flags & FLAG_RST != 0 {
        inc_stat!(STAT_RECV_RST);
        conn.state = TcpState::Closed;
        return None;
    }

    if tcp_flags & FLAG_FIN != 0 {
        if conn.state == TcpState::Established {
            inc_stat!(STAT_RECV_FIN_PSSV);
        } else {
            inc_stat!(STAT_RECV_FIN);
        }
    } else if tcp_flags & FLAG_SYN != 0 && tcp_flags & FLAG_ACK != 0 {
        inc_stat!(STAT_RECV_SYNACK);
    } else if payload_len > 0 {
        inc_stat!(STAT_RECV_PAYLOAD);
    } else if tcp_flags & FLAG_ACK != 0 {
        match conn.state {
            TcpState::SynReceived | TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck => {}
            _ => inc_stat!(STAT_RECV_ACK),
        }
    }

    match conn.state {
        TcpState::Listen if tcp_flags & FLAG_SYN != 0 => {
            conn.state = TcpState::SynReceived;
            conn.rcv_nxt = seq_num.wrapping_add(1);
            let send_seq = conn.snd_nxt;
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            inc_stat!(STAT_SENT_SYNACK);
            return Some((FLAG_SYN | FLAG_ACK, send_seq, conn.rcv_nxt));
        }

        TcpState::SynSent
            if tcp_flags & FLAG_SYN != 0
                && tcp_flags & FLAG_ACK != 0
                && ack_num == conn.snd_nxt =>
        {
            conn.state = TcpState::Established;
            conn.rcv_nxt = seq_num.wrapping_add(1);
            inc_stat!(STAT_SENT_SYNACK2);
            return reply!(FLAG_ACK);
        }
        TcpState::SynSent if tcp_flags & FLAG_SYN != 0 && tcp_flags & FLAG_ACK != 0 => {
            inc_stat!(STAT_SENT_RST);
            return Some((FLAG_RST, ack_num, 0));
        }
        TcpState::SynSent if tcp_flags & FLAG_RST != 0 => {
            conn.state = TcpState::Closed;
        }

        TcpState::SynReceived if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt => {
            conn.state = TcpState::Established;
            inc_stat!(STAT_RECV_SYNACK2);
        }

        TcpState::Established if tcp_flags & FLAG_FIN != 0 => {
            conn.state = TcpState::LastAck;
            if seq_num == conn.rcv_nxt {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len).wrapping_add(1);
            }
            let send_seq = conn.snd_nxt;
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            inc_stat!(STAT_SENT_FIN_PSSV);
            inc_stat!(STAT_SENT_ACK4FIN);
            return Some((FLAG_FIN | FLAG_ACK, send_seq, conn.rcv_nxt));
        }
        TcpState::Established if tcp_flags & FLAG_ACK != 0 && payload_len > 0 => {
            if seq_num == conn.rcv_nxt {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len);
            }
            inc_stat!(STAT_SENT_ACK);
            return reply!(FLAG_ACK);
        }
        TcpState::Established
            if tcp_flags & FLAG_ACK != 0 && seq_num == conn.rcv_nxt.wrapping_sub(1) =>
        {
            inc_stat!(STAT_SENT_ACK);
            return reply!(FLAG_ACK);
        }

        TcpState::FinWait2 if tcp_flags & FLAG_FIN != 0 => {
            conn.state = TcpState::Closed;
            conn.rcv_nxt = seq_num.wrapping_add(1);
            inc_stat!(STAT_SENT_ACK4FIN);
            return reply!(FLAG_ACK);
        }

        TcpState::FinWait1 if tcp_flags & FLAG_FIN != 0 => {
            if seq_num == conn.rcv_nxt {
                conn.rcv_nxt = conn.rcv_nxt.wrapping_add(payload_len).wrapping_add(1);
            }
            inc_stat!(STAT_SENT_ACK4FIN);

            if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt {
                // Client ACKed our FIN and sent theirs simultaneously
                conn.state = TcpState::Closed;
                inc_stat!(STAT_RECV_ACK4FIN);
            } else {
                conn.state = TcpState::Closing;
            }
            return reply!(FLAG_ACK);
        }
        TcpState::FinWait1 if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt => {
            conn.state = TcpState::FinWait2;
            inc_stat!(STAT_RECV_ACK4FIN);
        }

        TcpState::CloseWait if tcp_flags & FLAG_FIN != 0 => {
            // Retransmit ACK for FIN if client missed the first pure ACK
            inc_stat!(STAT_SENT_ACK4FIN);
            return reply!(FLAG_ACK);
        }

        TcpState::Closing if tcp_flags & FLAG_ACK != 0 => {
            conn.state = TcpState::Closed;
            inc_stat!(STAT_RECV_ACK4FIN);
        }

        TcpState::LastAck if tcp_flags & FLAG_ACK != 0 && ack_num == conn.snd_nxt => {
            conn.state = TcpState::Closed;
            inc_stat!(STAT_RECV_ACK4FIN);
        }

        TcpState::Closed if tcp_flags & FLAG_RST == 0 => {
            inc_stat!(STAT_SENT_RST);
            return Some((FLAG_RST, 0, seq_num.wrapping_add(payload_len)));
        }

        _ => {}
    }

    None
}

//use log::trace;
//use zerocopy::FromBytes;
//use network_types::ip::Ipv4Hdr;
//use network_types::tcp::TcpHdr;

/*
#[inline]
pub fn prepare_checksums_and_ttl(p: &mut PduCore, base_addr: usize) {
    let frame_size = p.frame_size();
    let packet_len = p.data_len() as usize;
    let headroom = p.headroom();
    let stack = p.headers_mut();
    let Some(ip_index) = (0..stack.count()).find(|&i| stack.kinds[i] == HeaderKind::Ip) else {
        return;
    };
    let frame_offset = stack.offsets[ip_index] as usize;
    let Some(packet_offset) = frame_offset.checked_sub(headroom) else {
        return;
    };
    let Some(packet_end) = packet_offset.checked_add(Ipv4Hdr::LEN) else {
        return;
    };
    let Some(frame_end) = frame_offset.checked_add(Ipv4Hdr::LEN) else {
        return;
    };
    if packet_end > packet_len || frame_end > frame_size {
        return;
    }

    let (psz, src, dst) = {
        let ip_ptr = (base_addr + frame_offset) as *mut u8;
        // SAFETY: The stack offset and packet/frame bounds above ensure the IPv4 header is in
        // the frame. The caller owns this packet mutably for the duration of this function.
        let ip_bytes = unsafe { core::slice::from_raw_parts_mut(ip_ptr, Ipv4Hdr::LEN) };
        let Ok(ip) = Ipv4Hdr::mut_from_bytes(ip_bytes) else {
            return;
        };
        let ttl = ip.ttl;
        if ttl >= 1 {
            ip.ttl = ttl - 1;
        }
        update_ipv4_checksum(ip);
        (
            ip.payload_size(0),
            u32::from(ip.src_addr()),
            u32::from(ip.dst_addr()),
        )
    };
    let Some(tcp_index) = (0..stack.count()).find(|&i| stack.kinds[i] == HeaderKind::Tcp) else {
        return;
    };
    if psz < TcpHdr::LEN {
        return;
    }
    let tcp_frame_offset = stack.offsets[tcp_index] as usize;
    let Some(tcp_packet_offset) = tcp_frame_offset.checked_sub(headroom) else {
        return;
    };
    let Some(tcp_packet_end) = tcp_packet_offset.checked_add(psz) else {
        return;
    };
    let Some(tcp_frame_end) = tcp_frame_offset.checked_add(psz) else {
        return;
    };
    if tcp_packet_end > packet_len || tcp_frame_end > frame_size {
        return;
    }

    let checksum = {
        let tcp_ptr = (base_addr + tcp_frame_offset) as *mut u8;
        // SAFETY: The stack offset and packet/frame bounds above cover the entire TCP segment.
        let tcp_bytes = unsafe { core::slice::from_raw_parts_mut(tcp_ptr, psz) };
        update_tcp_checksum(tcp_bytes, src, dst);
        u16::from_be_bytes([tcp_bytes[16], tcp_bytes[17]])
    };
    trace!(
        "ip-payload_sz= {}, checksum recalc = {:X}",
        psz,
        checksum
    );
}
*/
