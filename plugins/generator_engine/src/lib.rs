#![no_std]

extern crate alloc;

mod diagnostics;

use alloc::string::String;
use alloc::vec::Vec;
use core::{mem::size_of, ptr};
use core::net::Ipv4Addr;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::udp::UdpHdr;
use crate::exports::wabrix::plugins::packet_engine::{
    Counter, Guest, TelemetryMetric, TelemetrySchema, TimerPlan,
};
use crate::wabrix::plugins::logging;
use wabrix_plugins::connections::ConnectionPool;
use wabrix_plugins::engine_common::{handle_control_event, ControlResult};
use wabrix_plugins::engine_common::{parse_generator_config, WasmCell, WasmValue};
use wabrix_api::headers::check::{finalize_checksum, ipv4_checksum};
use wabrix_api::headers::{
    new_ipv4_header, update_ipv4_checksum,
};
use wabrix_api::mailbox_api::{MailboxBatch, MailboxPacket};
use wabrix_api::{MAX_BATCH_SIZE, TIMER_KIND_TIMEOUT};

use wabrix_plugins::tcp_common::{
    write_tcp_packet, GeneratorConfig, GeneratorProtocol, PacketGenerator, FLAG_SYN,
    PORT_END_RANGE, PORT_START_RANGE, STAT_COUNT, STAT_DROP, STAT_SENT_SYN, STAT_TICK_DROP,
    STAT_TO_LINUX, TCP_STAT_NAMES,
};

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "engine-plugin",
});

static CONFIG: WasmCell<Option<GeneratorConfig>> = WasmCell::new(None);
static CONNECTIONS: WasmCell<Option<ConnectionPool>> = WasmCell::new(None);
static TIMEOUT_QUEUE: WasmCell<wabrix_plugins::tcp_common::TimeoutStack> =
    WasmCell::new(wabrix_plugins::tcp_common::TimeoutStack::new());
static PACKET_GEN: WasmCell<PacketGenerator> = WasmCell::new(PacketGenerator {
    last_tsc: 0,
    cycle_accumulator: 0,
    port_counter: PORT_START_RANGE,
    ip_offset: 0,
    prng_state: 1,
    packets_sent: 0,
    activated: true,
});

static CURRENT_TSC: WasmValue<u64> = WasmValue::new(0);
static RUN_START_TSC: WasmValue<u64> = WasmValue::new(0);
static GENERATION_START_TSC: WasmValue<u64> = WasmValue::new(0);
static CONFIGURED_BATCH_SIZE: WasmValue<u32> = WasmValue::new(MAX_BATCH_SIZE as u32);
static CONFIGURED_BATCH_SIZE_VARIANCE: WasmValue<u32> = WasmValue::new(0);
static NEXT_BATCH_TARGET: WasmValue<u32> = WasmValue::new(0);
static JITTER_PRNG_STATE: WasmValue<u64> = WasmValue::new(0x853c49e6748fea9b);

#[inline(always)]
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    if x == 0 {
        x = 0x853c49e6748fea9b;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

const ROUTE_TX: u32 = 0;
const ROUTE_LINUX: u32 = 1;
const ROUTE_DROP: u32 = 2;
const TIMESTAMP_MAGIC: [u8; 4] = *b"WABR";
const UDP_SEQUENCE_OFFSET: usize = TIMESTAMP_MAGIC.len() + size_of::<u64>();
const UDP_PAYLOAD_LEN: usize = UDP_SEQUENCE_OFFSET + size_of::<u64>();

// The zero-cost global counter array
static TCP_STATS: WasmCell<[u64; STAT_COUNT]> = WasmCell::new([0; STAT_COUNT]);

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true // You can add level filtering here if you want to save cycles
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            // Format the message using the alloc crate
            let msg = alloc::format!("generator_engine: {}", record.args());
            // Call the WIT-generated host function.
            // The path matches your package: wabrix:plugins/logging
            logging::log(record.level() as u32, &msg);
        }
    }

    fn flush(&self) {}
}

// 2. Add an init function to wire it up when the plugin starts
pub fn init_logging() {
    // We use set_logger instead of set_boxed_logger to avoid allocations if possible,
    // or Box::new if required by the log crate version.
    static LOGGER: HostLogger = HostLogger;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info); // Set your desired Wasm log level
}

#[inline(always)]
fn prepare_syn_packet(
    mb_packet: &mut MailboxPacket<'_>,
    gen: &mut PacketGenerator,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
    dst_ip: u32,
) {
    gen.packets_sent += 1;
    let src_port = gen.port_counter;
    gen.prng_state = gen
        .prng_state
        .wrapping_mul(1664525)
        .wrapping_add(1013904223);
    let isn = gen.prng_state;
    let packet_src_ip = src_ip.wrapping_add(gen.ip_offset);

    if gen.port_counter == PORT_END_RANGE {
        gen.port_counter = PORT_START_RANGE;
        gen.ip_offset = (gen.ip_offset + 1) % 250;
    } else {
        gen.port_counter += 1;
    }

    write_tcp_packet(
        mb_packet.as_packet(),
        src_mac,
        dst_mac,
        packet_src_ip,
        src_port,
        dst_ip,
        80,
        isn,
        0,
        FLAG_SYN,
    );
}

#[inline]
fn prepare_udp_packet(
    packet: &mut MailboxPacket<'_>,
    gen: &mut PacketGenerator,
    template: &UdpPacketTemplate,
) {
    gen.packets_sent += 1;
    let sequence = gen.packets_sent;
    let src_port = gen.port_counter;
    if gen.port_counter == PORT_END_RANGE {
        gen.port_counter = PORT_START_RANGE;
    } else {
        gen.port_counter += 1;
    }

    template.write(packet, src_port, sequence);
}

/// The UDP payload carries the host TSC snapshot, which is constant during a
/// batch. The sequence number and source port change for each generated packet.
struct UdpPacketTemplate {
    mac: EthHdr,
    ip: Ipv4Hdr,
    udp: UdpHdr,
    payload: [u8; UDP_SEQUENCE_OFFSET],
    checksum_without_dynamic_fields: u16,
}

impl UdpPacketTemplate {
    fn new(config: GeneratorBatchConfig, packet_tsc: u64) -> Self {
        let mut payload = [0u8; UDP_SEQUENCE_OFFSET];
        payload[..TIMESTAMP_MAGIC.len()].copy_from_slice(&TIMESTAMP_MAGIC);
        payload[TIMESTAMP_MAGIC.len()..].copy_from_slice(&packet_tsc.to_be_bytes());
        let mut checksum_payload = [0u8; UDP_PAYLOAD_LEN];
        checksum_payload[..payload.len()].copy_from_slice(&payload);

        let mac = EthHdr::new(config.dst_mac, config.src_mac, EtherType::Ipv4);

        let mut ip = new_ipv4_header();
        ip.set_src_addr(Ipv4Addr::from(config.src_ip));
        ip.set_dst_addr(Ipv4Addr::from(config.dst_ip));
        ip.ttl = 64;
        ip.set_vihl(4, Ipv4Hdr::LEN as u8);
        ip.set_proto(IpProto::Udp);
        ip.set_tot_len((Ipv4Hdr::LEN + size_of::<UdpHdr>() + UDP_PAYLOAD_LEN) as u16);
        ip.set_frags(0x2, 0);
        update_ipv4_checksum(&mut ip);

        let mut udp = UdpHdr {
            src: [0; 2],
            dst: [0; 2],
            len: [0; 2],
            check: [0; 2],
        };
        udp.set_dst_port(80);
        udp.set_len((size_of::<UdpHdr>() + UDP_PAYLOAD_LEN) as u16);

        // Compute the checksum once with a zero source port and sequence.
        // The changing source-port and sequence words are added per packet.
        let checksum_without_dynamic_fields = ipv4_checksum(
            (&raw mut udp).cast::<u8>(),
            size_of::<UdpHdr>(),
            3,
            &checksum_payload,
            config.src_ip,
            config.dst_ip,
            17,
        );

        Self {
            mac,
            ip,
            udp,
            payload,
            checksum_without_dynamic_fields,
        }
    }

    #[inline(always)]
    fn udp_header_for_packet(&self, src_port: u16, sequence: u64) -> UdpHdr {
        let mut udp = self.udp;
        udp.set_src_port(src_port);
        let sequence_sum = ((sequence >> 48) as u16 as u32)
            + ((sequence >> 32) as u16 as u32)
            + ((sequence >> 16) as u16 as u32)
            + (sequence as u16 as u32);
        udp.set_checksum(finalize_checksum(
            (!self.checksum_without_dynamic_fields as u32) + src_port as u32 + sequence_sum,
        ));
        udp
    }

    #[inline(always)]
    fn write(&self, packet: &mut MailboxPacket<'_>, src_port: u16, sequence: u64) {
        let udp = self.udp_header_for_packet(src_port, sequence);
        let packet = packet.as_packet();
        let header_len = packet.write_mac_ipv4_udp_headers(&self.mac, &self.ip, &udp);
        let sequence_bytes = sequence.to_be_bytes();
        // The UMEM frame is exclusively owned and has room for the fixed
        // timestamp and sequence payload.
        // SAFETY: The packet exclusively owns its UMEM frame; `header_len` is the end of
        // the headers just written, and the frame has capacity for this fixed 20-byte payload.
        // Both source arrays are stack-local and do not overlap the frame's payload region.
        unsafe {
            let payload_ptr = packet.data_ptr_mut().add(header_len as usize);
            ptr::copy_nonoverlapping(self.payload.as_ptr(), payload_ptr, self.payload.len());
            ptr::copy_nonoverlapping(
                sequence_bytes.as_ptr(),
                payload_ptr.add(UDP_SEQUENCE_OFFSET),
                sequence_bytes.len(),
            );
        }
        packet.resize_payload(header_len + UDP_PAYLOAD_LEN as u32);
    }
}

#[derive(Clone, Copy)]
struct GeneratorBatchConfig {
    generation_rate: u64,
    generation_limit: Option<u64>,
    src_ip: u32,
    dst_ip: u32,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    tsc_frequency: u64,
}

#[inline]
fn process_batch_for_protocol<const UDP: bool>(
    batch_size: u32,
    umem_offset: u32,
    mailbox_offset: u32,
    config: GeneratorBatchConfig,
) -> u32 {
    let mut batch = MailboxBatch::new(batch_size, umem_offset, mailbox_offset);
    let mut stats = TCP_STATS.borrow_mut();
    // Keep the generator state borrow across the batch. The state is owned by
    // this Wasm instance and is only accessed by this process_batch call, so
    // acquiring the RefCell borrow once avoids one borrow pair per packet.
    let mut gen = PACKET_GEN.borrow_mut();
    // The host TSC snapshot is updated by process_timers between batch calls,
    // so every packet in this batch shares the same timestamp.
    let packet_tsc = CURRENT_TSC.get();
    let udp_template = UDP.then(|| UdpPacketTemplate::new(config, packet_tsc));

    for mut packet in batch.iter_mut() {
        let action = match packet.tick_kind() {
            None => {
                // Route standard non-timer packets to Linux
                stats[STAT_TO_LINUX] += 1;
                ROUTE_LINUX
            }
            Some(timer_kind) if timer_kind == TIMER_KIND_TIMEOUT || config.generation_rate == 0 => {
                // Drop inactive timers or drop when generation is disabled
                stats[STAT_DROP] += 1;
                stats[STAT_TICK_DROP] += 1;
                ROUTE_DROP
            }
            Some(_) => {
                // Evaluate generation limits idiomatically
                let under_limit = config
                    .generation_limit
                    .is_none_or(|max| gen.packets_sent < max || max == 0);

                if !gen.activated || !under_limit {
                    stats[STAT_DROP] += 1;
                    stats[STAT_TICK_DROP] += 1;
                    ROUTE_DROP
                } else {
                    // Generate and track the packet
                    let packet_start_tsc = packet_tsc;

                    // `packet_start_tsc` originates from the host's actual
                    // `_rdtsc()` value passed through process_timers().
                    packet.as_packet().set_timestamp(packet_start_tsc);

                    if UDP {
                        prepare_udp_packet(&mut packet, &mut gen, udp_template.as_ref().unwrap());
                    } else {
                        prepare_syn_packet(
                            &mut packet,
                            &mut gen,
                            config.src_mac,
                            config.dst_mac,
                            config.src_ip,
                            config.dst_ip,
                        );
                    }

                    if gen.packets_sent == 1 {
                        GENERATION_START_TSC.set(packet_start_tsc);
                    }

                    let packet_end_tsc = packet_tsc;
                    let generation_complete = config
                        .generation_limit
                        .is_some_and(|limit| limit > 0 && gen.packets_sent == limit);

                    if generation_complete {
                        let start_tsc = GENERATION_START_TSC.get();
                        let elapsed_tsc = packet_end_tsc.saturating_sub(start_tsc);

                        let elapsed_micros = if config.tsc_frequency > 0 {
                            (elapsed_tsc as u128 * 1_000_000) / config.tsc_frequency as u128
                        } else {
                            0
                        };

                        let packets = gen.packets_sent as u128;
                        let packets_per_second = (packets * 1_000_000)
                            .checked_div(elapsed_micros)
                            .unwrap_or(0);

                        diagnostics::report_generation_complete(
                            packets,
                            elapsed_micros,
                            packets_per_second,
                            gen.cycle_accumulator,
                        );
                    }

                    stats[STAT_SENT_SYN] += 1;
                    ROUTE_TX
                }
            }
        };

        packet.set_action(action);
    }

    batch_size
}
struct GeneratorEngine;

impl Guest for GeneratorEngine {
    fn upgrade_shared_state(
        _source_schema_version: u32,
        _source_payload_size: u32,
    ) -> Result<(), String> {
        Err(String::from("generator_engine has no shared-state migration"))
    }

    // - init_data is called once per plugin instance, and is responsible for initializing the state of the plugin.
    // - It is called before any other function in the plugin.
    // - The init_data function is called with the following arguments:
    //   - data: A vector of key-value pairs, where each pair is a (key, value) tuple.
    //     The key value pairs are set in the .toml file for a node of type WasmEngine in the section "node_data"
    //   - tsc_frequency: The frequency of the TSC counter, in Hz.
    // - The init_data function should initialize the plugin's state, such as the connection pool
    //   or any other state that needs to be maintained across batches.
    // - The init_data function also stores the TSC frequency in GeneratorConfig.
    // - The init_data function returns a boolean value indicating whether the initialization was successful.
    // - If the initialization is successful, the plugin will be ready to process batches.
    fn init_data(
        data: Vec<(alloc::string::String, alloc::string::String)>,
        tsc_frequency: u64,
    ) -> bool {
        init_logging();

        let batch_size = data
            .iter()
            .find(|(key, _)| key == "batch_size")
            .and_then(|(_, value)| value.parse::<u32>().ok())
            .unwrap_or(MAX_BATCH_SIZE as u32);
        if batch_size == 0 || batch_size > MAX_BATCH_SIZE as u32 {
            log::error!(
                "generator engine initialization failed: batch_size must be between 1 and {}",
                MAX_BATCH_SIZE
            );
            return false;
        }

        let configured_variance = data
            .iter()
            .find(|(key, _)| key == "batch_size_variance")
            .map(|(_, value)| value.parse::<u32>());
        let batch_size_variance = match configured_variance {
            Some(Ok(variance)) => variance,
            Some(Err(_)) => {
                log::error!(
                    "generator engine initialization failed: batch_size_variance must be a non-negative integer"
                );
                return false;
            }
            None => 0, // Keep batch targets fixed unless variance is configured.
        };
        if batch_size_variance >= batch_size
            || batch_size.saturating_add(batch_size_variance) > MAX_BATCH_SIZE as u32
        {
            log::error!(
                "generator engine initialization failed: batch_size {} with batch_size_variance {} must stay between 1 and MAX_BATCH_SIZE {}",
                batch_size,
                batch_size_variance,
                MAX_BATCH_SIZE
            );
            return false;
        }

        let Some((config, _node_name)) = parse_generator_config(data, tsc_frequency) else {
            log::error!(
                "generator engine initialization failed: invalid or incomplete configuration"
            );
            return false;
        };
        *CONFIG.borrow_mut() = Some(config);
        CONFIGURED_BATCH_SIZE.set(batch_size);
        CONFIGURED_BATCH_SIZE_VARIANCE.set(batch_size_variance);

        true
    }

    fn process_batch(batch_size: u32, umem_offset: u32, mailbox_offset: u32) -> u32 {
        let config_guard = CONFIG.borrow();
        let Some(config) = config_guard.as_ref() else {
            // init_data is required to succeed before process_batch is called.
            // Fail closed if the host violates that lifecycle contract.
            drop(config_guard);
            let mut batch = MailboxBatch::new(batch_size, umem_offset, mailbox_offset);
            for mut packet in batch.iter_mut() {
                packet.set_action(ROUTE_DROP);
            }
            return batch_size;
        };

        let protocol = config.protocol;
        let config = GeneratorBatchConfig {
            generation_rate: config.generation_rate.unwrap_or(0),
            generation_limit: config.generation_limit,
            src_ip: u32::from_be_bytes(config.src_ip.unwrap_or([0; 4])),
            dst_ip: u32::from_be_bytes(config.dst_ip.unwrap_or([0; 4])),
            src_mac: config.src_mac.unwrap_or([0; 6]),
            dst_mac: config.dst_mac.unwrap_or([0xff; 6]),
            tsc_frequency: config.tsc_frequency,
        };
        match protocol {
            GeneratorProtocol::Syn => {
                process_batch_for_protocol::<false>(batch_size, umem_offset, mailbox_offset, config)
            }
            GeneratorProtocol::Udp => {
                process_batch_for_protocol::<true>(batch_size, umem_offset, mailbox_offset, config)
            }
        }
    }

    fn process_timers(current_tsc: u64) -> TimerPlan {
        // Global state updates remain imperative but concise
        CURRENT_TSC.set(current_tsc);
        diagnostics::record_timer_poll(current_tsc);
        if RUN_START_TSC.get() == 0 {
            RUN_START_TSC.set(current_tsc);
        }

        // Pattern match the config to extract only what we need, or return early
        let config_guard = CONFIG.borrow();
        let (tsc_freq, rate, limit) = match config_guard.as_ref() {
            Some(c) if c.tsc_frequency > 0 && c.generation_rate.unwrap_or(0) > 0 => (
                c.tsc_frequency,
                c.generation_rate.unwrap(),
                c.generation_limit,
            ),
            _ => {
                return TimerPlan {
                    timeout_frames: 0,
                    packet_frames: 0,
                }
            }
        };

        // Evaluate the frame generation as a single expression
        let packet_frames = {
            let mut gen = PACKET_GEN.borrow_mut();

            // Check if we are stopped by a limit (treating Some(0) as unlimited)
            let limit_reached = limit.is_some_and(|max| max > 0 && gen.packets_sent >= max);

            if !gen.activated || limit_reached {
                0 // Block evaluates to 0, no frames generated
            } else {
                // Calculate time delta
                let delta_tsc = if gen.last_tsc == 0 {
                    0
                } else {
                    current_tsc.saturating_sub(gen.last_tsc)
                };
                gen.last_tsc = current_tsc;

                // Accumulate cycles
                gen.cycle_accumulator = gen
                    .cycle_accumulator
                    .saturating_add(delta_tsc.saturating_mul(rate));
                diagnostics::record_cycle_credit(delta_tsc.saturating_mul(rate));

                // Calculate how many frames the cycles allow
                let available_frames = gen.cycle_accumulator / tsc_freq;
                diagnostics::record_available_frames(available_frames);

                let nominal_batch = CONFIGURED_BATCH_SIZE.get().clamp(1, MAX_BATCH_SIZE as u32);
                let delta = CONFIGURED_BATCH_SIZE_VARIANCE.get();
                let mut target = NEXT_BATCH_TARGET.get();
                if target == 0 {
                    target = if delta > 0 {
                        let mut prng = JITTER_PRNG_STATE.get();
                        let rand_val = xorshift64(&mut prng);
                        JITTER_PRNG_STATE.set(prng);
                        let span = (2 * delta).saturating_add(1);
                        (nominal_batch - delta).saturating_add((rand_val % (span as u64)) as u32)
                    } else {
                        nominal_batch
                    };
                    NEXT_BATCH_TARGET.set(target);
                }

                // If a generation limit is active and remaining packets is smaller than target,
                // cap target so we don't stall waiting for unreachable credits.
                let effective_target = match limit {
                    Some(max) if max > 0 => {
                        let remaining = max.saturating_sub(gen.packets_sent);
                        (target as u64).min(remaining) as u32
                    }
                    _ => target,
                };

                let final_frames =
                    if effective_target > 0 && available_frames >= (effective_target as u64) {
                        let frames = (available_frames as u32).min(effective_target);
                        NEXT_BATCH_TARGET.set(0);
                        frames
                    } else {
                        0
                    };

                diagnostics::record_final_frames(
                    available_frames,
                    effective_target as u64,
                    final_frames,
                    nominal_batch,
                );

                // Deduct consumed cycles immediately
                if final_frames > 0 {
                    gen.cycle_accumulator = gen
                        .cycle_accumulator
                        .saturating_sub((final_frames as u64).saturating_mul(tsc_freq));
                    diagnostics::record_requested_frames(final_frames);
                }

                final_frames
            }
        };

        TimerPlan {
            timeout_frames: 0,
            packet_frames,
        }
    }

    // Inside the Wasm plugin code

    fn on_control_event(raw_opcode: u32, payload: Vec<u8>) -> bool {
        match handle_control_event(raw_opcode, &payload, &CONFIG, &PACKET_GEN) {
            ControlResult::Flush(mode) => {
                flush_state(mode);
                true
            }
            ControlResult::Handled => true,
            ControlResult::Invalid => false,
        }
    }

    fn get_telemetry_schema() -> TelemetrySchema {
        TelemetrySchema {
            counters: TCP_STAT_NAMES
                .iter()
                .map(|name| String::from(*name))
                .chain(core::iter::once(String::from("watermark")))
                .collect(),
            histograms: Vec::new(),
        }
    }

    fn get_telemetry() -> Vec<TelemetryMetric> {
        let mut stats = TCP_STATS.borrow().to_vec();
        // Add current pool usage to stats
        if let Some(pool) = CONNECTIONS.borrow().as_ref() {
            stats.push(pool.watermark as u64); // Current active/reused nodes
        }
        stats
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                TelemetryMetric::Counter(Counter {
                    name: if index < TCP_STAT_NAMES.len() {
                        String::from(TCP_STAT_NAMES[index])
                    } else {
                        String::from("watermark")
                    },
                    value,
                })
            })
            .collect()
    }
}

fn set_state(state: u8) {
    let mut packet_gen = PACKET_GEN.borrow_mut();
    let mut config_guard = CONFIG.borrow_mut();

    // Safely attempt to modify the config only if it exists
    if let Some(config) = config_guard.as_mut() {
        match state {
            0 => {
                // State 0: Offline / Paused
                packet_gen.activated = false;
                config.bypass = false;
            }
            1 => {
                // State 1: Online / Active
                packet_gen.activated = true;
                config.bypass = false;
            }
            2 => {
                // State 2: Bypass Mode
                // Disable generation, let all traffic flow transparently
                packet_gen.activated = false;
                config.bypass = true;
            }
            _ => {
                // Ignore unknown states
            }
        }
    }
}

fn flush_state(mode: u8) {
    // This stops the generator and prevents a new run from starting automatically.
    set_state(0);

    // Clear the pool in-place instead of re-allocating
    if let Some(pool) = CONNECTIONS.borrow_mut().as_mut() {
        pool.clear();
    }

    // Clear the pending timeout teardowns so we don't send FINs for connections
    // that just got wiped out.
    TIMEOUT_QUEUE.borrow_mut().clear();

    // Reset the SYN generator tracking
    {
        let mut packet_gen = PACKET_GEN.borrow_mut();
        packet_gen.packets_sent = 0;
        packet_gen.cycle_accumulator = 0;
        packet_gen.last_tsc = 0;

        // Reset inter-batch jitter target
        NEXT_BATCH_TARGET.set(0);

        // Optional: If mode == 1 (Hard Reset), also reset the PRNG and Port Counter
        // to ensure perfectly repeatable PCAP generation across test runs.
        if mode == 1 {
            packet_gen.port_counter = PORT_START_RANGE;
            packet_gen.prng_state = 1;
            JITTER_PRNG_STATE.set(0x853c49e6748fea9b);
        }
    }

    // 5. Clear all telemetry counters
    *TCP_STATS.borrow_mut() = [0; STAT_COUNT];

    log::trace!("TCP Engine state flushed (mode: {})", mode);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;
    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn udp_template_matches_full_packet_checksum() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let config = GeneratorBatchConfig {
            generation_rate: 1,
            generation_limit: None,
            src_ip: 0x0a0a0ade,
            dst_ip: 0x0a0a0a1f,
            src_mac: [0x44, 0x49, 0x88, 0x06, 0x63, 0x38],
            dst_mac: [0x44, 0x49, 0x88, 0x06, 0x63, 0x39],
            tsc_frequency: 3_417_600_000,
        };

        for timestamp in [0, 1, 0x1234_5678_9abc_def0, u64::MAX] {
            let template = UdpPacketTemplate::new(config, timestamp);
            assert_eq!(&template.payload[..4], &TIMESTAMP_MAGIC);
            assert_eq!(
                &template.payload[TIMESTAMP_MAGIC.len()..UDP_SEQUENCE_OFFSET],
                &timestamp.to_be_bytes()
            );

            let sequence: u64 = 0x0123_4567_89ab_cdef;
            let mut payload = [0u8; UDP_PAYLOAD_LEN];
            payload[..UDP_SEQUENCE_OFFSET].copy_from_slice(&template.payload);
            payload[UDP_SEQUENCE_OFFSET..].copy_from_slice(&sequence.to_be_bytes());

            for port in [
                0,
                1,
                PORT_START_RANGE,
                32_768,
                template.checksum_without_dynamic_fields,
                PORT_END_RANGE,
            ] {
                let udp = template.udp_header_for_packet(port, sequence);
                let mut full_datagram = [0u8; size_of::<UdpHdr>() + UDP_PAYLOAD_LEN];
                unsafe {
                    ptr::copy_nonoverlapping(
                        (&raw const udp).cast::<u8>(),
                        full_datagram.as_mut_ptr(),
                        size_of::<UdpHdr>(),
                    );
                }
                full_datagram[size_of::<UdpHdr>()..].copy_from_slice(&payload);
                let expected = ipv4_checksum(
                    full_datagram.as_mut_ptr(),
                    full_datagram.len(),
                    3,
                    &[],
                    config.src_ip,
                    config.dst_ip,
                    17,
                );
                assert_eq!(
                    udp.checksum(),
                    expected,
                    "timestamp={timestamp} port={port}"
                );
            }
        }
    }

    #[test]
    fn process_timers_jitter_bounds_and_conservation() {
        let _guard = TEST_MUTEX.lock().unwrap();
        flush_state(1);
        set_state(1);

        let tsc_freq = 3_000_000_000u64; // 3 GHz
        let rate = 1_000_000u64; // 1 Mpps
        let nominal_batch = 32u32;
        CONFIGURED_BATCH_SIZE.set(nominal_batch);
        CONFIGURED_BATCH_SIZE_VARIANCE.set(nominal_batch / 2);

        let mut config = GeneratorConfig::default();
        config.tsc_frequency = tsc_freq;
        config.generation_rate = Some(rate);
        config.generation_limit = None;
        *CONFIG.borrow_mut() = Some(config);

        let mut current_tsc = 10_000_000u64;
        let mut total_packets = 0u64;
        let mut batch_sizes = Vec::new();

        // Step through small time slices (e.g. 5 microseconds each step)
        let delta_step = 15_000u64; // 5us at 3GHz = 15,000 cycles (expecting ~5 packets per step)
        for _ in 0..10_000 {
            current_tsc += delta_step;
            let plan = GeneratorEngine::process_timers(current_tsc);
            if plan.packet_frames > 0 {
                assert!(
                    plan.packet_frames <= MAX_BATCH_SIZE as u32,
                    "Batch size {} exceeded MAX_BATCH_SIZE {}",
                    plan.packet_frames,
                    MAX_BATCH_SIZE
                );
                assert!(
                    plan.packet_frames >= (nominal_batch / 2),
                    "Batch size {} below minimum expected",
                    plan.packet_frames
                );
                assert!(
                    plan.packet_frames <= (nominal_batch + nominal_batch / 2),
                    "Batch size {} above maximum expected",
                    plan.packet_frames
                );
                total_packets += plan.packet_frames as u64;
                batch_sizes.push(plan.packet_frames);
            }
        }

        // Verify there is variation in batch sizes
        let first_size = batch_sizes[0];
        let has_variation = batch_sizes.iter().any(|&s| s != first_size);
        assert!(has_variation, "Batch sizes should vary dynamically");

        // Verify that total packets generated matches expected rate over total elapsed time
        let elapsed_tsc = 10_000 * delta_step;
        let expected_packets = (elapsed_tsc * rate) / tsc_freq;
        let diff = total_packets.abs_diff(expected_packets);
        assert!(
            diff <= MAX_BATCH_SIZE as u64,
            "Total generated packets {} deviated significantly from expected {}",
            total_packets,
            expected_packets
        );
    }

    #[test]
    fn process_timers_respects_max_batch_size_when_configured_large() {
        let _guard = TEST_MUTEX.lock().unwrap();
        flush_state(1);
        set_state(1);

        let tsc_freq = 3_000_000_000u64;
        let rate = 10_000_000u64;
        CONFIGURED_BATCH_SIZE.set(MAX_BATCH_SIZE as u32);
        CONFIGURED_BATCH_SIZE_VARIANCE.set(0);

        let mut config = GeneratorConfig::default();
        config.tsc_frequency = tsc_freq;
        config.generation_rate = Some(rate);
        config.generation_limit = None;
        *CONFIG.borrow_mut() = Some(config);

        let mut current_tsc = 10_000_000u64;
        // Large jump in TSC
        current_tsc += 3_000_000_000u64; // 1 second
        let plan = GeneratorEngine::process_timers(current_tsc);

        assert!(
            plan.packet_frames <= MAX_BATCH_SIZE as u32,
            "Packet frames {} exceeded MAX_BATCH_SIZE {}",
            plan.packet_frames,
            MAX_BATCH_SIZE
        );
    }
}

// Export the implementation to the runtime
export!(GeneratorEngine);
