#![no_std]

extern crate alloc;

use crate::exports::wabrix::plugins::packet_engine::{
    Counter, Guest, TelemetryMetric, TelemetrySchema, TimerPlan,
};
use crate::wabrix::plugins::logging;
use alloc::string::String;
use alloc::vec::Vec;
use wabrix_plugins::connections::{ConnectionPool, FlowKey, TcpState};
use wabrix_plugins::engine_common::{
    handle_control_event, parse_tcp_engine_config, ControlResult, WasmCell, WasmValue,
};
use wabrix_api::helpers::parse_suffixed_number;
use wabrix_api::mailbox_api::MailboxBatch;
use wabrix_api::packet::Packet;
use wabrix_plugins::tcp_common::{run_tcp_state_machine, tcp_flags, tcp_telemetry, write_tcp_packet, PacketGenerator, TcpEngineConfig, TimeoutStack, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, PORT_END_RANGE, PORT_START_RANGE, STAT_COUNT, STAT_DROP, STAT_RECV_RST, STAT_RECV_SYN, STAT_SENT_FIN, STAT_SENT_RST, STAT_SENT_SYN, STAT_SENT_SYNACK, STAT_TICK_DROP, STAT_TO_LINUX, STAT_UNEXPECTED, TCP_ROUTE_DROP as ROUTE_DROP, TCP_ROUTE_LINUX as ROUTE_LINUX, TCP_ROUTE_TX as ROUTE_TX, TCP_STAT_NAMES};
use wabrix_api::{
    EngineTimerPlan, HotWasmPayload, PluginOpcode, StandardOpcode, MAX_BATCH_SIZE, TIMER_KIND_NONE,
    TIMER_KIND_TIMEOUT,
};

// 1. Tell the macro to read the .wit file and generate the bindings
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "engine-plugin",
});

// =====================================================================
// ZERO-COST WASM STATE CONTAINERS
// =====================================================================

// A zero-cost, single-threaded state container for WASM.
// Uses `RefCell` to prevent re-entrancy panics, but uses NO ATOMICS.
// An even faster container for simple Copy types (like u64).
// Uses `Cell`, which doesn't even have a borrow counter. Absolute zero overhead.
static CONFIG: WasmCell<Option<TcpEngineConfig>> = WasmCell::new(None);
static CONNECTIONS: WasmCell<Option<ConnectionPool>> = WasmCell::new(None);
static TIMEOUT_QUEUE: WasmCell<TimeoutStack> = WasmCell::new(TimeoutStack::new());
static SYN_GEN: WasmCell<PacketGenerator> = WasmCell::new(PacketGenerator {
    last_tsc: 0,
    cycle_accumulator: 0,
    port_counter: PORT_START_RANGE,
    ip_offset: 0,
    prng_state: 1,
    packets_sent: 0,
    activated: true,
});

// Replaced AtomicU64 and Mutex<u64> with WasmValue (Instant access)
static CURRENT_TSC: WasmValue<u64> = WasmValue::new(0);
static LAST_TIMEOUT_SCAN: WasmValue<u64> = WasmValue::new(0);
static RUN_START_TSC: WasmValue<u64> = WasmValue::new(0);
static LAST_TIMER_LOG_TSC: WasmValue<u64> = WasmValue::new(0);

const TIMEOUT_SCAN_INTERVAL_MILLIS: u64 = 10;
const TIMEOUT_SCAN_INTERVAL_DIVISOR: u64 = 1_000 / TIMEOUT_SCAN_INTERVAL_MILLIS;

const MAX_CONNECTIONS: usize = 524_288;
//const MAX_CONNECTIONS: usize = 1_048_576;

#[inline]
fn timeout_scan_interval_cycles(tsc_frequency: u64) -> u64 {
    tsc_frequency / TIMEOUT_SCAN_INTERVAL_DIVISOR
}

// The zero-cost global counter array
static TCP_STATS: WasmCell<[u64; STAT_COUNT]> = WasmCell::new([0; STAT_COUNT]);

// The macro to use inside process_batch
macro_rules! inc_stat {
    ($stat:expr) => {
        TCP_STATS.borrow_mut()[$stat] += 1
    };
}

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true // You can add level filtering here if you want to save cycles
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            // Format the message using the alloc crate
            let msg = alloc::format!("tcp_engine: {}", record.args());
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

fn init_state_machine(tcp_node_name: String) {
    // 524,288 is a power of 2. It will consume ~25MB of Wasm heap instantly at boot,
    // but it will NEVER trigger a resize or memory.grow during execution.
    *CONNECTIONS.borrow_mut() = Some(ConnectionPool::new(MAX_CONNECTIONS, tcp_node_name));
}

struct TcpEngine;

impl Guest for TcpEngine {
    fn upgrade_shared_state(
        _source_schema_version: u32,
        _source_payload_size: u32,
    ) -> Result<(), String> {
        Err(String::from("tcp_engine has no shared-state migration"))
    }

    // - init_data is called once per plugin instance, and is responsible for initializing the state of the plugin.
    // - It is called before any other function in the plugin.
    // - The init_data function is called with the following arguments:
    //   - data: A vector of key-value pairs, where each pair is a (key, value) tuple.
    //     The key value pairs are set in the .toml file for a node of type WasmEngine in the section "node_data"
    //   - tsc_frequency: The frequency of the TSC counter, in Hz.
    // - The init_data function should initialize the plugin's state, such as the connection pool
    //   or any other state that needs to be maintained across batches.
    // - The init_data function should also set the tsc_frequency value in the EngineConfig struct.
    // - The init_data function returns a boolean value indicating whether the initialization was successful.
    // - If the initialization is successful, the plugin will be ready to process batches.
    fn init_data(
        data: Vec<(alloc::string::String, alloc::string::String)>,
        tsc_frequency: u64,
    ) -> bool {
        init_logging();
        let (config, node_name) = match parse_tcp_engine_config(data, tsc_frequency) {
            Ok(result) => result,
            Err(error) => {
                log::warn!("TCP engine initialization rejected: {}", error);
                return false;
            }
        };

        init_state_machine(node_name);

        *CONFIG.borrow_mut() = Some(config);

        true
    }

    fn process_batch(batch_size: u32, umem_offset: u32, mailbox_offset: u32) -> u32 {
        log::trace!(
            "process_batch: batch_size={}, umem_offset={}",
            batch_size,
            umem_offset
        );
        let mut batch = MailboxBatch::new(batch_size, umem_offset, mailbox_offset);

        // - Keep the configuration borrowed for the duration of the batch
        // - Prevents heap allocation of the node name string on the hot path
        let config_guard = CONFIG.borrow();
        let Some(local_config) = config_guard.as_ref() else {
            log::error!("process_batch: missing configuration");
            for mut packet in batch.iter_mut() {
                packet.set_action(ROUTE_DROP);
            }
            return batch_size;
        };

        let mut processed_count = 0;

        // Fast-Path Bypass
        if local_config.bypass {
            for mut packet in batch.iter_mut() {
                let action = if packet.tick_kind().is_some() {
                    inc_stat!(STAT_DROP);
                    inc_stat!(STAT_TICK_DROP);
                    ROUTE_DROP
                } else {
                    inc_stat!(STAT_TO_LINUX);
                    ROUTE_LINUX
                };
                packet.set_action(action);
                processed_count += 1;
            }
            return processed_count;
        }

        let mut connections_guard = CONNECTIONS.borrow_mut();
        let Some(pool) = connections_guard.as_mut() else {
            log::error!("process_batch: connection table uninitialized — dropping all packets");
            for mut packet in batch.iter_mut() {
                packet.set_action(ROUTE_DROP);
                processed_count += 1;
            }
            return processed_count;
        };
        let touch_interval_cycles = timeout_scan_interval_cycles(local_config.tsc_frequency);

        // Hoist pre-parsed MAC addresses outside the packet iteration loop
        let reply_src_mac = local_config.src_mac.unwrap_or([0; 6]);
        let reply_dst_mac = local_config.dst_mac.unwrap_or([0xff; 6]);

        // Pre-calculate integer IP representations once per batch
        let base_src_ip = u32::from_be_bytes(local_config.src_ip.unwrap_or([0, 0, 0, 0]));
        let base_dst_ip = u32::from_be_bytes(local_config.dst_ip.unwrap_or([0, 0, 0, 0]));
        let generation_rate = local_config.generation_rate.unwrap_or(0);

        for mut packet in batch.iter_mut() {
            let tick_kind = packet.tick_kind();
            let is_tick = tick_kind.is_some();
            let timer_kind = tick_kind.unwrap_or(TIMER_KIND_NONE);

            let (action, _len) = if is_tick {
                log::trace!("process_batch: tick");
                let mut a = ROUTE_DROP;
                let mut l = 64u32;
                let mut generated_reply = false;

                // PRIORITY 1: Process Timeout Teardowns
                let pending_timeout = if timer_kind == TIMER_KIND_TIMEOUT {
                    let mut queue = TIMEOUT_QUEUE.borrow_mut();
                    queue.pop()
                } else {
                    None
                };

                if let Some(flow_key) = pending_timeout {
                    log::trace!(
                        "process_batch: processing timeout for flow_key {:?}",
                        flow_key
                    );
                    let current_tsc = CURRENT_TSC.get();
                    let (snd_nxt, rcv_nxt, state, exists) =
                        if let Some(conn) = pool.get_mut_and_touch(&flow_key, current_tsc) {
                            (conn.snd_nxt, conn.rcv_nxt, conn.state, true)
                        } else {
                            (0, 0, TcpState::Closed, false)
                        };

                    if exists {
                        if state == TcpState::Established || state == TcpState::SynReceived {
                            if let Some(conn) = pool.get_mut(&flow_key) {
                                conn.state = TcpState::FinWait1;
                                conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
                            }
                            l = write_tcp_packet(
                                packet.as_packet(),
                                reply_src_mac,
                                reply_dst_mac,
                                flow_key.2,
                                flow_key.3,
                                flow_key.0,
                                flow_key.1,
                                snd_nxt,
                                rcv_nxt,
                                FLAG_FIN | FLAG_ACK,
                            );
                            inc_stat!(STAT_SENT_FIN);
                            a = ROUTE_TX;
                            generated_reply = true;
                        } else {
                            pool.remove(&flow_key);
                            inc_stat!(STAT_SENT_RST);
                            l = write_tcp_packet(
                                packet.as_packet(),
                                reply_src_mac,
                                reply_dst_mac,
                                flow_key.2,
                                flow_key.3,
                                flow_key.0,
                                flow_key.1,
                                snd_nxt,
                                rcv_nxt,
                                FLAG_RST | FLAG_ACK,
                            );
                            a = ROUTE_TX;
                            generated_reply = true;
                        }
                    }
                }

                // PRIORITY 2: Generate new SYNs
                if !generated_reply && timer_kind != TIMER_KIND_TIMEOUT {
                    log::trace!("process_batch: generating new SYN");
                    if generation_rate > 0 {
                        let mut gen = SYN_GEN.borrow_mut();
                        let allowed_to_send = gen.activated
                            && match local_config.syn_limit {
                                Some(max_syns) => gen.packets_sent < max_syns || max_syns == 0,
                                None => true,
                            };

                        if allowed_to_send {
                            gen.packets_sent += 1;
                            gen.prng_state = gen
                                .prng_state
                                .wrapping_mul(1664525)
                                .wrapping_add(1013904223);
                            let isn = gen.prng_state;

                            let src_port = gen.port_counter;
                            let our_ip = base_src_ip.wrapping_add(gen.ip_offset);

                            if gen.port_counter == PORT_END_RANGE {
                                gen.port_counter = PORT_START_RANGE;
                                gen.ip_offset = (gen.ip_offset + 1) % 250;
                            } else {
                                gen.port_counter += 1;
                            }

                            let dst_port = 80;
                            let flow_key = FlowKey(base_dst_ip, dst_port, our_ip, src_port);
                            pool.insert(
                                flow_key,
                                TcpState::SynSent,
                                isn.wrapping_add(1),
                                0,
                                CURRENT_TSC.get(),
                            );

                            let reply_src_mac = local_config.src_mac.unwrap_or([0; 6]);
                            let reply_dst_mac = local_config.dst_mac.unwrap_or([0xff; 6]);

                            l = write_tcp_packet(
                                packet.as_packet(),
                                reply_src_mac,
                                reply_dst_mac,
                                our_ip,
                                src_port,
                                base_dst_ip,
                                dst_port,
                                isn,
                                0,
                                FLAG_SYN,
                            );
                            inc_stat!(STAT_SENT_SYN);
                            a = ROUTE_TX;
                            generated_reply = true;
                        }
                    }
                }

                if !generated_reply {
                    inc_stat!(STAT_DROP);
                    inc_stat!(STAT_TICK_DROP);
                    a = ROUTE_DROP;
                    l = 64;
                }
                (a, l)
            } else {
                if packet.fingerprint() == Packet::TCP_OVER_IPV4 {
                    let p = packet.as_packet();
                    unsafe { process_tcp_packet(p, pool, local_config, touch_interval_cycles) }
                } else {
                    inc_stat!(STAT_TO_LINUX);
                    (ROUTE_LINUX, packet.data_len())
                }
            };
            packet.set_action(action);
            processed_count += 1;
        }
        log::trace!(
            "process_batch: Finished successfully with {} packets",
            processed_count
        );
        processed_count
    }

    fn process_timers(current_tsc: u64) -> TimerPlan {
        // Share time with process_batch
        CURRENT_TSC.set(current_tsc);

        if RUN_START_TSC.get() == 0 {
            RUN_START_TSC.set(current_tsc);
        }

        // Keep the configuration borrowed for the duration of this read-only
        // operation. Cloning `EngineConfig` here would clone its optional
        // node name on every timer callback.
        let config_guard = CONFIG.borrow();
        let Some(config) = config_guard.as_ref() else {
            return TimerPlan {
                timeout_frames: 0,
                packet_frames: 0,
            };
        };
        let tsc_freq = config.tsc_frequency;

        if tsc_freq == 0 {
            return TimerPlan {
                timeout_frames: 0,
                packet_frames: 0,
            };
        }

        // =================================================================
        // 1. TIMEOUT SCAVENGER
        // =================================================================
        if let Some(timeout_cycles) = config.timeout_cycles {
            let last_scan = LAST_TIMEOUT_SCAN.get();

            // Run the table scan only once every 10ms to save CPU
            if current_tsc.saturating_sub(last_scan) > timeout_scan_interval_cycles(tsc_freq) {
                LAST_TIMEOUT_SCAN.set(current_tsc);
                let mut pool_guard = CONNECTIONS.borrow_mut();
                let mut queue = TIMEOUT_QUEUE.borrow_mut();

                if let Some(pool) = pool_guard.as_mut() {
                    let available_capacity = queue.available_capacity();
                    if available_capacity > 0 {
                        pool.scavenge_timeouts(
                            current_tsc,
                            timeout_cycles,
                            available_capacity,
                            &mut queue,
                        );
                    }
                }
            }
        }
        // Keep the pending count separate from the count that will be
        // scheduled below. The allocator reserves capacity for both timeout
        // cleanup and SYN generation, then fills any remaining slots.
        let pending_timeout_frames = TIMEOUT_QUEUE.borrow().len() as u32;

        // =================================================================
        // 2. SYN GENERATOR
        // =================================================================
        let generation_rate = config.generation_rate.unwrap_or(0);
        let mut syn_delta_tsc = 0;
        let mut desired_syn_frames = 0;
        let mut syn_accumulator = 0;
        if generation_rate > 0 {
            let mut gen = SYN_GEN.borrow_mut();

            let allowed_to_send = gen.activated
                && match config.syn_limit {
                    Some(max_syns) => gen.packets_sent < max_syns || max_syns == 0,
                    None => true,
                };

            if allowed_to_send {
                if gen.last_tsc == 0 {
                    gen.last_tsc = current_tsc;
                }
                let delta_tsc = current_tsc.saturating_sub(gen.last_tsc);
                gen.last_tsc = current_tsc;
                syn_delta_tsc = delta_tsc;

                gen.cycle_accumulator = gen
                    .cycle_accumulator
                    .saturating_add(delta_tsc.saturating_mul(generation_rate));
                let mut syn_frames = (gen.cycle_accumulator / tsc_freq) as u32;

                if let Some(max_syns) = config.syn_limit {
                    let remaining = max_syns.saturating_sub(gen.packets_sent);
                    if (syn_frames as u64) > remaining {
                        syn_frames = remaining as u32;
                    }
                }
                desired_syn_frames = syn_frames;

                log::trace!(
                    "process_timers: syn_frames= {}, gen.syns_sent= {}, max_syns= {:?}",
                    syn_frames,
                    gen.packets_sent,
                    config.syn_limit
                );
                // The accumulator is reduced after the fair allocation below
                // so SYN credit that does not fit in this batch is retained.
            }
        }

        let max_batch = MAX_BATCH_SIZE as u32;
        let desired_timeout_frames = pending_timeout_frames.min(max_batch);
        let desired_syn_frames = desired_syn_frames.min(max_batch);

        let (timeout_frames, packet_frames) =
            if desired_timeout_frames.saturating_add(desired_syn_frames) <= max_batch {
                (desired_timeout_frames, desired_syn_frames)
            } else {
                // Give each workload a guaranteed share when both are backlogged:
                // up to two thirds for timeout cleanup and at least one third for
                // SYNs. Any unused portion of either share is given to the other.
                let mut timeout_frames = desired_timeout_frames.min(2 * max_batch / 3);
                let mut syn_frames = desired_syn_frames.min(max_batch - timeout_frames);

                let mut remaining = max_batch - timeout_frames - syn_frames;
                let extra_timeout = (desired_timeout_frames - timeout_frames).min(remaining);
                timeout_frames += extra_timeout;
                remaining -= extra_timeout;
                syn_frames += (desired_syn_frames - syn_frames).min(remaining);
                (timeout_frames, syn_frames)
            };

        if generation_rate > 0 {
            let mut gen = SYN_GEN.borrow_mut();
            gen.cycle_accumulator = gen
                .cycle_accumulator
                .saturating_sub((packet_frames as u64).saturating_mul(tsc_freq));
            syn_accumulator = gen.cycle_accumulator;
        }

        let frames_to_request = timeout_frames + packet_frames;
        let potential_log = generation_rate > 0
            && ((pending_timeout_frames > (20 * MAX_BATCH_SIZE) as u32)
                || (packet_frames >= desired_syn_frames));

        if potential_log {
            let last_timer_log_tsc = LAST_TIMER_LOG_TSC.get();
            if last_timer_log_tsc == 0
                || current_tsc.saturating_sub(last_timer_log_tsc) >= 30 * tsc_freq
            {
                LAST_TIMER_LOG_TSC.set(current_tsc);
                let timestamp_micros = current_tsc
                    .saturating_sub(RUN_START_TSC.get())
                    .saturating_mul(1_000_000)
                    .checked_div(tsc_freq)
                    .unwrap_or(0);
                let timestamp_ms = timestamp_micros / 1_000;
                let timestamp_ms_fraction = timestamp_micros % 1_000;
                let delta_ms = syn_delta_tsc as f64 * 1_000.0 / tsc_freq as f64;
                log::debug!(
                    "process_timers: timestamp_ms={}.{:03}, delta_ms={:.3}, syn_frames={}, desired_syn_frames={}, syn_accumulator={}, timeout_frames={}, pending_timeout_frames={}, total_frames={}",
                    timestamp_ms,
                    timestamp_ms_fraction,
                    delta_ms,
                    packet_frames,
                    desired_syn_frames,
                    syn_accumulator,
                    timeout_frames,
                    pending_timeout_frames,
                    frames_to_request
                );
            }
        }

        let plan = EngineTimerPlan::new(timeout_frames, packet_frames, ROUTE_TX);
        TimerPlan {
            timeout_frames: plan.timeout_frames,
            packet_frames: plan.packet_frames,
        }
    }

    // Inside the Wasm plugin code

    fn on_control_event(raw_opcode: u32, payload: Vec<u8>) -> bool {
        return match handle_control_event(raw_opcode, &payload, &CONFIG, &SYN_GEN) {
            ControlResult::Flush(mode) => {
                flush_state(mode);
                true
            }
            ControlResult::Handled => true,
            ControlResult::Invalid => false,
        };

        #[allow(unreachable_code)]

        let opcode = PluginOpcode::from(raw_opcode);

        match opcode {
            PluginOpcode::Standard(StandardOpcode::SetOperationalState) => {
                if payload.len() == 1 {
                    let state = payload[0];
                    set_state(state);
                    log::info!("Operational state set to: {}", state);
                    true
                } else {
                    log::warn!("SetOperationalState failed: invalid payload length");
                    false
                }
            }
            PluginOpcode::Standard(StandardOpcode::FlushState) => {
                // Default to mode zero if no payload is provided
                // Parse the mode byte if available
                let mode = if payload.len() == 1 { payload[0] } else { 0 };
                flush_state(mode);
                log::info!("State flushed with mode: {}", mode);
                true
            }
            PluginOpcode::Standard(StandardOpcode::Ping) => {
                log::info!("PING received by TcpEngine");
                true
            }
            PluginOpcode::Standard(StandardOpcode::UpdateConfiguration) => {
                if let Ok(data) = postcard::from_bytes::<HotWasmPayload>(&payload) {
                    // Parse phase: validate all inputs before mutating state to ensure atomic updates
                    let parsed_generation_rate = match data.updates.get("generation_rate") {
                        Some(s) if s.is_empty() => Some(None),
                        Some(s) => match parse_suffixed_number(s) {
                            Ok(val) => Some(Some(val)),
                            Err(_) => {
                                log::warn!("UpdateConfiguration failed: invalid generation_rate");
                                return false;
                            }
                        },
                        None => None,
                    };

                    let parsed_syn_limit = match data.updates.get("syn_limit") {
                        Some(s) if s.is_empty() => Some(None),
                        Some(s) => match parse_suffixed_number(s) {
                            Ok(val) => Some(Some(val)),
                            Err(_) => {
                                log::warn!("UpdateConfiguration failed: invalid syn_limit");
                                return false;
                            }
                        },
                        None => None,
                    };

                    let parsed_close_timeout = match data.updates.get("close_timeout") {
                        Some(s) if s.is_empty() => Some(None),
                        Some(s) => match s.parse::<u64>() {
                            Ok(val) => Some(Some(val)),
                            Err(_) => {
                                log::warn!("UpdateConfiguration failed: invalid close_timeout");
                                return false;
                            }
                        },
                        None => None,
                    };

                    // Apply phase: compare against current state to prevent redundant updates and logs
                    let mut guard = CONFIG.borrow_mut();
                    if let Some(ref mut config) = *guard {
                        if let Some(new_val) = parsed_generation_rate {
                            if config.generation_rate != new_val {
                                config.generation_rate = new_val;
                                log::info!("UpdateConfiguration: generation_rate updated");
                            }
                        }
                        if let Some(new_val) = parsed_syn_limit {
                            if config.syn_limit != new_val {
                                config.syn_limit = new_val;
                                log::info!("UpdateConfiguration: syn_limit updated");
                            }
                        }
                        if let Some(new_val) = parsed_close_timeout {
                            if config.close_timeout_millis != new_val {
                                config.close_timeout_millis = new_val;
                                config.refresh_timeout_cycles();
                                log::info!("UpdateConfiguration: close_timeout updated");
                            }
                        }
                    }
                    true
                } else {
                    log::warn!("UpdateConfiguration failed: payload deserialization error");
                    false
                }
            }
            _ => {
                log::warn!("Ignored opcode: {:?}", opcode);
                false
            }
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
        let stats = TCP_STATS.borrow();
        let watermark = CONNECTIONS
            .borrow()
            .as_ref()
            .map(|pool| pool.watermark as u64)
            .unwrap_or(0);
        tcp_telemetry(&stats, watermark)
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
    let mut syn_gen = SYN_GEN.borrow_mut();
    let mut config_guard = CONFIG.borrow_mut();

    // Safely attempt to modify the config only if it exists
    if let Some(config) = config_guard.as_mut() {
        match state {
            0 => {
                // State 0: Offline / Paused
                syn_gen.activated = false;
                config.bypass = false;
            }
            1 => {
                // State 1: Online / Active
                syn_gen.activated = true;
                config.bypass = false;
            }
            2 => {
                // State 2: Bypass Mode
                // Disable generation, let all traffic flow transparently
                syn_gen.activated = false;
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
    LAST_TIMEOUT_SCAN.set(0);
    LAST_TIMER_LOG_TSC.set(0);

    // Reset the SYN generator tracking
    {
        let mut syn_gen = SYN_GEN.borrow_mut();
        syn_gen.packets_sent = 0;
        syn_gen.cycle_accumulator = 0;
        syn_gen.last_tsc = 0;

        // Optional: If mode == 1 (Hard Reset), also reset the PRNG and Port Counter
        // to ensure perfectly repeatable PCAP generation across test runs.
        if mode == 1 {
            syn_gen.port_counter = PORT_START_RANGE;
            syn_gen.prng_state = 1;
        }
    }

    // 5. Clear all telemetry counters
    *TCP_STATS.borrow_mut() = [0; STAT_COUNT];

    log::trace!("TCP Engine state flushed (mode: {})", mode);
}

/// Extracts protocol data, runs the state machine, and formats replies
unsafe fn process_tcp_packet(
    packet: &mut Packet,
    pool: &mut ConnectionPool,
    config: &TcpEngineConfig,
    touch_interval_cycles: u64,
) -> (u32, u32) {
    let current_tsc = CURRENT_TSC.get();

    // Safely extract the strongly-typed headers using the Context Wrapper
    let mac_hdr = match packet.eth_header() {
        Some(m) => m,
        None => return (ROUTE_LINUX, packet.data_len()),
    };
    let ip_hdr = match packet.ipv4_header() {
        Some(i) => i,
        None => return (ROUTE_LINUX, packet.data_len()),
    };
    let tcp_hdr = match packet.tcp_header() {
        Some(t) => t,
        None => return (ROUTE_LINUX, packet.data_len()),
    };

    let incoming_src_mac = mac_hdr.src_addr;
    let incoming_dst_mac = mac_hdr.dst_addr;

    let src_ip = u32::from(ip_hdr.src_addr());
    let dst_ip = u32::from(ip_hdr.dst_addr());
    let src_port = u16::from_be_bytes(tcp_hdr.source);
    let dst_port = u16::from_be_bytes(tcp_hdr.dest);
    let flow_key = FlowKey(src_ip, src_port, dst_ip, dst_port);
    log::trace!(
        "process_tcp_packet: processing packet with flow_key {:?}",
        flow_key
    );

    let tcp_flags = tcp_flags(tcp_hdr);
    let seq_num = u32::from_be_bytes(tcp_hdr.seq);
    let ack_num = u32::from_be_bytes(tcp_hdr.ack_seq);

    let ip_total_len = ip_hdr.tot_len() as u32;
    let ip_hdr_len = ip_hdr.ihl() as u32;
    let tcp_hdr_len = tcp_hdr.doff() as u32 * 4;
    let payload_len = ip_total_len.saturating_sub(ip_hdr_len + tcp_hdr_len);

    let action_opt;
    let mut current_state = None;

    if let Some(conn) =
        pool.get_mut_and_touch_if_elapsed(&flow_key, current_tsc, touch_interval_cycles)
    {
        // Scope the borrow so it drops immediately after the state machine runs
        let mut stats_guard = TCP_STATS.borrow_mut();
        action_opt = run_tcp_state_machine(
            conn,
            tcp_flags,
            seq_num,
            ack_num,
            payload_len,
            &mut stats_guard,
        );
        current_state = Some(conn.state);
    } else {
        if tcp_flags & FLAG_RST != 0 {
            inc_stat!(STAT_RECV_RST);
            return (ROUTE_DROP, 0);
        }
        // Catch stray ACKs and SYN-ACKs for dead connections
        if tcp_flags & FLAG_ACK != 0 {
            inc_stat!(STAT_UNEXPECTED);
            let reply_seq = ack_num;
            let reply_ack = seq_num
                .wrapping_add(payload_len)
                .wrapping_add(if tcp_flags & FLAG_FIN != 0 { 1 } else { 0 });

            inc_stat!(STAT_SENT_RST);
            action_opt = Some((FLAG_RST | FLAG_ACK, reply_seq, reply_ack));
        } else if tcp_flags & FLAG_SYN != 0 {
            inc_stat!(STAT_RECV_SYN);
            let rcv_nxt = seq_num.wrapping_add(1);
            let initial_snd_nxt = 1000u32;
            pool.insert(
                flow_key,
                TcpState::SynReceived,
                initial_snd_nxt.wrapping_add(1),
                rcv_nxt,
                current_tsc,
            );

            inc_stat!(STAT_SENT_SYNACK);
            action_opt = Some((FLAG_SYN | FLAG_ACK, initial_snd_nxt, rcv_nxt));
        } else {
            inc_stat!(STAT_UNEXPECTED);
            let reply_seq = if tcp_flags & FLAG_ACK != 0 {
                ack_num
            } else {
                0
            };
            let reply_ack = seq_num
                .wrapping_add(payload_len)
                .wrapping_add(if tcp_flags & FLAG_FIN != 0 { 1 } else { 0 });

            inc_stat!(STAT_SENT_RST);
            action_opt = Some((FLAG_RST | FLAG_ACK, reply_seq, reply_ack));
        }
    }

    if current_state == Some(TcpState::Closed) {
        pool.remove(&flow_key);
    }

    if let Some((reply_flags, reply_seq, reply_ack)) = action_opt {
        let reply_dst_mac = incoming_src_mac;
        let reply_src_mac = config.src_mac.unwrap_or(incoming_dst_mac);

        let len = write_tcp_packet(
            packet,
            reply_src_mac,
            reply_dst_mac,
            dst_ip,
            dst_port,
            src_ip,
            src_port,
            reply_seq,
            reply_ack,
            reply_flags,
        );
        return (ROUTE_TX, len);
    }

    (ROUTE_DROP, 0)
}

// Export the implementation to the runtime
export!(TcpEngine);
