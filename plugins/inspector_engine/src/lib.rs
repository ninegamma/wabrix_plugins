#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell, RefMut};

use crate::exports::wabrix::plugins::packet_engine::{
    Counter, Guest, Histogram, HistogramSchema, TelemetryMetric, TelemetrySchema, TimerPlan,
};
use crate::wabrix::plugins::logging;
use crate::wabrix::plugins::shared_state::{self, StateLayout};
//use macaddr::MacAddr6;
use wabrix_api::helpers::parse_mac;
use wabrix_api::mailbox_api::MailboxBatch;
use wabrix_api::SharedState;
use wabrix_api::{
    HotWasmPayload, PluginOpcode, StandardOpcode, MAX_HISTOGRAM_BUCKETS,
};

/// Histogram resolution and range shared by the inspector plugin and host.
pub const INSPECTOR_DELAY_HISTOGRAM_BUCKET_WIDTH_US: u64 = 10;
pub const INSPECTOR_DELAY_HISTOGRAM_FINITE_BUCKETS: usize = MAX_HISTOGRAM_BUCKETS -1;
const MAX_DELAY_WINDOW_INTERVALS: usize = 5;

wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "engine-plugin",
});

const ROUTE_TX: u32 = 0;
const ROUTE_DROP: u32 = 1;
const TIMESTAMP_MAGIC: [u8; 4] = *b"WABR";
const SEND_TSC_OFFSET: usize = TIMESTAMP_MAGIC.len();
const UDP_SEQUENCE_OFFSET: usize = SEND_TSC_OFFSET + core::mem::size_of::<u64>();
const GENERATED_UDP_PAYLOAD_LEN: usize = UDP_SEQUENCE_OFFSET + core::mem::size_of::<u64>();


struct WasmCell<T>(RefCell<T>);

unsafe impl<T> Sync for WasmCell<T> {}

impl<T> WasmCell<T> {
    const fn new(value: T) -> Self {
        Self(RefCell::new(value))
    }

    fn borrow(&self) -> Ref<'_, T> {
        self.0.borrow()
    }

    fn borrow_mut(&self) -> RefMut<'_, T> {
        self.0.borrow_mut()
    }
}

struct InspectorConfig {
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    delay_scale: DelayScale,
    shared_state: Option<SharedState<InspectorSharedState>>,
    pending_upgrade: Option<(u32, u32)>,
}

/// Persistent Inspector fields stored directly in the host-shared region.
#[repr(C)]
#[derive(Clone, Copy)]
struct InspectorSharedState {
    bypass: u8,
    _reserved: [u8; 7],
    packets_inspected: u64,
    bytes_inspected: u64,
    unexpected: u64,
    delay_samples: u64,
    delay_sum_us: u64,
    delay_histogram: [u64; MAX_HISTOGRAM_BUCKETS],
    // Peak in the current telemetry interval and the five latest interval peaks.
    max_delay_current_interval_us: u64,
    max_delay_intervals_us: [u64; MAX_DELAY_WINDOW_INTERVALS],
    max_delay_interval_cursor: u8,
    // Next sequence expected, starting at 1.
    next_sequence: u64,
    // Count of marked UDP packets with a readable sequence.
    sequence_packets: u64,
    // Missing sequence values inferred from forward gaps.
    sequence_missing: u64,
    // Packets whose sequence is below the expected value.
    sequence_out_of_sequence: u64,
    // Marked payloads too short to contain a sequence.
    sequence_malformed: u64,
    // Last totals logged, so telemetry reports only new anomalies.
    logged_sequence_missing: u64,
    logged_sequence_out_of_sequence: u64,
    logged_sequence_malformed: u64,
}

impl Default for InspectorSharedState {
    fn default() -> Self {
        Self {
            bypass: 0,
            _reserved: [0; 7],
            packets_inspected: 0,
            bytes_inspected: 0,
            unexpected: 0,
            delay_samples: 0,
            delay_sum_us: 0,
            delay_histogram: [0; MAX_HISTOGRAM_BUCKETS],
            max_delay_current_interval_us: 0,
            max_delay_intervals_us: [0; MAX_DELAY_WINDOW_INTERVALS],
            max_delay_interval_cursor: 0,
            next_sequence: 0,
            sequence_packets: 0,
            sequence_missing: 0,
            sequence_out_of_sequence: 0,
            sequence_malformed: 0,
            logged_sequence_missing: 0,
            logged_sequence_out_of_sequence: 0,
            logged_sequence_malformed: 0,
        }
    }
}

const INSPECTOR_SHARED_STATE_TYPE_ID: [u8; 16] = [
    0xf5, 0x7b, 0x87, 0x9a, 0x1c, 0xa2, 0x4e, 0xd9, 0xa9, 0x02, 0x7c, 0x2f, 0x8a, 0x5d, 0xb1, 0x34,
];
const INSPECTOR_SHARED_STATE_SCHEMA_VERSION: u32 = 2;

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            src_mac: None,
            dst_mac: None,
            delay_scale: DelayScale::new(0),
            shared_state: None,
            pending_upgrade: None,
        }
    }
}

static CONFIG: WasmCell<InspectorConfig> = WasmCell::new(InspectorConfig {
    src_mac: None,
    dst_mac: None,
    delay_scale: DelayScale::new(0),
    shared_state: None,
    pending_upgrade: None,
});

#[derive(Clone, Copy)]
struct DelayScale {
    frequency: u64,
    numerator: u32,
    denominator: u32,
    denominator_reciprocal: u64,
    max_fast_cycles: u32,
}

impl DelayScale {
    const fn new(frequency: u64) -> Self {
        // Reduce cycles * 1_000_000 / frequency once at initialization.
        let mut a = frequency;
        let mut b = 1_000_000u64;
        while b != 0 {
            let remainder = a % b;
            a = b;
            b = remainder;
        }
        let numerator = (1_000_000 / a) as u32;
        let denominator = frequency / a;
        if denominator <= u32::MAX as u64 {
            let denominator_reciprocal = match (u32::MAX as u64 + 1).checked_div(denominator) {
                Some(reciprocal) => reciprocal,
                None => 0,
            };
            Self {
                frequency,
                numerator,
                denominator: denominator as u32,
                denominator_reciprocal,
                max_fast_cycles: u32::MAX / numerator,
            }
        } else {
            Self {
                frequency,
                numerator,
                denominator: 0,
                denominator_reciprocal: 0,
                max_fast_cycles: 0,
            }
        }
    }
}

#[inline]
fn packet_delay_us(receive_tsc: u64, send_tsc: u64, scale: DelayScale) -> Option<u64> {
    if scale.frequency == 0 || receive_tsc < send_tsc {
        return None;
    }

    let elapsed_cycles = receive_tsc - send_tsc;
    if scale.denominator != 0 && elapsed_cycles <= scale.max_fast_cycles as u64 {
        let scaled_cycles = elapsed_cycles as u32 * scale.numerator;
        let quotient = ((u64::from(scaled_cycles) * scale.denominator_reciprocal) >> 32) as u32;
        let remainder = scaled_cycles - quotient * scale.denominator;
        // The floored reciprocal can underestimate the quotient by at most one
        // for a u32 dividend; this correction makes the result exact.
        return Some((quotient + u32::from(remainder >= scale.denominator)) as u64);
    }

    Some(packet_delay_us_fallback(elapsed_cycles, scale.frequency))
}

#[derive(Clone, Copy)]
struct GeneratedUdpMetadata {
    send_tsc: u64,
    sequence: u64,
}

#[inline(always)]
fn parse_generated_udp_payload(payload: &[u8]) -> Result<Option<GeneratedUdpMetadata>, ()> {
    if payload.get(..TIMESTAMP_MAGIC.len()) != Some(TIMESTAMP_MAGIC.as_slice()) {
        return Ok(None);
    }
    if payload.len() < GENERATED_UDP_PAYLOAD_LEN {
        return Err(());
    }

    let send_tsc = u64::from_be_bytes(
        payload[SEND_TSC_OFFSET..UDP_SEQUENCE_OFFSET]
            .try_into()
            .map_err(|_| ())?,
    );
    let sequence = u64::from_be_bytes(
        payload[UDP_SEQUENCE_OFFSET..GENERATED_UDP_PAYLOAD_LEN]
            .try_into()
            .map_err(|_| ())?,
    );
    Ok(Some(GeneratedUdpMetadata { send_tsc, sequence }))
}

#[inline(always)]
fn record_sequence(config: &mut InspectorSharedState, sequence: u64) {
    config.sequence_packets = config.sequence_packets.saturating_add(1);
    if sequence == config.next_sequence {
        config.next_sequence = config.next_sequence.saturating_add(1);
    } else if sequence > config.next_sequence {
        config.sequence_missing = config
            .sequence_missing
            .saturating_add(sequence - config.next_sequence);
        config.next_sequence = sequence.saturating_add(1);
    } else {
        config.sequence_out_of_sequence = config.sequence_out_of_sequence.saturating_add(1);
    }
}

#[cold]
fn packet_delay_us_fallback(elapsed_cycles: u64, tsc_frequency: u64) -> u64 {
    // Keep the exact wide-range behavior for values outside the 32-bit path.
    // The first case still avoids Wasm's software 128-bit division.
    if let Some(scaled_cycles) = elapsed_cycles.checked_mul(1_000_000) {
        return scaled_cycles / tsc_frequency;
    }

    let seconds = elapsed_cycles / tsc_frequency;
    let remainder = elapsed_cycles % tsc_frequency;
    let fractional_us = if let Some(scaled_remainder) = remainder.checked_mul(1_000_000) {
        scaled_remainder / tsc_frequency
    } else {
        // Compute the fractional part exactly even for unusually large TSC
        // frequencies. Modular doubling/addition keeps every intermediate u64.
        let mut fraction = 0u64;
        let mut residual = 0u64;
        for bit in (0..20).rev() {
            fraction *= 2;
            if residual >= tsc_frequency - residual {
                residual -= tsc_frequency - residual;
                fraction += 1;
            } else {
                residual *= 2;
            }
            if (1_000_000u64 >> bit) & 1 != 0 {
                if residual >= tsc_frequency - remainder {
                    residual -= tsc_frequency - remainder;
                    fraction += 1;
                } else {
                    residual += remainder;
                }
            }
        }
        fraction
    };
    // Preserve the original narrowing cast's wraparound for oversized results.
    seconds.wrapping_mul(1_000_000).wrapping_add(fractional_us)
}

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let message = alloc::format!("inspector_engine: {}", record.args());
            logging::log(record.level() as u32, &message);
        }
    }

    fn flush(&self) {}
}

fn init_logging() {
    static LOGGER: HostLogger = HostLogger;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);
}

fn set_shared_bypass(bypass: bool) -> bool {
    let mut config = CONFIG.borrow_mut();
    let Some(shared_state) = config.shared_state.as_mut() else {
        return false;
    };
    // SAFETY: Control events are delivered to the active instance at the
    // runner boundary, when no staged runtime accesses the shared payload.
    unsafe {
        shared_state.with_mut(|state| state.bypass = u8::from(bypass));
    }
    true
}

struct InspectorEngine;

impl Guest for InspectorEngine {
    fn init_data(data: Vec<(String, String)>, tsc_frequency: u64) -> bool {
        init_logging();
        let layout = StateLayout {
            type_id: INSPECTOR_SHARED_STATE_TYPE_ID.to_vec(),
            schema_version: INSPECTOR_SHARED_STATE_SCHEMA_VERSION,
            payload_size: core::mem::size_of::<InspectorSharedState>() as u32,
            reserved_capacity: 127 * 1024,
            required_alignment: core::mem::align_of::<InspectorSharedState>() as u32,
            compatible_source_versions: Vec::new(),
        };
        let view = match shared_state::attach(&layout) {
            Ok(view) => view,
            Err(error) => {
                log::error!("could not attach Inspector shared state: {}", error);
                return false;
            }
        };
        let pending_upgrade = view
            .upgrade_required
            .then_some((view.current_schema_version, view.current_payload_size));
        // SAFETY: The host validated the region bounds and layout and returned
        // an offset aligned for this payload type. During an append-only
        // upgrade, the old payload is smaller but the full new type fits the
        // reserved capacity and is not accessed until the upgrade callback.
        let mut shared_state = match unsafe {
            SharedState::<InspectorSharedState>::from_region(
                view.payload_offset,
                view.current_payload_size,
                view.payload_capacity,
                view.upgrade_required,
            )
        } {
            Ok(state) => state,
            Err(error) => {
                log::error!("invalid Inspector shared-state view: {}", error);
                return false;
            }
        };
        if view.is_new {
            let initial_state = InspectorSharedState {
                next_sequence: 1,
                ..InspectorSharedState::default()
            };
            // SAFETY: This is a newly allocated region and this instance is the
            // first plugin runtime attached to it.
            unsafe { shared_state.with_mut(|state| *state = initial_state) };
        }

        let mut config = InspectorConfig {
            delay_scale: DelayScale::new(tsc_frequency),
            shared_state: Some(shared_state),
            pending_upgrade,
            ..InspectorConfig::default()
        };
        for (key, value) in data {
            match key.as_str() {
                "src_mac" => config.src_mac = parse_mac(&value),
                "dst_mac" => config.dst_mac = parse_mac(&value),
                _ => {}
            }
        }
        *CONFIG.borrow_mut() = config;
        log::info!("InspectorEngine initialized");
        true
    }

    fn upgrade_shared_state(
        source_schema_version: u32,
        source_payload_size: u32,
    ) -> Result<(), String> {
        let config = CONFIG.borrow();
        if config.pending_upgrade != Some((source_schema_version, source_payload_size)) {
            return Err(String::from(
                "Inspector shared-state upgrade does not match the attached source schema",
            ));
        }
        Err(alloc::format!(
            "Inspector has no append-only migration from schema {source_schema_version}"
        ))
    }

    fn process_batch(batch_size: u32, umem_offset: u32, mailbox_offset: u32) -> u32 {
        let mut batch = MailboxBatch::new(batch_size, umem_offset, mailbox_offset);
        let config = CONFIG.borrow_mut();
        let shared_state_ptr = match config.shared_state.as_ref() {
            Some(shared_state) => shared_state.as_ptr(),
            None => return u32::MAX,
        };
        // SAFETY: The runner invokes packet processing only on the active
        // instance; staged replacements do not process until the old instance
        // has stopped accessing this shared payload.
        let state = unsafe { &mut *shared_state_ptr };
        let bypass = state.bypass != 0;
        let delay_scale = config.delay_scale;
        let mut processed = 0;

        for mut packet in batch.iter_mut() {
            if packet.tick_kind().is_some() {
                packet.set_action(ROUTE_DROP);
                continue;
            }

            if !bypass {
                state.packets_inspected += 1;
                state.bytes_inspected += packet.data_len() as u64;

                let metadata = if packet.udp_header().is_some() {
                    packet.payload().map(parse_generated_udp_payload)
                } else {
                    None
                };
                let metadata = match metadata {
                    Some(Ok(Some(metadata))) => {
                        record_sequence(state, metadata.sequence);
                        Some(metadata)
                    }
                    Some(Err(())) => {
                        state.sequence_malformed = state.sequence_malformed.saturating_add(1);
                        None
                    }
                    Some(Ok(None)) | None => None,
                };

                match metadata.and_then(|metadata| {
                    packet_delay_us(packet.timestamp(), metadata.send_tsc, delay_scale)
                }) {
                    Some(delay_us) => {
                        state.delay_samples += 1;
                        state.delay_sum_us = state.delay_sum_us.saturating_add(delay_us);
                        if delay_us > state.max_delay_current_interval_us {
                            state.max_delay_current_interval_us = delay_us;
                        }
                        // Prometheus bounds are inclusive (le=10us), so a
                        // sample exactly on a boundary belongs in that bucket.
                        let bucket = (delay_us.saturating_sub(1)
                            / INSPECTOR_DELAY_HISTOGRAM_BUCKET_WIDTH_US)
                            .min(INSPECTOR_DELAY_HISTOGRAM_FINITE_BUCKETS as u64)
                            as usize;
                        state.delay_histogram[bucket] =
                            state.delay_histogram[bucket].saturating_add(1);
                    }
                    None => state.unexpected += 1,
                }

                packet.set_action(ROUTE_TX);
            } else {
                packet.set_action(ROUTE_TX);
            }

            /* As we drop the packet currently, we do not need this:
            // The packet crossed the cable and is being sent back through the
            // receiving interface. Apply the configured reverse Ethernet
            // addresses so the frame reaches the other NIC port.
            if config.src_mac.is_some() || config.dst_mac.is_some() {
                if let Some(header) = packet.eth_header_mut() {
                    if let Some(mac) = config.src_mac {
                        let mac = MacAddr6::from(mac);
                        header.set_smac(&mac);
                    }
                    if let Some(mac) = config.dst_mac {
                        let mac = MacAddr6::from(mac);
                        header.set_dmac(&mac);
                    }
                }
            }
            */
            processed += 1;
        }

        processed
    }

    fn process_timers(_current_tsc: u64) -> TimerPlan {
        TimerPlan {
            timeout_frames: 0,
            packet_frames: 0,
        }
    }

    fn on_control_event(raw_opcode: u32, payload: Vec<u8>) -> bool {
        match PluginOpcode::from(raw_opcode) {
            PluginOpcode::Standard(StandardOpcode::SetOperationalState) if payload.len() == 1 => {
                set_shared_bypass(payload[0] == 2)
            }
            PluginOpcode::Standard(StandardOpcode::UpdateConfiguration) => {
                let Ok(data) = postcard::from_bytes::<HotWasmPayload>(&payload) else {
                    return false;
                };

                if let Some(value) = data.updates.get("bypass") {
                    return set_shared_bypass(value == "true" || value == "1");
                }
                true
            }
            _ => false,
        }
    }

    fn get_telemetry_schema() -> TelemetrySchema {
        TelemetrySchema {
            counters: alloc::vec![
                String::from("packets_inspected"),
                String::from("bytes_inspected"),
                String::from("unexpected"),
                String::from("sequence_packets"),
                String::from("sequence_missing"),
                String::from("sequence_out_of_sequence"),
                String::from("sequence_malformed"),
                String::from("max_delay_us_5s"),
            ],
            histograms: alloc::vec![HistogramSchema {
                name: String::from("delay"),
                bucket_count: MAX_HISTOGRAM_BUCKETS as u32,
            }],
        }
    }

    fn get_telemetry() -> Vec<TelemetryMetric> {
        let mut config = CONFIG.borrow_mut();
        let Some(shared_state) = config.shared_state.as_mut() else {
            return Vec::new();
        };
        // SAFETY: Telemetry is polled by the active runtime at a runner
        // boundary, with no staged runtime concurrently accessing the payload.
        unsafe {
            shared_state.with_mut(|state| {
                let new_missing = state
                    .sequence_missing
                    .saturating_sub(state.logged_sequence_missing);
                let new_out_of_sequence = state
                    .sequence_out_of_sequence
                    .saturating_sub(state.logged_sequence_out_of_sequence);
                let new_malformed = state
                    .sequence_malformed
                    .saturating_sub(state.logged_sequence_malformed);
                if new_missing > 0 || new_out_of_sequence > 0 || new_malformed > 0 {
                    log::warn!(
                        "UDP sequence anomalies since previous telemetry report: missing={}, out_of_sequence={}, malformed={} (totals: missing={}, out_of_sequence={}, malformed={})",
                        new_missing,
                        new_out_of_sequence,
                        new_malformed,
                        state.sequence_missing,
                        state.sequence_out_of_sequence,
                        state.sequence_malformed
                    );
                }
                state.logged_sequence_missing = state.sequence_missing;
                state.logged_sequence_out_of_sequence = state.sequence_out_of_sequence;
                state.logged_sequence_malformed = state.sequence_malformed;

                let interval = usize::from(state.max_delay_interval_cursor);
                state.max_delay_intervals_us[interval] = state.max_delay_current_interval_us;
                state.max_delay_current_interval_us = 0;
                state.max_delay_interval_cursor =
                    ((interval + 1) % MAX_DELAY_WINDOW_INTERVALS) as u8;
                let max_delay_us_5s = state
                    .max_delay_intervals_us
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(0);

                alloc::vec![
                    TelemetryMetric::Counter(Counter {
                        name: String::from("packets_inspected"),
                        value: state.packets_inspected
                    }),
                    TelemetryMetric::Counter(Counter {
                        name: String::from("bytes_inspected"),
                        value: state.bytes_inspected
                    }),
                    TelemetryMetric::Counter(Counter {
                        name: String::from("unexpected"),
                        value: state.unexpected
                    }),
                    TelemetryMetric::Counter(Counter {
                        name: String::from("sequence_packets"),
                        value: state.sequence_packets
                    }),
                    TelemetryMetric::Counter(Counter {
                        name: String::from("sequence_missing"),
                        value: state.sequence_missing
                    }),
                    TelemetryMetric::Counter(Counter {
                        name: String::from("sequence_out_of_sequence"),
                        value: state.sequence_out_of_sequence
                    }),
                    TelemetryMetric::Counter(Counter {
                        name: String::from("sequence_malformed"),
                        value: state.sequence_malformed
                    }),
                    TelemetryMetric::Counter(Counter {
                        name: String::from("max_delay_us_5s"),
                        value: max_delay_us_5s
                    }),
                    TelemetryMetric::Hist(Histogram {
                        name: String::from("delay"),
                        sum: state.delay_sum_us,
                        count: state.delay_samples,
                        buckets: state.delay_histogram.to_vec(),
                    }),
                ]
            })
        }
    }
}

export!(InspectorEngine);

#[cfg(test)]
mod tests {
    use super::{packet_delay_us, DelayScale};

    #[test]
    fn packet_delay_rejects_invalid_timestamps_and_frequency() {
        assert_eq!(packet_delay_us(10, 0, DelayScale::new(0)), None);
        assert_eq!(packet_delay_us(9, 10, DelayScale::new(1)), None);
        assert_eq!(packet_delay_us(10, 10, DelayScale::new(1)), Some(0));
    }

    #[test]
    fn packet_delay_matches_wide_arithmetic() {
        let values = [
            1,
            999_999,
            1_000_000,
            3_000_000_000,
            u64::MAX / 1_000_000,
            u64::MAX / 1_000_000 + 1,
            u64::MAX / 2,
            u64::MAX - 1,
            u64::MAX,
        ];
        let check = |elapsed: u64, frequency: u64| {
            let expected = ((elapsed as u128 * 1_000_000) / frequency as u128) as u64;
            assert_eq!(
                packet_delay_us(elapsed, 0, DelayScale::new(frequency)),
                Some(expected),
                "elapsed={elapsed} frequency={frequency}"
            );
        };
        for frequency in [1_000_000, 3_417_600_000, 4_294_967_295, u64::MAX] {
            let scale = DelayScale::new(frequency);
            for elapsed in [
                0,
                1,
                scale.max_fast_cycles as u64,
                scale.max_fast_cycles as u64 + 1,
                1_000_000,
                u64::MAX,
            ] {
                check(elapsed, frequency);
            }
        }
        for elapsed in values {
            for frequency in values {
                check(elapsed, frequency);
            }
        }
        let mut state = 42u64;
        for _ in 0..10_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let elapsed = state;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            check(elapsed, state.max(1));
        }
    }
}
