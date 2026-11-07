extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use exports::wabrix::plugins::packet_engine::{
    Counter, Guest, TelemetryMetric, TelemetrySchema, TimerPlan,
};
use postcard;
use wabrix::plugins::logging;
use wabrix_api::mailbox_api::MailboxBatch;
use wabrix_api::{HotWasmPayload, PluginOpcode, StandardOpcode};

wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "engine-plugin",
});

// Zero-cost, single-threaded state container for WASM.
pub struct WasmCell<T>(RefCell<T>);
unsafe impl<T> Sync for WasmCell<T> {}

impl<T> WasmCell<T> {
    pub const fn new(value: T) -> Self {
        Self(RefCell::new(value))
    }
    pub fn borrow_mut(&self) -> core::cell::RefMut<'_, T> {
        self.0.borrow_mut()
    }
    pub fn borrow(&self) -> core::cell::Ref<'_, T> {
        self.0.borrow()
    }
}

// Internal plugin configuration and telemetry counters
#[derive(Default, Clone)]
struct FilterConfig {
    bypass: bool,
    signature: Vec<u8>,
    packets_forwarded: u64,
    packets_dropped: u64,
}

static CONFIG: WasmCell<Option<FilterConfig>> = WasmCell::new(None);

// Route targets mapped to the TOML configuration routes array
const ROUTE_TX: u32 = 0;
const ROUTE_DROP: u32 = 1;

struct HostLogger;

impl log::Log for HostLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let msg = alloc::format!("filter_engine: {}", record.args());
            logging::log(record.level() as u32, &msg);
        }
    }

    fn flush(&self) {}
}

pub fn init_logging() {
    static LOGGER: HostLogger = HostLogger;
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Info);
}

struct FilterEngine;

impl Guest for FilterEngine {
    fn upgrade_shared_state(
        _source_schema_version: u32,
        _source_payload_size: u32,
    ) -> Result<(), String> {
        Err(String::from("filter_engine has no shared-state migration"))
    }

    // Validates incoming configuration and prepares the active signature
    fn init_data(data: Vec<(String, String)>, _tsc_frequency: u64) -> bool {
        init_logging();
        let mut config = FilterConfig {
            bypass: false,
            ..Default::default()
        };

        for (key, value) in data {
            if key == "signature" {
                config.signature = value.into_bytes();
            }
        }

        log::info!(
            "FilterEngine initialized with signature length: {}",
            config.signature.len()
        );
        *CONFIG.borrow_mut() = Some(config);

        true
    }

    // Scans packet payloads and routes them based on signature presence
    fn process_batch(batch_size: u32, umem_offset: u32, mailbox_offset: u32) -> u32 {
        let mut batch = MailboxBatch::new(batch_size, umem_offset, mailbox_offset);
        let mut config_guard = CONFIG.borrow_mut();

        let Some(config) = config_guard.as_mut() else {
            for mut packet in batch.iter_mut() {
                packet.set_action(ROUTE_DROP);
            }
            return batch_size;
        };

        if config.bypass {
            for mut packet in batch.iter_mut() {
                packet.set_action(ROUTE_TX);
                config.packets_forwarded += 1;
            }
            return batch_size;
        }

        let mut processed_count = 0;
        let sig_len = config.signature.len();

        for mut packet in batch.iter_mut() {
            if packet.is_a_tick() {
                packet.set_action(ROUTE_DROP);
                processed_count += 1;
                continue;
            }

            // SAFETY: The packet data pointer is bounded by the length provided by AF_XDP.
            // Memory is constrained to the WASM linear memory mapping defined by the host.
            let payload = unsafe {
                core::slice::from_raw_parts(packet.data_ptr(), packet.data_len() as usize)
            };

            let mut matched = false;

            // Execute linear search for the malicious byte signature
            if sig_len > 0
                && payload.len() >= sig_len
                && payload
                    .windows(sig_len)
                    .any(|window| window == config.signature.as_slice())
            {
                matched = true;
            }

            if matched {
                packet.set_action(ROUTE_DROP);
                config.packets_dropped += 1;
            } else {
                packet.set_action(ROUTE_TX);
                config.packets_forwarded += 1;
            }

            processed_count += 1;
        }

        processed_count
    }

    fn process_timers(_current_tsc: u64) -> TimerPlan {
        TimerPlan {
            timeout_frames: 0,
            packet_frames: 0,
        }
    }

    // Intercepts control events to modify the active DPI signature without restarting
    fn on_control_event(raw_opcode: u32, payload: Vec<u8>) -> bool {
        let opcode = PluginOpcode::from(raw_opcode);

        match opcode {
            PluginOpcode::Standard(StandardOpcode::SetOperationalState) if payload.len() == 1 => {
                let mut guard = CONFIG.borrow_mut();
                if let Some(ref mut config) = *guard {
                    config.bypass = payload[0] == 2;
                    log::info!("Bypass mode updated");
                }
                true
            }
            PluginOpcode::Standard(StandardOpcode::UpdateConfiguration) => {
                if let Ok(data) = postcard::from_bytes::<HotWasmPayload>(&payload) {
                    let new_signature = match data.updates.get("signature") {
                        Some(s) if s.is_empty() => Some(Vec::new()),
                        Some(s) => Some(s.clone().into_bytes()),
                        None => None,
                    };

                    let mut guard = CONFIG.borrow_mut();
                    if let Some(ref mut config) = *guard {
                        if let Some(sig) = new_signature {
                            if config.signature != sig {
                                config.signature = sig;
                                log::info!(
                                    "Signature dynamically updated to length: {}",
                                    config.signature.len()
                                );
                            }
                        }
                    }
                    true
                } else {
                    log::warn!("Payload deserialization error");
                    false
                }
            }
            _ => false,
        }
    }

    fn get_telemetry_schema() -> TelemetrySchema {
        TelemetrySchema {
            counters: alloc::vec![
                String::from("packets_forwarded"),
                String::from("packets_dropped"),
            ],
            histograms: Vec::new(),
        }
    }

    // Exposes statistics to the host metrics server
    fn get_telemetry() -> Vec<TelemetryMetric> {
        let guard = CONFIG.borrow();
        if let Some(config) = guard.as_ref() {
            alloc::vec![
                TelemetryMetric::Counter(Counter {
                    name: String::from("packets_forwarded"),
                    value: config.packets_forwarded,
                }),
                TelemetryMetric::Counter(Counter {
                    name: String::from("packets_dropped"),
                    value: config.packets_dropped,
                }),
            ]
        } else {
            alloc::vec![
                TelemetryMetric::Counter(Counter {
                    name: String::from("packets_forwarded"),
                    value: 0,
                }),
                TelemetryMetric::Counter(Counter {
                    name: String::from("packets_dropped"),
                    value: 0,
                }),
            ]
        }
    }
}

export!(FilterEngine);
