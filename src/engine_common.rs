//! Shared, WIT-independent support for `engine-plugin` implementations.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use hashbrown::HashMap;

use wabrix_api::helpers::{parse_ip, parse_mac, parse_suffixed_number};
use crate::tcp_common::{
    CommonEngineConfig, GeneratorConfig, GeneratorProtocol, PacketGenerator, TcpEngineConfig,
};
use wabrix_api::{HotWasmPayload, OperationalState, PluginOpcode, StandardOpcode};

/// No-std equivalent of the formatting helper used by the native tools.
pub trait SeparatedString {
    fn separated_string(&self) -> String;
}

impl SeparatedString for u128 {
    fn separated_string(&self) -> String {
        let value = self.to_string();
        let mut result = String::with_capacity(value.len() + value.len() / 3);

        for (index, character) in value.chars().enumerate() {
            if index > 0 && (value.len() - index).is_multiple_of(3) {
                result.push(',');
            }
            result.push(character);
        }
        result
    }
}

impl SeparatedString for u64 {
    fn separated_string(&self) -> String {
        (*self as u128).separated_string()
    }
}

/// A zero-cost state container for single-threaded WASM plugin state.
pub struct WasmCell<T>(RefCell<T>);

// SAFETY: A WASM component instance is single-threaded. The `Sync` implementation is
// required only so the container can be used in a static and cannot be observed concurrently.
unsafe impl<T> Sync for WasmCell<T> {}

impl<T> WasmCell<T> {
    pub const fn new(value: T) -> Self {
        Self(RefCell::new(value))
    }

    pub fn borrow(&self) -> core::cell::Ref<'_, T> {
        self.0.borrow()
    }

    pub fn borrow_mut(&self) -> core::cell::RefMut<'_, T> {
        self.0.borrow_mut()
    }
}

/// A zero-cost state container for simple `Copy` values in a WASM plugin.
pub struct WasmValue<T>(Cell<T>);

// SAFETY: As with `WasmCell`, plugin state is accessed by one WASM thread only.
unsafe impl<T> Sync for WasmValue<T> {}

impl<T> WasmValue<T> {
    pub const fn new(value: T) -> Self {
        Self(Cell::new(value))
    }

    pub fn get(&self) -> T
    where
        T: Copy,
    {
        self.0.get()
    }

    pub fn set(&self, value: T) {
        self.0.set(value)
    }
}

pub enum ControlResult {
    Handled,
    Flush(u8),
    Invalid,
}

pub trait EngineConfigModel {
    fn common_mut(&mut self) -> &mut CommonEngineConfig;
    fn apply_updates(&mut self, updates: &HashMap<String, String>) -> bool;
}

/// Parse and validate the configuration shared by native and Wasm TCP engines.
///
/// The returned name uses the common fallback behavior: an explicit `name`
/// wins, otherwise the original `src_ip` string is used.
pub fn parse_tcp_engine_config(
    data: Vec<(String, String)>,
    tsc_frequency: u64,
) -> Result<(TcpEngineConfig, String), String> {
    let mut config = TcpEngineConfig {
        common: CommonEngineConfig {
            tsc_frequency,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut raw_src_ip: Option<String> = None;

    for (key, value) in data {
        match key.as_str() {
            "name" => config.name = Some(value),
            "src_mac" => {
                config.src_mac = parse_mac(&value);
                if config.src_mac.is_none() {
                    return Err(format!("invalid src_mac: {}", value));
                }
            }
            "dst_mac" => {
                config.dst_mac = parse_mac(&value);
                if config.dst_mac.is_none() {
                    return Err(format!("invalid dst_mac: {}", value));
                }
            }
            "src_ip" => {
                raw_src_ip = Some(value.clone());
                config.src_ip = parse_ip(&value);
                if config.src_ip.is_none() {
                    return Err(format!("invalid src_ip: {}", value));
                }
            }
            "dst_ip" => {
                config.dst_ip = parse_ip(&value);
                if config.dst_ip.is_none() {
                    return Err(format!("invalid dst_ip: {}", value));
                }
            }
            "rng_seed" => {
                config.rng_seed = value.parse::<u32>().ok();
                if config.rng_seed.is_none() {
                    return Err(format!("invalid rng_seed: {}", value));
                }
            }
            "generation_rate" => {
                config.generation_rate = parse_suffixed_number(&value).ok();
                if config.generation_rate.is_none() {
                    return Err(format!("invalid generation_rate: {}", value));
                }
            }
            "syn_limit" => {
                config.syn_limit = parse_suffixed_number(&value).ok();
                if config.syn_limit.is_none() {
                    return Err(format!("invalid syn_limit: {}", value));
                }
            }
            "close_timeout" => {
                config.close_timeout_millis = value.parse::<u64>().ok();
                if config.close_timeout_millis.is_none() {
                    return Err(format!("invalid close_timeout: {}", value));
                }
            }
            _ => {}
        }
    }

    if config.src_ip.is_none() {
        return Err(String::from("missing required src_ip"));
    }
    if config.src_mac.is_none() {
        return Err(String::from("missing required src_mac"));
    }
    if config.dst_mac.is_none() {
        return Err(String::from("missing required dst_mac"));
    }
    if config.generation_rate.is_some_and(|rate| rate > 0) && config.dst_ip.is_none() {
        return Err(String::from(
            "dst_ip is required when generation_rate is positive",
        ));
    }

    config.refresh_timeout_cycles();
    let node_name = config
        .name
        .clone()
        .or(raw_src_ip)
        .unwrap_or_else(|| String::from("unknown"));

    Ok((config, node_name))
}

fn parse_update_number(
    updates: &HashMap<String, String>,
    key: &str,
) -> Result<Option<Option<u64>>, ()> {
    match updates.get(key) {
        Some(value) if value.is_empty() => Ok(Some(None)),
        Some(value) => parse_suffixed_number(value)
            .map(|number| Some(Some(number)))
            .map_err(|_| ()),
        None => Ok(None),
    }
}

impl EngineConfigModel for TcpEngineConfig {
    fn common_mut(&mut self) -> &mut CommonEngineConfig {
        &mut self.common
    }

    fn apply_updates(&mut self, updates: &HashMap<String, String>) -> bool {
        let Ok(generation_rate) = parse_update_number(updates, "generation_rate") else {
            return false;
        };
        let Ok(syn_limit) = parse_update_number(updates, "syn_limit") else {
            return false;
        };
        let close_timeout = match updates.get("close_timeout") {
            Some(value) if value.is_empty() => Some(None),
            Some(value) => match value.parse::<u64>() {
                Ok(number) => Some(Some(number)),
                Err(_) => return false,
            },
            None => None,
        };

        if let Some(value) = generation_rate {
            self.generation_rate = value;
        }
        if let Some(value) = syn_limit {
            self.syn_limit = value;
        }
        if let Some(value) = close_timeout {
            self.close_timeout_millis = value;
            self.refresh_timeout_cycles();
        }
        true
    }
}

/// Decode and atomically apply a serialized TCP hot-configuration update.
///
/// The candidate configuration is updated first. The live configuration is
/// replaced only after every requested value has been validated successfully.
pub fn apply_tcp_configuration_update(
    payload: &[u8],
    config: &mut TcpEngineConfig,
) -> Result<(), String> {
    let data = postcard::from_bytes::<HotWasmPayload>(payload)
        .map_err(|error| format!("invalid TCP configuration payload: {}", error))?;
    let mut candidate = config.clone();
    if !candidate.apply_updates(&data.updates) {
        return Err(String::from("invalid TCP configuration update"));
    }
    *config = candidate;
    Ok(())
}

impl EngineConfigModel for GeneratorConfig {
    fn common_mut(&mut self) -> &mut CommonEngineConfig {
        &mut self.common
    }

    fn apply_updates(&mut self, updates: &HashMap<String, String>) -> bool {
        let rate_key = "generation_rate";
        let limit_key = if updates.contains_key("generation_limit") {
            "generation_limit"
        } else {
            "syn_limit"
        };
        let Ok(rate) = parse_update_number(updates, rate_key) else {
            return false;
        };
        let Ok(limit) = parse_update_number(updates, limit_key) else {
            return false;
        };
        let protocol = match updates.get("prot").or_else(|| updates.get("protocol")) {
            Some(value) => match GeneratorProtocol::parse(value) {
                Some(protocol) => Some(protocol),
                None => return false,
            },
            None => None,
        };

        if let Some(value) = rate {
            self.generation_rate = value;
        }
        if let Some(value) = limit {
            self.generation_limit = value;
        }
        if let Some(protocol) = protocol {
            self.protocol = protocol;
        }
        true
    }
}

/// Handle the control protocol shared by all `engine-plugin` implementations.
/// Plugin adapters remain responsible only for plugin-specific flush work and logging.
pub fn handle_control_event<C: EngineConfigModel>(
    raw_opcode: u32,
    payload: &[u8],
    config: &WasmCell<Option<C>>,
    syn_generator: &WasmCell<PacketGenerator>,
) -> ControlResult {
    match PluginOpcode::from(raw_opcode) {
        PluginOpcode::Standard(StandardOpcode::SetOperationalState) => {
            if payload.len() != 1 {
                return ControlResult::Invalid;
            }
            if OperationalState::from_payload(payload[0]).is_none() {
                return ControlResult::Invalid;
            }
            set_operational_state(payload[0], config, syn_generator);
            ControlResult::Handled
        }
        PluginOpcode::Standard(StandardOpcode::FlushState) => {
            if payload.len() > 1 {
                return ControlResult::Invalid;
            }
            let mode = if payload.len() == 1 { payload[0] } else { 0 };
            set_operational_state(0, config, syn_generator);
            reset_syn_state(mode, syn_generator);
            ControlResult::Flush(mode)
        }
        PluginOpcode::Standard(StandardOpcode::Ping) => ControlResult::Handled,
        PluginOpcode::Standard(StandardOpcode::UpdateConfiguration) => {
            let Ok(data) = postcard::from_bytes::<HotWasmPayload>(payload) else {
                return ControlResult::Invalid;
            };
            if apply_configuration_update(&data.updates, config) {
                ControlResult::Handled
            } else {
                ControlResult::Invalid
            }
        }
        _ => ControlResult::Invalid,
    }
}

pub fn set_operational_state<C: EngineConfigModel>(
    state: u8,
    config: &WasmCell<Option<C>>,
    syn_generator: &WasmCell<PacketGenerator>,
) {
    let mut generator = syn_generator.borrow_mut();
    let mut config = config.borrow_mut();

    if let Some(config) = config.as_mut() {
        match OperationalState::from_payload(state) {
            Some(OperationalState::Offline) => {
                generator.activated = false;
                config.common_mut().bypass = false;
            }
            Some(OperationalState::Online) => {
                generator.activated = true;
                config.common_mut().bypass = false;
            }
            Some(OperationalState::Bypass) => {
                generator.activated = false;
                config.common_mut().bypass = true;
            }
            None => {}
        }
    }
}

pub fn reset_syn_state(mode: u8, syn_generator: &WasmCell<PacketGenerator>) {
    let mut generator = syn_generator.borrow_mut();
    generator.packets_sent = 0;
    generator.cycle_accumulator = 0;
    generator.last_tsc = 0;

    if mode == 1 {
        generator.port_counter = crate::tcp_common::PORT_START_RANGE;
        generator.prng_state = 1;
    }
}

fn apply_configuration_update<C: EngineConfigModel>(
    updates: &HashMap<String, String>,
    config: &WasmCell<Option<C>>,
) -> bool {
    let mut guard = config.borrow_mut();
    let Some(config) = guard.as_mut() else {
        return false;
    };
    config.apply_updates(updates)
}

/// Parse and validate configuration common to engine plugins.
///
/// The returned node name uses the shared engine fallback behavior: an explicit
/// `name` wins, otherwise the original `src_ip` string is used.
pub fn parse_generator_config(
    data: Vec<(String, String)>,
    tsc_frequency: u64,
) -> Option<(GeneratorConfig, String)> {
    let mut config = GeneratorConfig::default();
    let mut raw_src_ip = None;

    for (key, value) in data {
        match key.as_str() {
            "name" => config.name = Some(value),
            "src_mac" => {
                config.src_mac = parse_mac(&value);
                config.src_mac.as_ref()?;
            }
            "dst_mac" => {
                config.dst_mac = parse_mac(&value);
                config.dst_mac.as_ref()?;
            }
            "src_ip" => {
                raw_src_ip = Some(value.clone());
                config.src_ip = parse_ip(&value);
                config.src_ip.as_ref()?;
            }
            "dst_ip" => {
                config.dst_ip = parse_ip(&value);
                config.dst_ip.as_ref()?;
            }
            "rng_seed" => {
                config.rng_seed = value.parse::<u32>().ok();
                config.rng_seed.as_ref()?;
            }
            "generation_rate" => {
                config.generation_rate = parse_suffixed_number(&value).ok();
                config.generation_rate.as_ref()?;
            }
            "generation_limit" | "syn_limit" => {
                config.generation_limit = parse_suffixed_number(&value).ok();
                config.generation_limit.as_ref()?;
            }
            "protocol" | "prot" => {
                config.protocol = GeneratorProtocol::parse(&value)?;
            }
            _ => {}
        }
    }

    if config.src_ip.is_none()
        || config.src_mac.is_none()
        || config.dst_mac.is_none()
        || (config.dst_ip.is_none() && config.generation_rate.is_some_and(|rate| rate > 0))
    {
        return None;
    }

    config.common.tsc_frequency = tsc_frequency;
    let node_name = config
        .name
        .clone()
        .or(raw_src_ip)
        .unwrap_or_else(|| String::from("unknown"));

    Some((config, node_name))
}

#[cfg(test)]
mod tests {
    use super::{
        apply_tcp_configuration_update, handle_control_event, parse_tcp_engine_config,
        set_operational_state, ControlResult, WasmCell,
    };
    use crate::tcp_common::{PacketGenerator, TcpEngineConfig, PORT_START_RANGE};
    use wabrix_api::HotWasmPayload;
    use wabrix_api::StandardOpcode;
    use alloc::vec;

    fn valid_client_data() -> alloc::vec::Vec<(alloc::string::String, alloc::string::String)> {
        vec![
            ("name".into(), "client".into()),
            ("src_mac".into(), "00:11:22:33:44:55".into()),
            ("dst_mac".into(), "66:77:88:99:aa:bb".into()),
            ("src_ip".into(), "10.0.0.1".into()),
            ("dst_ip".into(), "10.0.0.2".into()),
            ("generation_rate".into(), "1.5k".into()),
            ("syn_limit".into(), "10k".into()),
            ("close_timeout".into(), "80".into()),
        ]
    }

    #[test]
    fn parses_shared_tcp_configuration() {
        let (config, name) = parse_tcp_engine_config(valid_client_data(), 3_000)
            .expect("valid TCP configuration should parse");

        assert_eq!(name, "client");
        assert_eq!(config.generation_rate, Some(1_500));
        assert_eq!(config.syn_limit, Some(10_000));
        assert_eq!(config.close_timeout_millis, Some(80));
        assert_eq!(config.timeout_cycles, Some(240));
    }

    #[test]
    fn rejects_invalid_values_and_missing_required_fields() {
        let mut invalid = valid_client_data();
        invalid.push(("generation_rate".into(), "not-a-rate".into()));
        assert!(parse_tcp_engine_config(invalid, 3_000).is_err());

        let server = vec![
            ("src_mac".into(), "00:11:22:33:44:55".into()),
            ("dst_mac".into(), "66:77:88:99:aa:bb".into()),
            ("src_ip".into(), "10.0.0.2".into()),
        ];
        assert!(parse_tcp_engine_config(server, 3_000).is_ok());

        let missing_source = vec![("dst_mac".into(), "66:77:88:99:aa:bb".into())];
        assert!(parse_tcp_engine_config(missing_source, 3_000).is_err());
    }

    #[test]
    fn applies_tcp_hot_updates_atomically() {
        let (mut config, _) = parse_tcp_engine_config(valid_client_data(), 3_000)
            .expect("valid TCP configuration should parse");
        let payload = postcard::to_allocvec(&HotWasmPayload {
            updates: [
                ("generation_rate".into(), "2M".into()),
                ("close_timeout".into(), "120".into()),
            ]
            .into_iter()
            .collect(),
        })
        .expect("payload should serialize");

        apply_tcp_configuration_update(&payload, &mut config).expect("valid update should apply");
        assert_eq!(config.generation_rate, Some(2_000_000));
        assert_eq!(config.close_timeout_millis, Some(120));
        assert_eq!(config.timeout_cycles, Some(360));

        let invalid_payload = postcard::to_allocvec(&HotWasmPayload {
            updates: [
                ("generation_rate".into(), "3M".into()),
                ("close_timeout".into(), "invalid".into()),
            ]
            .into_iter()
            .collect(),
        })
        .expect("payload should serialize");

        assert!(apply_tcp_configuration_update(&invalid_payload, &mut config).is_err());
        assert_eq!(config.generation_rate, Some(2_000_000));
        assert_eq!(config.close_timeout_millis, Some(120));
    }

    fn lifecycle_state() -> (WasmCell<Option<TcpEngineConfig>>, WasmCell<PacketGenerator>) {
        (
            WasmCell::new(Some(TcpEngineConfig::default())),
            WasmCell::new(PacketGenerator {
                last_tsc: 100,
                cycle_accumulator: 200,
                port_counter: PORT_START_RANGE + 10,
                ip_offset: 3,
                prng_state: 42,
                packets_sent: 7,
                activated: true,
            }),
        )
    }

    #[test]
    fn lifecycle_states_have_shared_meanings() {
        let (config, generator) = lifecycle_state();

        set_operational_state(0, &config, &generator);
        assert!(!generator.borrow().activated);
        assert!(!config.borrow().as_ref().unwrap().bypass);

        set_operational_state(1, &config, &generator);
        assert!(generator.borrow().activated);
        assert!(!config.borrow().as_ref().unwrap().bypass);

        set_operational_state(2, &config, &generator);
        assert!(!generator.borrow().activated);
        assert!(config.borrow().as_ref().unwrap().bypass);
    }

    #[test]
    fn lifecycle_control_rejects_unknown_state() {
        let (config, generator) = lifecycle_state();
        let result = handle_control_event(
            StandardOpcode::SetOperationalState as u32,
            &[3],
            &config,
            &generator,
        );

        assert!(matches!(result, ControlResult::Invalid));
        assert!(generator.borrow().activated);
        assert!(!config.borrow().as_ref().unwrap().bypass);
    }

    #[test]
    fn flush_modes_share_generator_reset_semantics() {
        let (config, generator) = lifecycle_state();

        let result =
            handle_control_event(StandardOpcode::FlushState as u32, &[], &config, &generator);
        assert!(matches!(result, ControlResult::Flush(0)));
        assert_eq!(generator.borrow().packets_sent, 0);
        assert_eq!(generator.borrow().cycle_accumulator, 0);
        assert_eq!(generator.borrow().last_tsc, 0);
        assert_eq!(generator.borrow().port_counter, PORT_START_RANGE + 10);

        {
            let mut generator = generator.borrow_mut();
            generator.port_counter = PORT_START_RANGE + 20;
            generator.prng_state = 99;
        }
        let result =
            handle_control_event(StandardOpcode::FlushState as u32, &[1], &config, &generator);
        assert!(matches!(result, ControlResult::Flush(1)));
        assert_eq!(generator.borrow().port_counter, PORT_START_RANGE);
        assert_eq!(generator.borrow().prng_state, 1);
        assert!(!generator.borrow().activated);
        assert!(!config.borrow().as_ref().unwrap().bypass);

        assert!(matches!(
            handle_control_event(
                StandardOpcode::FlushState as u32,
                &[0, 1],
                &config,
                &generator,
            ),
            ControlResult::Invalid
        ));
    }
}
