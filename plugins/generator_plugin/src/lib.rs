// Inside your WASM Plugin (Guest)
#![no_std]
extern crate alloc;

use crate::exports::wabrix::plugins::generator::Guest;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU32, Ordering};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use spin::Mutex; // <-- idiomatic no_std lock
use wabrix_api::headers::new_ipv4_header;
use wabrix_api::helpers::{parse_ip, parse_mac};
use wabrix_api::packet::PacketBatch;
use wabrix_plugins::tcp_common::new_tcp_header;

// Generate bindings from the WIT file
wit_bindgen::generate!({
    path: "../../wit/wabrix.wit",
    world: "generator-plugin",
});

// 1. Define a structured config to hold parsed data
#[derive(Clone, Default)]
struct GeneratorConfig {
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    src_ip: Option<[u8; 4]>,
    dst_ip: Option<[u8; 4]>,
    rng_seed: Option<u32>, // random IP generation!
}

static CONFIG: Mutex<Option<GeneratorConfig>> = Mutex::new(None);
/// Use core atomics for safe #![no_std] global state.
// WASM is single-threaded, so Ordering::Relaxed is essentially zero-cost.
static WORKER_ID: AtomicU32 = AtomicU32::new(0);
static SEQ_COUNTER: AtomicU32 = AtomicU32::new(0);

struct MyGenerator;

// =====================================================================

// A lightning-fast, zero-dependency PRNG for #![no_std]
#[inline(always)]
fn fast_rand(mut state: u32) -> u32 {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    state
}

impl Guest for MyGenerator {
    fn save_state() -> Result<Vec<u8>, alloc::string::String> {
        Ok(Vec::new())
    }

    fn restore_state(state: Vec<u8>) -> Result<(), alloc::string::String> {
        if state.is_empty() {
            Ok(())
        } else {
            Err(alloc::string::String::from(
                "generator_plugin does not support state restoration",
            ))
        }
    }

    fn init_data(data: Vec<(alloc::string::String, alloc::string::String)>, worker_id: u32) {
        let mut config = GeneratorConfig::default();

        // Parse strings into structured bytes ONCE at startup
        for (key, value) in data {
            match key.as_str() {
                "src_mac" => {
                    if let Some(bytes) = parse_mac(&value) {
                        config.src_mac = Some(bytes);
                    }
                }
                "dst_mac" => {
                    if let Some(bytes) = parse_mac(&value) {
                        config.dst_mac = Some(bytes);
                    }
                }
                "src_ip" => {
                    if let Some(bytes) = parse_ip(&value) {
                        config.src_ip = Some(bytes);
                    }
                }
                "dst_ip" => {
                    if let Some(bytes) = parse_ip(&value) {
                        config.dst_ip = Some(bytes);
                    }
                }
                "rng_seed" => {
                    config.rng_seed = value.parse::<u32>().ok();
                }
                _ => {} // Ignore unknown keys
            }
        }

        // Safely store the parsed config in our global state
        *CONFIG.lock() = Some(config);
        WORKER_ID.store(worker_id, Ordering::Relaxed);
        SEQ_COUNTER.store(0, Ordering::Relaxed);
    }

    fn set_dst(mac: (u8, u8, u8, u8, u8, u8), ip: (u8, u8, u8, u8)) {
        // Reconstruct into native arrays
        let ip_bytes: [u8; 4] = [ip.0, ip.1, ip.2, ip.3];
        let mac_bytes: [u8; 6] = [mac.0, mac.1, mac.2, mac.3, mac.4, mac.5];

        // 1. Lock the global mutex
        let mut config_guard = CONFIG.lock();

        // 2. If the config has been initialized, modify the fields in place
        if let Some(config) = config_guard.as_mut() {
            config.dst_ip = Some(ip_bytes);
            config.dst_mac = Some(mac_bytes);
        }
    }

    fn generate_batch(mut batch_bytes: Vec<u8>, umem_offset: u32) -> Vec<u32> {
        let mut batch = PacketBatch::new(&mut batch_bytes, umem_offset);

        let worker_id = WORKER_ID.load(Ordering::Relaxed) as u16;
        let mut seq = SEQ_COUNTER.load(Ordering::Relaxed);
        let mut config = CONFIG.lock().clone().unwrap_or_default();

        // Pre-calculate static fields outside the loop for maximum performance
        let dst_mac = config.dst_mac.unwrap_or([0xff; 6]);
        let src_mac = config.src_mac.unwrap_or([1, 2, 3, 4, 5, 6]);
        let dst_ip = Ipv4Addr::from(config.dst_ip.unwrap_or([192, 168, 177, 222]));
        let base_src_ip = config.src_ip.unwrap_or([192, 168, 177, 2]);

        let lengths: Vec<u32> = batch
            .iter_mut()
            .map(|mut packet| {
                // 1. Calculate dynamic fields per-packet
                let src_ip_u32 = if let Some(seed) = config.rng_seed {
                    let new_seed = fast_rand(seed);
                    config.rng_seed = Some(new_seed);
                    new_seed
                } else {
                    u32::from_be_bytes(base_src_ip)
                };

                // 2. Build the Ethernet header
                let mac = EthHdr::new(dst_mac, src_mac, EtherType::Ipv4);

                // 3. Build the IPv4 header
                let mut ip = new_ipv4_header();
                ip.set_src_addr(Ipv4Addr::from(src_ip_u32));
                ip.set_dst_addr(dst_ip);
                ip.ttl = 128;
                ip.set_vihl(4, Ipv4Hdr::LEN as u8);
                ip.set_proto(IpProto::Tcp);
                ip.set_tot_len(40);
                ip.set_frags(0x2, 0); // DF=1

                // 4. Build the TCP header
                let mut tcp = new_tcp_header();
                tcp.set_syn(1);
                tcp.source = 111u16.to_be_bytes();
                tcp.dest = worker_id.to_be_bytes();
                tcp.set_doff(5);
                tcp.seq = seq.to_be_bytes();

                // 5. Serialize directly into Wasm memory
                let len = packet.write_eth_ipv4_tcp_headers(&mac, &ip, &tcp);

                seq = seq.wrapping_add(1);
                len
            })
            .collect();

        // Save state
        SEQ_COUNTER.store(seq, Ordering::Relaxed);
        if let Some(ref mut c) = *CONFIG.lock() {
            c.rng_seed = config.rng_seed;
        }

        lengths
    }
}

// Export the implementation to the runtime
export!(MyGenerator);
