use wabrix_plugins::engine_common::SeparatedString;

#[cfg(feature = "runtime-diagnostics")]
use wabrix_plugins::engine_common::WasmCell;

#[cfg(feature = "runtime-diagnostics")]
struct RuntimeDiagnostics {
    process_timers_calls: u64,
    timer_cycles_credited: u64,
    timer_frames_requested: u64,
    first_timer_tsc: u64,
    last_timer_tsc: u64,
    timer_available_frames_total: u64,
    timer_cap_exceeded_calls: u64,
    timer_max_available_frames: u64,
    timer_frames_held_by_cap: u64,
    timer_available_histogram: [u64; 6],
    timer_final_frames_histogram: [u64; 3],
}

#[cfg(feature = "runtime-diagnostics")]
static DIAGNOSTICS: WasmCell<RuntimeDiagnostics> = WasmCell::new(RuntimeDiagnostics {
    process_timers_calls: 0,
    timer_cycles_credited: 0,
    timer_frames_requested: 0,
    first_timer_tsc: 0,
    last_timer_tsc: 0,
    timer_available_frames_total: 0,
    timer_cap_exceeded_calls: 0,
    timer_max_available_frames: 0,
    timer_frames_held_by_cap: 0,
    timer_available_histogram: [0; 6],
    timer_final_frames_histogram: [0; 3],
});

pub fn record_timer_poll(current_tsc: u64) {
    #[cfg(feature = "runtime-diagnostics")]
    {
        let mut diagnostics = DIAGNOSTICS.borrow_mut();
        diagnostics.process_timers_calls = diagnostics.process_timers_calls.saturating_add(1);
        if diagnostics.first_timer_tsc == 0 {
            diagnostics.first_timer_tsc = current_tsc;
        }
        diagnostics.last_timer_tsc = current_tsc;
    }
    #[cfg(not(feature = "runtime-diagnostics"))]
    let _ = current_tsc;
}

pub fn record_cycle_credit(cycles: u64) {
    #[cfg(feature = "runtime-diagnostics")]
    {
        let mut diagnostics = DIAGNOSTICS.borrow_mut();
        diagnostics.timer_cycles_credited =
            diagnostics.timer_cycles_credited.saturating_add(cycles);
    }
    #[cfg(not(feature = "runtime-diagnostics"))]
    let _ = cycles;
}

pub fn record_available_frames(available_frames: u64) {
    #[cfg(feature = "runtime-diagnostics")]
    {
        let bucket = match available_frames {
            0 => 0,
            1..=511 => 1,
            512..=1023 => 2,
            1024..=4095 => 3,
            4096..=65_535 => 4,
            _ => 5,
        };
        let mut diagnostics = DIAGNOSTICS.borrow_mut();
        diagnostics.timer_available_histogram[bucket] =
            diagnostics.timer_available_histogram[bucket].saturating_add(1);
        diagnostics.timer_available_frames_total = diagnostics
            .timer_available_frames_total
            .saturating_add(available_frames);
        diagnostics.timer_max_available_frames =
            diagnostics.timer_max_available_frames.max(available_frames);
    }
    #[cfg(not(feature = "runtime-diagnostics"))]
    let _ = available_frames;
}

pub fn record_final_frames(
    available_frames: u64,
    allowed_frames: u64,
    final_frames: u32,
    configured_batch_size: u32,
) {
    #[cfg(feature = "runtime-diagnostics")]
    {
        let final_bucket = if final_frames == 0 {
            0
        } else if final_frames < configured_batch_size {
            1
        } else {
            2
        };
        let mut diagnostics = DIAGNOSTICS.borrow_mut();
        diagnostics.timer_final_frames_histogram[final_bucket] =
            diagnostics.timer_final_frames_histogram[final_bucket].saturating_add(1);
        if available_frames > configured_batch_size as u64 {
            diagnostics.timer_cap_exceeded_calls =
                diagnostics.timer_cap_exceeded_calls.saturating_add(1);
            diagnostics.timer_frames_held_by_cap = diagnostics
                .timer_frames_held_by_cap
                .saturating_add(allowed_frames.saturating_sub(final_frames as u64));
        }
    }
    #[cfg(not(feature = "runtime-diagnostics"))]
    let _ = (
        available_frames,
        allowed_frames,
        final_frames,
        configured_batch_size,
    );
}

pub fn record_requested_frames(frames: u32) {
    #[cfg(feature = "runtime-diagnostics")]
    {
        let mut diagnostics = DIAGNOSTICS.borrow_mut();
        diagnostics.timer_frames_requested = diagnostics
            .timer_frames_requested
            .saturating_add(frames as u64);
    }
    #[cfg(not(feature = "runtime-diagnostics"))]
    let _ = frames;
}

pub fn report_generation_complete(
    packets: u128,
    elapsed_micros: u128,
    packets_per_second: u128,
    final_cycle_accumulator: u64,
) {
    #[cfg(feature = "runtime-diagnostics")]
    {
        let diagnostics = DIAGNOSTICS.borrow();
        log::info!(
            "generation run complete: packets={}, elapsed={}us, speed={} packets/s, process_timers_calls={}, timer_cycles_credited={}, timer_frames_requested={}, timer_available_frames_total={}, timer_cap_exceeded_calls={}, timer_max_available_frames={}, timer_frames_held_by_cap={}, available_frames_histogram={:?}, final_frames_histogram={:?}, first_timer_tsc={}, last_timer_tsc={}, final_cycle_accumulator={}",
            packets.separated_string(),
            elapsed_micros.separated_string(),
            packets_per_second.separated_string(),
            diagnostics.process_timers_calls.separated_string(),
            diagnostics.timer_cycles_credited.separated_string(),
            diagnostics.timer_frames_requested.separated_string(),
            diagnostics.timer_available_frames_total.separated_string(),
            diagnostics.timer_cap_exceeded_calls.separated_string(),
            diagnostics.timer_max_available_frames.separated_string(),
            diagnostics.timer_frames_held_by_cap.separated_string(),
            diagnostics.timer_available_histogram,
            diagnostics.timer_final_frames_histogram,
            diagnostics.first_timer_tsc.separated_string(),
            diagnostics.last_timer_tsc.separated_string(),
            final_cycle_accumulator.separated_string()
        );
    }
    #[cfg(not(feature = "runtime-diagnostics"))]
    log::info!(
        "generation run complete: packets={}, elapsed={}us, speed={} packets/s",
        packets.separated_string(),
        elapsed_micros.separated_string(),
        packets_per_second.separated_string()
    );
    #[cfg(not(feature = "runtime-diagnostics"))]
    let _ = final_cycle_accumulator;
}
