#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::{HashMap, RingBuf},
    programs::ProbeContext,
};

/// IP address type indicator
#[repr(u8)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

#[repr(C)]
pub struct NetworkEvent {
    pub pid: u32,
    pub source_port: u16,
    pub dest_port: u16,
    /// IP version: 4 for IPv4, 6 for IPv6
    pub ip_version: u8,
    /// Padding to maintain alignment
    pub _padding: [u8; 3],
    /// IPv4 address (only first 4 bytes used for IPv4)
    pub dest_ip_v4: [u8; 4],
    /// IPv6 address (full 16 bytes for IPv6)
    pub dest_ip_v6: [u8; 16],
    pub bytes: u32,
    pub timestamp_ns: u64,
}

// Map to filter which PIDs to trace
#[map]
static NETWORK_FILTER: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// Ring buffer for network events
#[map]
static NETWORK_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);

// Kprobe on tcp_connect to capture outgoing connections
#[kprobe]
pub fn network_connect(ctx: ProbeContext) -> u32 {
    match try_network_connect(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_network_connect(ctx: &ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    unsafe {
        if NETWORK_FILTER.get(&pid).is_none() {
            return Ok(0);
        }
    }

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    let event = NetworkEvent {
        pid,
        source_port: 0,
        dest_port: 0,
        ip_version: 0,
        _padding: [0u8; 3],
        dest_ip_v4: [0u8; 4],
        dest_ip_v6: [0u8; 16],
        bytes: 0,
        timestamp_ns,
    };

    if let Some(mut entry) = NETWORK_EVENTS.reserve::<NetworkEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
