#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, kprobe},
    maps::{RingBuf, HashMap},
    programs::ProbeContext,
};

#[repr(C)]
pub struct NetworkEvent {
    pub pid: u32,
    pub source_port: u16,
    pub dest_ip: [u8; 4], // IPv4 address
    pub dest_port: u16,
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

fn try_network_connect(_ctx: &ProbeContext) -> Result<u32, i64> {
    // Get current PID and TGID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check if this PID is in our filter
    unsafe {
        if NETWORK_FILTER.get(&pid).is_none() {
            return Ok(0);
        }
    }

    // tcp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
    // We need to read from the sock structure to get connection details

    // For now, we'll create a placeholder event
    // In a real implementation, we'd read from the sock structure
    let source_port: u16 = 0;
    let dest_ip: [u8; 4] = [0, 0, 0, 0];
    let dest_port: u16 = 0;
    let bytes: u32 = 0;

    // Get current timestamp
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Create event
    let event = NetworkEvent {
        pid,
        source_port,
        dest_ip,
        dest_port,
        bytes,
        timestamp_ns,
    };

    // Submit event to ring buffer
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
