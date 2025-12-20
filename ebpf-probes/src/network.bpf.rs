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

fn try_network_connect(ctx: &ProbeContext) -> Result<u32, i64> {
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

    // Read from the sock structure to get actual connection details
    let source_port: u16 = unsafe {
        let sk_ptr = ctx.arg(0).unwrap_or(0 as *const u8);
        // Read source port from sock structure
        // sock->sk_num is the source port (network byte order)
        let sk_num_offset = 16; // Offset to sk_num in sock structure
        let sk_num_bytes: u16 = core::ptr::read_volatile(sk_ptr.add(sk_num_offset) as *const u16);
        sk_num_bytes.to_be() // Convert from network byte order
    };

    let dest_port: u16 = unsafe {
        // Read destination port from sockaddr structure
        let uaddr_ptr = ctx.arg(1).unwrap_or(0 as *const u8);
        // sockaddr_in.sin_port is at offset 2
        let sin_port_bytes: u16 = core::ptr::read_volatile(uaddr_ptr.add(2) as *const u16);
        sin_port_bytes.to_be() // Convert from network byte order
    };

    let dest_ip: [u8; 4] = unsafe {
        // Read destination IP from sockaddr structure
        let uaddr_ptr = ctx.arg(1).unwrap_or(0 as *const u8);
        // sockaddr_in.sin_addr.s_addr is at offset 4
        let sin_addr_bytes: u32 = core::ptr::read_volatile(uaddr_ptr.add(4) as *const u32);
        sin_addr_bytes.to_be_bytes() // Convert to byte array
    };

    let bytes: u32 = 0; // We'll keep this as 0 for now since we don't have packet size info in tcp_connect

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
