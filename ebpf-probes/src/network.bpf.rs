#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{map, kprobe},
    maps::{RingBuf, HashMap},
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

    // Read address family from sockaddr structure to determine IPv4 vs IPv6
    // sockaddr.sa_family is at offset 0 (2 bytes)
    let sa_family: u16 = unsafe {
        let uaddr_ptr = ctx.arg(1).unwrap_or(0 as *const u8);
        core::ptr::read_volatile(uaddr_ptr as *const u16)
    };

    // AF_INET = 2 (IPv4), AF_INET6 = 10 (IPv6)
    let (ip_version, dest_ip_v4, dest_ip_v6, dest_port) = match sa_family {
        2 => {
            // AF_INET (IPv4)
            let dest_port: u16 = unsafe {
                let uaddr_ptr = ctx.arg(1).unwrap_or(0 as *const u8);
                // sockaddr_in.sin_port is at offset 2
                let sin_port_bytes: u16 = core::ptr::read_volatile(uaddr_ptr.add(2) as *const u16);
                sin_port_bytes.to_be()
            };

            let dest_ip: [u8; 4] = unsafe {
                let uaddr_ptr = ctx.arg(1).unwrap_or(0 as *const u8);
                // sockaddr_in.sin_addr.s_addr is at offset 4
                let sin_addr_bytes: u32 = core::ptr::read_volatile(uaddr_ptr.add(4) as *const u32);
                sin_addr_bytes.to_be_bytes()
            };

            (IpVersion::V4 as u8, dest_ip, [0u8; 16], dest_port)
        }
        10 => {
            // AF_INET6 (IPv6)
            let dest_port: u16 = unsafe {
                let uaddr_ptr = ctx.arg(1).unwrap_or(0 as *const u8);
                // sockaddr_in6.sin6_port is at offset 2
                let sin6_port_bytes: u16 = core::ptr::read_volatile(uaddr_ptr.add(2) as *const u16);
                sin6_port_bytes.to_be()
            };

            // sockaddr_in6.sin6_addr is at offset 8 (16 bytes)
            let mut dest_ip_v6: [u8; 16] = [0u8; 16];
            unsafe {
                let uaddr_ptr = ctx.arg(1).unwrap_or(0 as *const u8);
                // Read 16 bytes of IPv6 address
                for i in 0..16 {
                    dest_ip_v6[i] = core::ptr::read_volatile(uaddr_ptr.add(8 + i) as *const u8);
                }
            }

            (IpVersion::V6 as u8, [0u8; 4], dest_ip_v6, dest_port)
        }
        _ => {
            // Unknown address family, skip
            return Ok(0);
        }
    };

    let bytes: u32 = 0; // We'll keep this as 0 for now since we don't have packet size info in tcp_connect

    // Get current timestamp
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Create event
    let event = NetworkEvent {
        pid,
        source_port,
        dest_port,
        ip_version,
        _padding: [0u8; 3],
        dest_ip_v4,
        dest_ip_v6,
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
