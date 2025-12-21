#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};

// Map of Blocked IPv4 addresses (u32 in network byte order)
#[map]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Map of Blocked IPv6 addresses (128-bit as [u8; 16])
#[map]
static BLOCKED_IPS_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_skb]
pub fn block_outbound(ctx: SkBuffContext) -> i32 {
    match try_block_outbound(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Default Allow on error
    }
}

fn try_block_outbound(ctx: &SkBuffContext) -> Result<i32, i64> {
    // For cgroup_skb, the data pointer usually points to the L3 header (IP header)

    // Read version/IHL byte
    let ver_ihl = ctx.load::<u8>(0)?;
    let version = ver_ihl >> 4;

    match version {
        4 => try_block_ipv4(ctx),
        6 => try_block_ipv6(ctx),
        _ => Ok(1), // Allow unknown IP versions
    }
}

/// Check if an IPv4 destination address is blocked
fn try_block_ipv4(ctx: &SkBuffContext) -> Result<i32, i64> {
    // IPv4 Header: Dest IP is at offset 16
    let dest_ip = ctx.load::<u32>(16)?;

    // Check if blocked
    unsafe {
        if BLOCKED_IPS.get(&dest_ip).is_some() {
            // Found in blocklist -> Drop
            return Ok(0);
        }
    }

    // Default Allow
    Ok(1)
}

/// Check if an IPv6 destination address is blocked
fn try_block_ipv6(ctx: &SkBuffContext) -> Result<i32, i64> {
    // IPv6 Header: Dest IP is at offset 24 (16 bytes for source IP at offset 8, then 16 bytes for dest)
    // IPv6 header structure:
    //   0-3:   Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
    //   4-5:   Payload Length
    //   6:     Next Header
    //   7:     Hop Limit
    //   8-23:  Source Address (128 bits / 16 bytes)
    //   24-39: Destination Address (128 bits / 16 bytes)

    let mut dest_ip: [u8; 16] = [0u8; 16];

    // Read destination IPv6 address byte by byte
    // Note: Using individual byte loads for eBPF verifier compatibility
    dest_ip[0] = ctx.load::<u8>(24)?;
    dest_ip[1] = ctx.load::<u8>(25)?;
    dest_ip[2] = ctx.load::<u8>(26)?;
    dest_ip[3] = ctx.load::<u8>(27)?;
    dest_ip[4] = ctx.load::<u8>(28)?;
    dest_ip[5] = ctx.load::<u8>(29)?;
    dest_ip[6] = ctx.load::<u8>(30)?;
    dest_ip[7] = ctx.load::<u8>(31)?;
    dest_ip[8] = ctx.load::<u8>(32)?;
    dest_ip[9] = ctx.load::<u8>(33)?;
    dest_ip[10] = ctx.load::<u8>(34)?;
    dest_ip[11] = ctx.load::<u8>(35)?;
    dest_ip[12] = ctx.load::<u8>(36)?;
    dest_ip[13] = ctx.load::<u8>(37)?;
    dest_ip[14] = ctx.load::<u8>(38)?;
    dest_ip[15] = ctx.load::<u8>(39)?;

    // Check if blocked
    unsafe {
        if BLOCKED_IPS_V6.get(&dest_ip).is_some() {
            // Found in blocklist -> Drop
            return Ok(0);
        }
    }

    // Default Allow
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}