#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};

// Map of Blocked IPs (IPv4 as u32 in network byte order)
#[map]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

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
    
    if version != 4 {
        return Ok(1); // Allow non-IPv4 for now
    }

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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}