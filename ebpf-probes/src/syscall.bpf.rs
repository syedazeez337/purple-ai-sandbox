#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_get_current_comm},
    macros::{map, tracepoint},
    maps::{RingBuf, HashMap},
    programs::TracePointContext,
};

#[repr(C)]
pub struct SyscallEvent {
    pub pid: u32,
    pub tid: u32,
    pub syscall_nr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
}

// Map to filter which PIDs to trace
#[map]
static SYSCALL_FILTER: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// Ring buffer for syscall events
#[map]
static SYSCALL_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);

#[tracepoint]
pub fn syscall_enter(ctx: TracePointContext) -> u32 {
    match try_syscall_enter(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_syscall_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    // Get current PID and TGID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // Check if this PID is in our filter
    unsafe {
        if SYSCALL_FILTER.get(&pid).is_none() {
            return Ok(0);
        }
    }

    // Read syscall number from tracepoint args
    // For raw_syscalls:sys_enter, the format is:
    // field: long id (syscall number)
    // field: unsigned long args[6]
    let syscall_nr: u64 = unsafe { ctx.read_at(8)? };

    // Read first three arguments from the args array
    let arg0: u64 = unsafe { ctx.read_at(16)? };
    let arg1: u64 = unsafe { ctx.read_at(24)? };
    let arg2: u64 = unsafe { ctx.read_at(32)? };

    // Get current timestamp
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Get process name (comm)
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    // Create event
    let event = SyscallEvent {
        pid,
        tid,
        syscall_nr,
        arg0,
        arg1,
        arg2,
        timestamp_ns,
        comm,
    };

    // Submit event to ring buffer
    if let Some(mut entry) = SYSCALL_EVENTS.reserve::<SyscallEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
