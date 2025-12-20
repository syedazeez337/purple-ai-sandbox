#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    macros::{map, kprobe},
    maps::{RingBuf, HashMap},
    programs::ProbeContext,
};

#[repr(C)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub syscall: u32,
    pub flags: u32,
    pub filename: [u8; 128],  // Reduced to fit BPF stack limit
    pub timestamp_ns: u64,
}

// Map to filter which PIDs to trace
#[map]
static FILE_FILTER: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

// Ring buffer for file access events
#[map]
static FILE_EVENTS: RingBuf = RingBuf::with_byte_size(1 << 24, 0);

// Kprobe on do_sys_openat2 to capture file opens
#[kprobe]
pub fn file_open(ctx: ProbeContext) -> u32 {
    match try_file_open(&ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_file_open(ctx: &ProbeContext) -> Result<u32, i64> {
    // Get current PID and TGID
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // Check if this PID is in our filter
    unsafe {
        if FILE_FILTER.get(&pid).is_none() {
            return Ok(0);
        }
    }

    // Read arguments from kprobe context
    // do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
    // Argument 0: dfd (directory fd)
    // Argument 1: filename pointer
    // Argument 2: open_how struct pointer

    // Get filename pointer (arg1)
    let filename_ptr: *const u8 = ctx.arg(1).ok_or(1i64)?;

    // Read filename from userspace (limited to 128 bytes due to BPF stack limit)
    let mut filename = [0u8; 128];
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut filename);
    }

    // Get flags - we'd need to read from the open_how struct
    // For simplicity, we'll just mark as 0
    let flags: u32 = 0;

    // Get current timestamp
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Create event
    let event = FileAccessEvent {
        pid,
        syscall: 257, // openat2 syscall number
        flags,
        filename,
        timestamp_ns,
    };

    // Submit event to ring buffer
    if let Some(mut entry) = FILE_EVENTS.reserve::<FileAccessEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
