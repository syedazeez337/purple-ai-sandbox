//! Event definitions and parsing logic for eBPF events

use serde::{Deserialize, Serialize};
use std::fmt;

/// Syscall event captured by eBPF
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl SyscallEvent {
    /// Convert from raw bytes to SyscallEvent
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }

        let mut event = Self {
            pid: 0,
            tid: 0,
            syscall_nr: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            timestamp_ns: 0,
            comm: [0; 16],
        };

        // Check alignment to prevent undefined behavior
        if bytes.as_ptr().align_offset(std::mem::align_of::<Self>()) != 0 {
            return None;
        }

        // Safe because we've checked the length and alignment
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr() as *const Self,
                &mut event as *mut Self,
                1,
            );
        }

        Some(event)
    }

    /// Get the process name as a string
    pub fn comm_str(&self) -> String {
        let end = self
            .comm
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.comm.len());
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }
}

impl fmt::Display for SyscallEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Syscall[pid={}, tid={}, nr={}, args=({:#x}, {:#x}, {:#x}), comm={}]",
            self.pid,
            self.tid,
            self.syscall_nr,
            self.arg0,
            self.arg1,
            self.arg2,
            self.comm_str()
        )
    }
}

/// File access event captured by eBPF
#[derive(Debug, Clone)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub syscall: u32,
    pub flags: u32,
    pub filename: [u8; 128], // Reduced to match BPF stack limit
    pub timestamp_ns: u64,
}

// Manual Serialize/Deserialize for FileAccessEvent due to array size limitation
impl serde::Serialize for FileAccessEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("FileAccessEvent", 5)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("syscall", &self.syscall)?;
        state.serialize_field("flags", &self.flags)?;
        state.serialize_field("filename", &self.filename_str())?;
        state.serialize_field("timestamp_ns", &self.timestamp_ns)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for FileAccessEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct Helper {
            pid: u32,
            syscall: u32,
            flags: u32,
            filename: String,
            timestamp_ns: u64,
        }
        let helper = Helper::deserialize(deserializer)?;
        let mut filename = [0u8; 128];
        let bytes = helper.filename.as_bytes();
        let len = bytes.len().min(128);
        filename[..len].copy_from_slice(&bytes[..len]);
        Ok(FileAccessEvent {
            pid: helper.pid,
            syscall: helper.syscall,
            flags: helper.flags,
            filename,
            timestamp_ns: helper.timestamp_ns,
        })
    }
}

impl FileAccessEvent {
    /// Convert from raw bytes to FileAccessEvent
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }

        let mut event = Self {
            pid: 0,
            syscall: 0,
            flags: 0,
            filename: [0; 128],
            timestamp_ns: 0,
        };

        // Check alignment to prevent undefined behavior
        if bytes.as_ptr().align_offset(std::mem::align_of::<Self>()) != 0 {
            return None;
        }

        // Safe because we've checked the length and alignment
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr() as *const Self,
                &mut event as *mut Self,
                1,
            );
        }

        Some(event)
    }

    /// Get the filename as a string
    pub fn filename_str(&self) -> String {
        let end = self
            .filename
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.filename.len());
        String::from_utf8_lossy(&self.filename[..end]).into_owned()
    }
}

impl fmt::Display for FileAccessEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FileAccess[pid={}, syscall={}, flags={:#x}, filename={}]",
            self.pid,
            self.syscall,
            self.flags,
            self.filename_str()
        )
    }
}

/// Network event captured by eBPF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub source_port: u16,
    pub dest_ip: [u8; 4],
    pub dest_port: u16,
    pub bytes: u32,
    pub timestamp_ns: u64,
}

impl NetworkEvent {
    /// Convert from raw bytes to NetworkEvent
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }

        let mut event = Self {
            pid: 0,
            source_port: 0,
            dest_ip: [0; 4],
            dest_port: 0,
            bytes: 0,
            timestamp_ns: 0,
        };

        // Check alignment to prevent undefined behavior
        if bytes.as_ptr().align_offset(std::mem::align_of::<Self>()) != 0 {
            return None;
        }

        // Safe because we've checked the length and alignment
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr() as *const Self,
                &mut event as *mut Self,
                1,
            );
        }

        Some(event)
    }

    /// Get the destination IP as a string
    pub fn dest_ip_str(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.dest_ip[0], self.dest_ip[1], self.dest_ip[2], self.dest_ip[3]
        )
    }
}

impl fmt::Display for NetworkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Network[pid={}, src_port={}, dest={}:{}, bytes={}]",
            self.pid,
            self.source_port,
            self.dest_ip_str(),
            self.dest_port,
            self.bytes
        )
    }
}
