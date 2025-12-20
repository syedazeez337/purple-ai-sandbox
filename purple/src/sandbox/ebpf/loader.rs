//! eBPF program loader and event processor
//!
//! This module handles loading, attaching, and managing eBPF programs for
//! tracing syscalls, file access, and network connections from sandboxed processes.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "ebpf")]
use aya::Ebpf;
#[cfg(feature = "ebpf")]
use aya::maps::{HashMap as AyaHashMap, RingBuf};
#[cfg(feature = "ebpf")]
use aya::programs::{CgroupSkb, KProbe, TracePoint};

use crate::sandbox::ebpf::events::{FileAccessEvent, NetworkEvent, SyscallEvent};

/// Path to compiled eBPF programs (set by build.rs)
#[cfg(feature = "ebpf")]
const EBPF_PROGRAMS_DIR: &str = env!("EBPF_PROGRAMS_DIR");

/// Combined event type for all eBPF events
#[derive(Debug, Clone)]
pub enum EbpfEvent {
    Syscall(SyscallEvent),
    FileAccess(FileAccessEvent),
    Network(NetworkEvent),
}

/// Configuration for which eBPF tracers to enable
#[derive(Debug, Clone, Default)]
pub struct EbpfConfig {
    pub trace_syscalls: bool,
    pub trace_files: bool,
    pub trace_network: bool,
    pub enable_network_filter: bool,
}

/// eBPF loader and manager
#[cfg(feature = "ebpf")]
pub struct EbpfLoader {
    /// The syscall tracer eBPF program
    syscall_bpf: Option<Ebpf>,
    /// The file access tracer eBPF program
    file_bpf: Option<Ebpf>,
    /// The network tracer eBPF program
    network_bpf: Option<Ebpf>,
    /// The network filter eBPF program
    network_filter_bpf: Option<Ebpf>,
    /// Configuration
    config: EbpfConfig,
    /// Flag to indicate if programs are attached
    attached: bool,
    /// Flag to signal shutdown
    #[allow(dead_code)] // TODO: Use in async shutdown logic
    shutdown: Arc<AtomicBool>,
}

#[cfg(not(feature = "ebpf"))]
pub struct EbpfLoader;

#[cfg(feature = "ebpf")]
impl EbpfLoader {
    /// Create a new eBPF loader with default configuration
    pub fn new() -> Result<Self, EbpfError> {
        Self::with_config(EbpfConfig {
            trace_syscalls: true,
            trace_files: true,
            trace_network: true,
            enable_network_filter: true,
        })
    }

    /// Create a new eBPF loader with specific configuration
    pub fn with_config(config: EbpfConfig) -> Result<Self, EbpfError> {
        Ok(Self {
            syscall_bpf: None,
            file_bpf: None,
            network_bpf: None,
            network_filter_bpf: None,
            config,
            attached: false,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Load all configured eBPF programs from the compiled bytecode
    pub fn load_programs(&mut self) -> Result<(), EbpfError> {
        use std::path::Path;

        let programs_dir = Path::new(EBPF_PROGRAMS_DIR);
        log::info!("Loading eBPF programs from: {:?}", programs_dir);

        // Load syscall tracer
        if self.config.trace_syscalls {
            let syscall_path = programs_dir.join("syscall");
            if syscall_path.exists() {
                log::debug!("Loading syscall tracer from {:?}", syscall_path);
                let bytes = std::fs::read(&syscall_path).map_err(|e| {
                    EbpfError::LoadError(format!("Failed to read syscall program: {}", e))
                })?;
                self.load_syscall_tracer(&bytes)?;
            } else {
                log::warn!("Syscall tracer not found at {:?}", syscall_path);
            }
        }

        // Load file access tracer
        if self.config.trace_files {
            let file_path = programs_dir.join("file_access");
            if file_path.exists() {
                log::debug!("Loading file tracer from {:?}", file_path);
                let bytes = std::fs::read(&file_path).map_err(|e| {
                    EbpfError::LoadError(format!("Failed to read file program: {}", e))
                })?;
                self.load_file_tracer(&bytes)?;
            } else {
                log::warn!("File tracer not found at {:?}", file_path);
            }
        }

        // Load network tracer
        if self.config.trace_network {
            let network_path = programs_dir.join("network");
            if network_path.exists() {
                log::debug!("Loading network tracer from {:?}", network_path);
                let bytes = std::fs::read(&network_path).map_err(|e| {
                    EbpfError::LoadError(format!("Failed to read network program: {}", e))
                })?;
                self.load_network_tracer(&bytes)?;
            } else {
                log::warn!("Network tracer not found at {:?}", network_path);
            }
        }

        // Load network filter
        if self.config.enable_network_filter {
            let filter_path = programs_dir.join("network_filter");
            if filter_path.exists() {
                log::debug!("Loading network filter from {:?}", filter_path);
                let bytes = std::fs::read(&filter_path).map_err(|e| {
                    EbpfError::LoadError(format!("Failed to read network filter program: {}", e))
                })?;
                self.load_network_filter(&bytes)?;
            } else {
                // Don't warn heavily if missing, might be optional
                log::debug!("Network filter not found at {:?}", filter_path);
            }
        }

        Ok(())
    }

    /// Load eBPF syscall tracer from compiled bytecode
    pub fn load_syscall_tracer(&mut self, bytes: &[u8]) -> Result<(), EbpfError> {
        log::info!("Loading eBPF syscall tracer ({} bytes)", bytes.len());

        let mut bpf = Ebpf::load(bytes)
            .map_err(|e| EbpfError::LoadError(format!("Failed to load syscall BPF: {}", e)))?;

        // Get the tracepoint program
        let program: &mut TracePoint = bpf
            .program_mut("syscall_enter")
            .ok_or_else(|| EbpfError::LoadError("syscall_enter program not found".to_string()))?
            .try_into()
            .map_err(|e| EbpfError::LoadError(format!("Failed to get tracepoint: {}", e)))?;

        // Load the program
        program.load().map_err(|e| {
            EbpfError::LoadError(format!("Failed to load tracepoint program: {}", e))
        })?;

        self.syscall_bpf = Some(bpf);
        log::info!("Syscall tracer loaded successfully");
        Ok(())
    }

    /// Load eBPF file access tracer from compiled bytecode
    pub fn load_file_tracer(&mut self, bytes: &[u8]) -> Result<(), EbpfError> {
        log::info!("Loading eBPF file tracer ({} bytes)", bytes.len());

        let mut bpf = Ebpf::load(bytes)
            .map_err(|e| EbpfError::LoadError(format!("Failed to load file BPF: {}", e)))?;

        // Get the kprobe program
        let program: &mut KProbe = bpf
            .program_mut("file_open")
            .ok_or_else(|| EbpfError::LoadError("file_open program not found".to_string()))?
            .try_into()
            .map_err(|e| EbpfError::LoadError(format!("Failed to get kprobe: {}", e)))?;

        // Load the program
        program
            .load()
            .map_err(|e| EbpfError::LoadError(format!("Failed to load kprobe program: {}", e)))?;

        self.file_bpf = Some(bpf);
        log::info!("File tracer loaded successfully");
        Ok(())
    }

    /// Load eBPF network tracer from compiled bytecode
    pub fn load_network_tracer(&mut self, bytes: &[u8]) -> Result<(), EbpfError> {
        log::info!("Loading eBPF network tracer ({} bytes)", bytes.len());

        let mut bpf = Ebpf::load(bytes)
            .map_err(|e| EbpfError::LoadError(format!("Failed to load network BPF: {}", e)))?;

        // Get the kprobe program
        let program: &mut KProbe = bpf
            .program_mut("network_connect")
            .ok_or_else(|| EbpfError::LoadError("network_connect program not found".to_string()))?
            .try_into()
            .map_err(|e| EbpfError::LoadError(format!("Failed to get kprobe: {}", e)))?;

        // Load the program
        program
            .load()
            .map_err(|e| EbpfError::LoadError(format!("Failed to load kprobe program: {}", e)))?;

        self.network_bpf = Some(bpf);
        log::info!("Network tracer loaded successfully");
        Ok(())
    }

    /// Load eBPF network filter from compiled bytecode
    pub fn load_network_filter(&mut self, bytes: &[u8]) -> Result<(), EbpfError> {
        log::info!("Loading eBPF network filter ({} bytes)", bytes.len());

        let mut bpf = Ebpf::load(bytes).map_err(|e| {
            EbpfError::LoadError(format!("Failed to load network filter BPF: {}", e))
        })?;

        // Get the cgroup_skb program
        let program: &mut CgroupSkb = bpf
            .program_mut("block_outbound")
            .ok_or_else(|| EbpfError::LoadError("block_outbound program not found".to_string()))?
            .try_into()
            .map_err(|e| EbpfError::LoadError(format!("Failed to get CgroupSkb: {}", e)))?;

        // Load the program
        program.load().map_err(|e| {
            EbpfError::LoadError(format!("Failed to load CgroupSkb program: {}", e))
        })?;

        self.network_filter_bpf = Some(bpf);
        log::info!("Network filter loaded successfully");
        Ok(())
    }

    /// Attach all loaded programs to their targets
    pub fn attach_programs(&mut self) -> Result<(), EbpfError> {
        if self.attached {
            log::warn!("eBPF programs already attached");
            return Ok(());
        }

        // Attach syscall tracer
        if let Some(bpf) = &mut self.syscall_bpf {
            let program: &mut TracePoint = bpf
                .program_mut("syscall_enter")
                .ok_or_else(|| EbpfError::AttachError("syscall_enter not found".to_string()))?
                .try_into()
                .map_err(|e| EbpfError::AttachError(format!("Failed to get tracepoint: {}", e)))?;

            program.attach("raw_syscalls", "sys_enter").map_err(|e| {
                EbpfError::AttachError(format!("Failed to attach syscall tracer: {}", e))
            })?;
            log::info!("Syscall tracer attached to raw_syscalls:sys_enter");
        }

        // Attach file tracer
        if let Some(bpf) = &mut self.file_bpf {
            let program: &mut KProbe = bpf
                .program_mut("file_open")
                .ok_or_else(|| EbpfError::AttachError("file_open not found".to_string()))?
                .try_into()
                .map_err(|e| EbpfError::AttachError(format!("Failed to get kprobe: {}", e)))?;

            program.attach("do_sys_openat2", 0).map_err(|e| {
                EbpfError::AttachError(format!("Failed to attach file tracer: {}", e))
            })?;
            log::info!("File tracer attached to do_sys_openat2");
        }

        // Attach network tracer
        if let Some(bpf) = &mut self.network_bpf {
            let program: &mut KProbe = bpf
                .program_mut("network_connect")
                .ok_or_else(|| EbpfError::AttachError("network_connect not found".to_string()))?
                .try_into()
                .map_err(|e| EbpfError::AttachError(format!("Failed to get kprobe: {}", e)))?;

            program.attach("tcp_connect", 0).map_err(|e| {
                EbpfError::AttachError(format!("Failed to attach network tracer: {}", e))
            })?;
            log::info!("Network tracer attached to tcp_connect");
        }

        self.attached = true;
        Ok(())
    }

    /// Attach network filter to a specific cgroup
    pub fn attach_network_filter(&mut self, cgroup_file: std::fs::File) -> Result<(), EbpfError> {
        if let Some(bpf) = &mut self.network_filter_bpf {
            let program: &mut CgroupSkb = bpf
                .program_mut("block_outbound")
                .ok_or_else(|| EbpfError::AttachError("block_outbound not found".to_string()))?
                .try_into()
                .map_err(|e| EbpfError::AttachError(format!("Failed to get CgroupSkb: {}", e)))?;

            // Attach to the cgroup file descriptor
            // CgroupSkb::attach takes an AsRawFd (File works)
            let attach_type = aya::programs::CgroupSkbAttachType::Egress;
            let attach_mode = aya::programs::CgroupAttachMode::Single;
            // We want to block OUTBOUND traffic

            program
                .attach(cgroup_file, attach_type, attach_mode)
                .map_err(|e| {
                    EbpfError::AttachError(format!("Failed to attach network filter: {}", e))
                })?;

            log::info!("Network filter attached to cgroup (Egress)");
        }
        Ok(())
    }

    /// Add an IP to the blocklist
    pub fn block_ip(&mut self, ip: std::net::Ipv4Addr) -> Result<(), EbpfError> {
        if let Some(bpf) = &mut self.network_filter_bpf {
            let mut blocklist: AyaHashMap<_, u32, u8> = bpf
                .map_mut("BLOCKED_IPS")
                .ok_or_else(|| EbpfError::MapError("BLOCKED_IPS map not found".to_string()))?
                .try_into()
                .map_err(|e| EbpfError::MapError(format!("Failed to get blocklist map: {}", e)))?;

            // IP should be in network byte order (Big Endian) as that's how BPF sees it
            // u32::from(ip) is Host Byte Order.
            // BPF ctx.load::<u32>(16) loads raw bytes.
            // 1.2.3.4 -> 0x01020304 in Big Endian.
            // If Host is Little Endian (x86), u32::from is 0x04030201.
            // We need to convert to Network Byte Order (Big Endian).
            let ip_u32 = u32::from(ip).to_be();

            blocklist.insert(ip_u32, 1, 0).map_err(|e| {
                EbpfError::MapError(format!("Failed to insert IP into blocklist: {}", e))
            })?;
            log::debug!("Blocked IP: {}", ip);
        }
        Ok(())
    }

    /// Register a PID to be traced by all probes
    pub fn register_sandbox_pid(&mut self, pid: i32) -> Result<(), EbpfError> {
        let pid_u32 = pid as u32;
        log::info!("Registering PID {} for eBPF tracing", pid);

        // Register in syscall filter
        if let Some(bpf) = &mut self.syscall_bpf {
            let mut filter: AyaHashMap<_, u32, u32> = bpf
                .map_mut("SYSCALL_FILTER")
                .ok_or_else(|| EbpfError::MapError("SYSCALL_FILTER map not found".to_string()))?
                .try_into()
                .map_err(|e| {
                    EbpfError::MapError(format!("Failed to get syscall filter map: {}", e))
                })?;

            filter.insert(pid_u32, 1, 0).map_err(|e| {
                EbpfError::MapError(format!("Failed to insert PID into syscall filter: {}", e))
            })?;
            log::debug!("Registered PID {} in SYSCALL_FILTER", pid);
        }

        // Register in file filter
        if let Some(bpf) = &mut self.file_bpf {
            let mut filter: AyaHashMap<_, u32, u32> = bpf
                .map_mut("FILE_FILTER")
                .ok_or_else(|| EbpfError::MapError("FILE_FILTER map not found".to_string()))?
                .try_into()
                .map_err(|e| {
                    EbpfError::MapError(format!("Failed to get file filter map: {}", e))
                })?;

            filter.insert(pid_u32, 1, 0).map_err(|e| {
                EbpfError::MapError(format!("Failed to insert PID into file filter: {}", e))
            })?;
            log::debug!("Registered PID {} in FILE_FILTER", pid);
        }

        // Register in network filter
        if let Some(bpf) = &mut self.network_bpf {
            let mut filter: AyaHashMap<_, u32, u32> = bpf
                .map_mut("NETWORK_FILTER")
                .ok_or_else(|| EbpfError::MapError("NETWORK_FILTER map not found".to_string()))?
                .try_into()
                .map_err(|e| {
                    EbpfError::MapError(format!("Failed to get network filter map: {}", e))
                })?;

            filter.insert(pid_u32, 1, 0).map_err(|e| {
                EbpfError::MapError(format!("Failed to insert PID into network filter: {}", e))
            })?;
            log::debug!("Registered PID {} in NETWORK_FILTER", pid);
        }

        Ok(())
    }

    /// Unregister a PID from all filters
    #[allow(dead_code)] // TODO: Use when PID cleanup is needed
    pub fn unregister_sandbox_pid(&mut self, pid: i32) -> Result<(), EbpfError> {
        let pid_u32 = pid as u32;
        log::info!("Unregistering PID {} from eBPF tracing", pid);

        if let Some(bpf) = &mut self.syscall_bpf
            && let Ok(mut filter) =
                AyaHashMap::<_, u32, u32>::try_from(bpf.map_mut("SYSCALL_FILTER").unwrap())
        {
            let _ = filter.remove(&pid_u32);
        }

        if let Some(bpf) = &mut self.file_bpf
            && let Ok(mut filter) =
                AyaHashMap::<_, u32, u32>::try_from(bpf.map_mut("FILE_FILTER").unwrap())
        {
            let _ = filter.remove(&pid_u32);
        }

        if let Some(bpf) = &mut self.network_bpf
            && let Ok(mut filter) =
                AyaHashMap::<_, u32, u32>::try_from(bpf.map_mut("NETWORK_FILTER").unwrap())
        {
            let _ = filter.remove(&pid_u32);
        }

        Ok(())
    }

    /// Poll events from all ring buffers (blocking)
    pub fn poll_events(&mut self) -> Result<Vec<EbpfEvent>, EbpfError> {
        let mut events = Vec::new();

        // Poll syscall events
        if let Some(bpf) = &mut self.syscall_bpf
            && let Some(map) = bpf.map_mut("SYSCALL_EVENTS")
            && let Ok(mut ring_buf) = RingBuf::try_from(map)
        {
            while let Some(item) = ring_buf.next() {
                if let Some(event) = SyscallEvent::from_bytes(&item) {
                    events.push(EbpfEvent::Syscall(event));
                }
            }
        }

        // Poll file events
        if let Some(bpf) = &mut self.file_bpf
            && let Some(map) = bpf.map_mut("FILE_EVENTS")
            && let Ok(mut ring_buf) = RingBuf::try_from(map)
        {
            while let Some(item) = ring_buf.next() {
                if let Some(event) = FileAccessEvent::from_bytes(&item) {
                    events.push(EbpfEvent::FileAccess(event));
                }
            }
        }

        // Poll network events
        if let Some(bpf) = &mut self.network_bpf
            && let Some(map) = bpf.map_mut("NETWORK_EVENTS")
            && let Ok(mut ring_buf) = RingBuf::try_from(map)
        {
            while let Some(item) = ring_buf.next() {
                if let Some(event) = NetworkEvent::from_bytes(&item) {
                    events.push(EbpfEvent::Network(event));
                }
            }
        }

        Ok(events)
    }

    /// Poll events asynchronously with timeout
    #[allow(dead_code)] // TODO: Use for async event polling
    pub async fn poll_events_async(
        &mut self,
        timeout_ms: u64,
    ) -> Result<Vec<EbpfEvent>, EbpfError> {
        // For now, do a simple poll with sleep
        // A more sophisticated implementation would use epoll/AsyncFd
        tokio::time::sleep(std::time::Duration::from_millis(timeout_ms.min(10))).await;
        self.poll_events()
    }

    /// Signal shutdown to stop event polling
    #[allow(dead_code)] // TODO: Use for graceful shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown was signaled
    #[allow(dead_code)] // TODO: Use for shutdown status checking
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Check if programs are attached
    #[allow(dead_code)] // TODO: Use for attachment status checking
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Get the shutdown flag for sharing with other threads
    #[allow(dead_code)] // TODO: Use for external shutdown control
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }
}

#[cfg(not(feature = "ebpf"))]
impl EbpfLoader {
    pub fn new() -> Result<Self, EbpfError> {
        Err(EbpfError::NotSupported)
    }

    pub fn register_sandbox_pid(&self, _pid: i32) -> Result<(), EbpfError> {
        Err(EbpfError::NotSupported)
    }
}

impl Default for EbpfLoader {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            #[cfg(feature = "ebpf")]
            {
                EbpfLoader {
                    syscall_bpf: None,
                    file_bpf: None,
                    network_bpf: None,
                    network_filter_bpf: None,
                    config: EbpfConfig::default(),
                    attached: false,
                    shutdown: Arc::new(AtomicBool::new(false)),
                }
            }
            #[cfg(not(feature = "ebpf"))]
            {
                EbpfLoader
            }
        })
    }
}

impl fmt::Debug for EbpfLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "ebpf")]
        {
            f.debug_struct("EbpfLoader")
                .field("attached", &self.attached)
                .field("config", &self.config)
                .finish()
        }
        #[cfg(not(feature = "ebpf"))]
        {
            f.debug_struct("EbpfLoader").finish()
        }
    }
}

/// Error type for eBPF operations
#[derive(Debug)]
pub enum EbpfError {
    /// Error loading BPF program
    LoadError(String),
    /// Error attaching program
    AttachError(String),
    /// Map operation error
    MapError(String),
    /// Channel closed
    #[allow(dead_code)] // TODO: Use for channel error handling
    ChannelClosed,
    /// eBPF not supported on this system
    #[allow(dead_code)] // TODO: Use for platform compatibility
    NotSupported,
    /// Feature not enabled
    #[allow(dead_code)] // TODO: Use for feature detection
    FeatureNotEnabled(String),
    /// IO error
    IoError(String),
}

impl fmt::Display for EbpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EbpfError::LoadError(s) => write!(f, "eBPF load error: {}", s),
            EbpfError::AttachError(s) => write!(f, "eBPF attach error: {}", s),
            EbpfError::MapError(s) => write!(f, "eBPF map error: {}", s),
            EbpfError::ChannelClosed => write!(f, "eBPF channel closed"),
            EbpfError::NotSupported => write!(f, "eBPF not supported on this system"),
            EbpfError::FeatureNotEnabled(s) => write!(f, "eBPF feature not enabled: {}", s),
            EbpfError::IoError(s) => write!(f, "eBPF IO error: {}", s),
        }
    }
}

impl std::error::Error for EbpfError {}

impl From<std::io::Error> for EbpfError {
    fn from(e: std::io::Error) -> Self {
        EbpfError::IoError(e.to_string())
    }
}
