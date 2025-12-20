//! eBPF integration module for Purple AI Sandbox
//!
//! This module provides the eBPF-based observability features for tracing
//! syscalls, file access, and network connections from sandboxed processes.

pub mod correlator;
pub mod events;
pub mod loader;

pub use correlator::CorrelationEngine;
pub use loader::{EbpfConfig, EbpfEvent, EbpfLoader};
