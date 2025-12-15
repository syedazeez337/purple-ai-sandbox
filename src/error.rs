// purple/src/error.rs

use std::fmt;
use std::io;

/// Custom error type for Purple sandbox operations
#[derive(Debug)]
pub enum PurpleError {
    /// IO-related errors
    IoError(io::Error),
    /// Policy-related errors
    PolicyError(String),
    /// Sandbox execution errors
    SandboxError(String),
    /// Namespace setup errors
    NamespaceError(String),
    /// Filesystem operation errors
    FilesystemError(String),
    /// Resource limit errors
    ResourceError(String),
    /// Network configuration errors
    NetworkError(String),
    /// Capability management errors
    CapabilityError(String),
    /// Syscall filtering errors
    SyscallError(String),
    /// Audit logging errors
    AuditError(String),
    /// Command execution errors
    CommandError(String),
    /// Configuration errors
    ConfigError(String),
    /// Permission/privilege errors
    PermissionError(String),
}

impl fmt::Display for PurpleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PurpleError::IoError(e) => write!(f, "IO error: {}", e),
            PurpleError::PolicyError(e) => write!(f, "Policy error: {}", e),
            PurpleError::SandboxError(e) => write!(f, "Sandbox error: {}", e),
            PurpleError::NamespaceError(e) => write!(f, "Namespace error: {}", e),
            PurpleError::FilesystemError(e) => write!(f, "Filesystem error: {}", e),
            PurpleError::ResourceError(e) => write!(f, "Resource error: {}", e),
            PurpleError::NetworkError(e) => write!(f, "Network error: {}", e),
            PurpleError::CapabilityError(e) => write!(f, "Capability error: {}", e),
            PurpleError::SyscallError(e) => write!(f, "Syscall error: {}", e),
            PurpleError::AuditError(e) => write!(f, "Audit error: {}", e),
            PurpleError::CommandError(e) => write!(f, "Command error: {}", e),
            PurpleError::ConfigError(e) => write!(f, "Config error: {}", e),
            PurpleError::PermissionError(e) => write!(f, "Permission error: {}", e),
        }
    }
}

impl std::error::Error for PurpleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PurpleError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PurpleError {
    fn from(err: io::Error) -> Self {
        PurpleError::IoError(err)
    }
}

impl From<String> for PurpleError {
    fn from(err: String) -> Self {
        PurpleError::SandboxError(err)
    }
}

impl From<&str> for PurpleError {
    fn from(err: &str) -> Self {
        PurpleError::SandboxError(err.to_string())
    }
}

/// Result type for Purple operations
pub type Result<T> = std::result::Result<T, PurpleError>;