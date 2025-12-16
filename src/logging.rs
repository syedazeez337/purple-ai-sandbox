// purple/src/logging.rs

use log::{LevelFilter, SetLoggerError};
use std::io::Write;
use std::sync::Once;

/// Initialize the logging system with the specified log level
pub fn init_logging(level: LevelFilter) -> Result<(), SetLoggerError> {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        env_logger::Builder::new()
            .filter_level(level)
            .format(|buf, record| {
                writeln!(
                    buf,
                    "[{}] {} - {}",
                    buf.timestamp_millis(),
                    record.level(),
                    record.args()
                )
            })
            .init();
    });

    Ok(())
}

/// Log level for different components
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        }
    }
}

/// Enhanced logging macros for different subsystems
#[macro_export]
macro_rules! sandbox_log {
    ($level:expr, $($arg:tt)*) => {{
        match $level {
            LogLevel::Trace => log::trace!($($arg)*),
            LogLevel::Debug => log::debug!($($arg)*),
            LogLevel::Info => log::info!($($arg)*),
            LogLevel::Warn => log::warn!($($arg)*),
            LogLevel::Error => log::error!($($arg)*),
        }
    }};
}

#[macro_export]
macro_rules! policy_log {
    ($level:expr, $($arg:tt)*) => {{
        match $level {
            LogLevel::Trace => log::trace!("[POLICY] {}", format_args!($($arg)*)),
            LogLevel::Debug => log::debug!("[POLICY] {}", format_args!($($arg)*)),
            LogLevel::Info => log::info!("[POLICY] {}", format_args!($($arg)*)),
            LogLevel::Warn => log::warn!("[POLICY] {}", format_args!($($arg)*)),
            LogLevel::Error => log::error!("[POLICY] {}", format_args!($($arg)*)),
        }
    }};
}

#[macro_export]
macro_rules! security_log {
    ($level:expr, $($arg:tt)*) => {{
        match $level {
            LogLevel::Trace => log::trace!("[SECURITY] {}", format_args!($($arg)*)),
            LogLevel::Debug => log::debug!("[SECURITY] {}", format_args!($($arg)*)),
            LogLevel::Info => log::info!("[SECURITY] {}", format_args!($($arg)*)),
            LogLevel::Warn => log::warn!("[SECURITY] {}", format_args!($($arg)*)),
            LogLevel::Error => log::error!("[SECURITY] {}", format_args!($($arg)*)),
        }
    }};
}

#[macro_export]
macro_rules! filesystem_log {
    ($level:expr, $($arg:tt)*) => {{
        match $level {
            LogLevel::Trace => log::trace!("[FS] {}", format_args!($($arg)*)),
            LogLevel::Debug => log::debug!("[FS] {}", format_args!($($arg)*)),
            LogLevel::Info => log::info!("[FS] {}", format_args!($($arg)*)),
            LogLevel::Warn => log::warn!("[FS] {}", format_args!($($arg)*)),
            LogLevel::Error => log::error!("[FS] {}", format_args!($($arg)*)),
        }
    }};
}

#[macro_export]
macro_rules! network_log {
    ($level:expr, $($arg:tt)*) => {{
        match $level {
            LogLevel::Trace => log::trace!("[NET] {}", format_args!($($arg)*)),
            LogLevel::Debug => log::debug!("[NET] {}", format_args!($($arg)*)),
            LogLevel::Info => log::info!("[NET] {}", format_args!($($arg)*)),
            LogLevel::Warn => log::warn!("[NET] {}", format_args!($($arg)*)),
            LogLevel::Error => log::error!("[NET] {}", format_args!($($arg)*)),
        }
    }};
}
