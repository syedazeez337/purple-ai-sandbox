// purple/src/sandbox/syscall_table.rs
//
// Custom syscall table for universal syscall name → number resolution.
// This eliminates dependency on libseccomp's limited syscall database.
// Generated at build time from kernel headers.

use std::collections::BTreeSet;
use std::collections::HashMap;

include!(concat!(env!("OUT_DIR"), "/syscall_table.rs"));

#[derive(Debug, Clone)]
pub struct SyscallTable {
    name_to_number: HashMap<&'static str, i64>,
}

impl SyscallTable {
    #[inline]
    pub fn new() -> Self {
        let mut name_to_number = HashMap::new();

        for &(name, num) in SYSCALL_TABLE {
            name_to_number.insert(name, num);
        }

        Self { name_to_number }
    }

    #[inline]
    pub fn get_number(&self, name: &str) -> Option<i64> {
        self.name_to_number.get(name).copied()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.name_to_number.len()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.name_to_number.is_empty()
    }
}

impl Default for SyscallTable {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
pub static SYSCALL_TABLE_INSTANCE: std::sync::OnceLock<SyscallTable> = std::sync::OnceLock::new();

#[allow(dead_code)]
#[inline]
pub fn get_syscall_number(name: &str) -> Option<i64> {
    SYSCALL_TABLE_INSTANCE
        .get_or_init(SyscallTable::new)
        .get_number(name)
}

#[allow(dead_code)]
#[inline]
pub fn resolve_syscall_names(names: &[String]) -> BTreeSet<i64> {
    let mut numbers = BTreeSet::new();
    for name in names {
        if let Some(num) = get_syscall_number(name) {
            numbers.insert(num);
        } else {
            log::warn!("Unknown syscall name: {}", name);
        }
    }
    numbers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_syscalls_exist() {
        let table = SyscallTable::new();

        assert!(table.get_number("read").is_some());
        assert!(table.get_number("write").is_some());
        assert!(table.get_number("openat").is_some());
        assert!(table.get_number("close").is_some());
        assert!(table.get_number("execve").is_some());
        assert!(table.get_number("exit_group").is_some());
    }

    #[test]
    fn test_unknown_syscall_returns_none() {
        let table = SyscallTable::new();

        assert!(table.get_number("nonexistent_syscall").is_none());
        assert!(table.get_number("foo_bar_baz").is_none());
    }

    #[test]
    fn test_newer_syscalls_exist() {
        let table = SyscallTable::new();

        assert!(table.get_number("clone3").is_some());
        assert!(table.get_number("pidfd_send_signal").is_some());
        assert!(table.get_number("openat2").is_some());
        assert!(table.get_number("close_range").is_some());
    }

    #[test]
    fn test_syscall_table_not_empty() {
        let table = SyscallTable::new();
        assert!(!table.is_empty());
        // x86_64 has 300+ syscalls defined in kernel headers
        assert!(
            table.len() > 300,
            "Expected > 300 syscalls, got {}",
            table.len()
        );
    }
}
