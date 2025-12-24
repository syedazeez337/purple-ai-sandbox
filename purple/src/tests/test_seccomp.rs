// src/tests/test_seccomp.rs

use crate::sandbox::syscall_table::{get_syscall_number, resolve_syscall_names};

#[test]
fn test_syscall_number_mapping() {
    // Test some common syscalls
    assert_eq!(get_syscall_number("read"), Some(0));
    assert_eq!(get_syscall_number("write"), Some(1));
    assert_eq!(get_syscall_number("open"), Some(2));
    assert_eq!(get_syscall_number("close"), Some(3));
    assert_eq!(get_syscall_number("execve"), Some(59));
    assert_eq!(get_syscall_number("exit_group"), Some(231));
    assert_eq!(get_syscall_number("clone3"), Some(435));

    // Test some network-related syscalls
    assert_eq!(get_syscall_number("socket"), Some(41));
    assert_eq!(get_syscall_number("connect"), Some(42));
    assert_eq!(get_syscall_number("bind"), Some(49));

    // Test unknown syscall
    assert_eq!(get_syscall_number("nonexistent_syscall"), None);
}

#[test]
fn test_syscall_name_resolution() {
    let syscall_names = vec![
        "read".to_string(),
        "write".to_string(),
        "openat".to_string(),
        "close".to_string(),
        "execve".to_string(),
        "unknown_syscall".to_string(), // This should be ignored
    ];

    let syscall_numbers = resolve_syscall_names(&syscall_names);

    // Should contain the known syscalls
    assert!(syscall_numbers.contains(&0)); // read
    assert!(syscall_numbers.contains(&1)); // write
    assert!(syscall_numbers.contains(&257)); // openat
    assert!(syscall_numbers.contains(&3)); // close
    assert!(syscall_numbers.contains(&59)); // execve

    // Should not contain unknown syscall
    assert!(!syscall_numbers.contains(&-1));

    // Should have exactly 5 entries (unknown one is ignored)
    assert_eq!(syscall_numbers.len(), 5);
}

#[test]
fn test_syscall_set_ordering() {
    // Test that the BTreeSet maintains order
    let names = vec![
        "write".to_string(),
        "read".to_string(),
        "execve".to_string(),
        "exit".to_string(),
    ];

    let numbers = resolve_syscall_names(&names);

    // Convert to vector to check ordering
    let number_vec: Vec<i64> = numbers.into_iter().collect();

    // Should be sorted
    assert!(number_vec.windows(2).all(|w| w[0] <= w[1]));

    // Should contain the expected syscalls
    assert!(number_vec.contains(&0)); // read
    assert!(number_vec.contains(&1)); // write
    assert!(number_vec.contains(&60)); // exit
    assert!(number_vec.contains(&59)); // execve
}
