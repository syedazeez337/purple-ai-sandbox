// src/tests/test_error.rs

use crate::error::PurpleError;
use std::error::Error;
use std::io;

#[test]
fn test_error_conversions() {
    // Test IO error conversion
    let io_error = io::Error::new(io::ErrorKind::NotFound, "File not found");
    let purple_error: PurpleError = io_error.into();

    match purple_error {
        PurpleError::IoError(e) => {
            assert_eq!(e.kind(), io::ErrorKind::NotFound);
            assert_eq!(e.to_string(), "File not found");
        }
        _ => panic!("Expected IoError variant"),
    }

    // Test String error conversion
    let string_error = "Test error".to_string();
    let purple_error: PurpleError = string_error.into();

    match purple_error {
        PurpleError::SandboxError(msg) => {
            assert_eq!(msg, "Test error");
        }
        _ => panic!("Expected SandboxError variant"),
    }

    // Test &str error conversion
    let str_error: PurpleError = "Another test error".into();

    match str_error {
        PurpleError::SandboxError(msg) => {
            assert_eq!(msg, "Another test error");
        }
        _ => panic!("Expected SandboxError variant"),
    }
}

#[test]
fn test_error_display() {
    let error = PurpleError::SandboxError("Test sandbox error".to_string());
    assert_eq!(error.to_string(), "Sandbox error: Test sandbox error");

    let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "Permission denied");
    let error: PurpleError = io_error.into();
    assert_eq!(error.to_string(), "IO error: Permission denied");
}

#[test]
fn test_error_source() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "File not found");
    let purple_error: PurpleError = io_error.into();

    // Check that source is preserved
    assert!(purple_error.source().is_some());
    assert_eq!(purple_error.source().unwrap().to_string(), "File not found");

    // Check that string errors don't have a source
    let string_error: PurpleError = "Test error".into();
    assert!(string_error.source().is_none());
}
