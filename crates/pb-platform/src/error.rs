//! Common error type for all OS adapter traits — Module 2.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("operation not supported on this platform")]
    Unsupported,
    #[error("operating system error: {0}")]
    Os(String),
    #[error("permission denied")]
    PermissionDenied,
    #[error("user cancelled the request")]
    Cancelled,
    #[error("invalid argument: {0}")]
    InvalidArg(String),
}
