//! FileSystemAdapter — Module 2 (capability-based, hardened in Module 2.1).
//!
//! SECURITY INVARIANT — never weaken:
//!   The trait surface NEVER accepts a `&Path` from a caller. Callers receive
//!   an opaque `FileHandle` from the picker and use that to read/write. Backends
//!   store the canonicalized path internally, indexed by handle.
//!
//!   Why: a path-string surface is honor-system. A buggy or malicious caller
//!   could pass any path. Capability tokens make arbitrary-path access a
//!   compile-time non-option.
//!
//! SECURITY INVARIANT — never bypass:
//!   Renderers NEVER call this trait directly. All file access flows through
//!   the IPC broker (pb-ipc, Module 6) under the OS-picker-gated model:
//!     * read  → user selects source via system open dialog
//!     * write → user selects destination via system save dialog
//!   No glob, no traversal, no path-from-string. Period.

use crate::PlatformError;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque capability token returned by the picker.
///
/// `FileHandle` carries no path string. The backend keeps a private map from
/// handle → canonicalized path. Handles are scoped to the lifetime of the
/// backend; release with `release_handle`. Cross-process transmission goes
/// through pb-ipc, which serializes only the inner `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileHandle(u64);

impl FileHandle {
    /// Mint a fresh, monotonically increasing handle.
    ///
    /// Backends call this exactly once per successful picker invocation and
    /// store the resulting (handle → path) mapping locally. The constructor
    /// is `pub` because backends live outside this crate; security comes from
    /// the process-model boundary, not from Rust visibility.
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        FileHandle(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    /// Raw u64 for IPC serialization only. Do NOT reconstruct paths from this.
    pub fn as_raw(self) -> u64 {
        self.0
    }

    /// Reconstruct a handle received over IPC. Returning `Self` here is safe:
    /// the receiver is in a process that already trusts its own handle map.
    pub fn from_raw(raw: u64) -> Self {
        FileHandle(raw)
    }
}

impl Default for FileHandle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct FilePickerOptions {
    pub title: String,
    /// (filter label, allowed extensions without leading dot).
    pub filters: Vec<(String, Vec<String>)>,
}

pub trait FileSystemAdapter: Send + Sync {
    /// Show OS open dialog. `Ok(None)` = user cancelled.
    fn open_picker(&self, opts: FilePickerOptions) -> Result<Option<FileHandle>, PlatformError>;

    /// Show OS save dialog. `Ok(None)` = user cancelled.
    fn save_picker(&self, opts: FilePickerOptions) -> Result<Option<FileHandle>, PlatformError>;

    /// Register a path the user dragged onto a window, minting a `FileHandle`.
    ///
    /// SECURITY INVARIANT — never weaken:
    ///   This method is the **third and only other** legitimate capability
    ///   source for `FileHandle` (alongside `open_picker` / `save_picker`).
    ///   It MUST be called ONLY from the chrome's OS-level drop-event handler
    ///   — i.e. the code path that observed the user actually dragging a file
    ///   onto a window. The OS witnessed the gesture; the path is therefore
    ///   trust-equivalent to a picker selection.
    ///
    /// SECURITY INVARIANT — never bypass:
    ///   This method MUST NOT be exposed to:
    ///     * renderers (directly or via IPC)
    ///     * any code path that accepts renderer-supplied data
    ///     * any caller that has not just received an OS drop event
    ///   A renderer-callable version of this would defeat the entire capability
    ///   model — it would let a malicious page mint a `FileHandle` for any path
    ///   it can construct as a string.
    ///
    /// Backends canonicalize the path internally, store it under a fresh
    /// handle, and return that handle. Cross-process transmission to renderers
    /// goes through pb-ipc, which serializes only the inner `u64` per §5.3.
    fn register_dropped_path(&self, path: &Path) -> Result<FileHandle, PlatformError>;

    /// Read the bytes of a previously picked file.
    fn read_handle(&self, handle: FileHandle) -> Result<Vec<u8>, PlatformError>;

    /// Write bytes to a previously chosen save destination.
    fn write_handle(&self, handle: FileHandle, bytes: &[u8]) -> Result<(), PlatformError>;

    /// User-visible filename (basename only, no directory components).
    /// For chrome display ("downloaded.pdf"). MUST NOT be exposed to content JS.
    fn handle_filename(&self, handle: FileHandle) -> Result<String, PlatformError>;

    /// Drop the backend's path mapping for this handle. After release,
    /// `read_handle` / `write_handle` for the same handle MUST return
    /// `PlatformError::InvalidArg`.
    fn release_handle(&self, handle: FileHandle);
}
