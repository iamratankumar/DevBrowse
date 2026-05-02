//! Local backup / import — Module 85.
//!
//! Export the entire vault to a single user-controlled file; import on
//! another device. Same on-wire format as cluster sync, so the file is
//! interchangeable with a sync payload. The user picks where the file
//! goes (Documents folder, USB stick, encrypted external drive).
//!
//! TODO(Module 85):
//!   * Export = full vault snapshot, vault-format-versioned (Module 83).
//!     Filename suggestion: `devbrowse-backup-{YYYYMMDD}-{shortid}.vault`.
//!   * Import = passphrase prompt, decrypt with same Argon2id params
//!     stored in the file header, verify integrity, optionally merge
//!     into local vault via the Module 84 sync log.
//!   * Mobile file picker: iOS uses `UIDocumentPicker`, Android uses
//!     Storage Access Framework. Desktop uses native file dialog from
//!     pb-ui Module 58. Both surfaces share this module's API.
//!   * Format compatibility: if the imported file has a higher
//!     format_version than this build understands, refuse with a
//!     clear "upgrade DevBrowse to import this backup" error rather
//!     than partial-decrypt.
