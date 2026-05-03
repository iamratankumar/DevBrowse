//! `fixture::mock_platform` — programmable mocks for the five
//! `pb-platform` adapter traits.
//!
//! Subtask 2 of Module 0.5. Each mock is a thin in-process stub holding
//! a `Mutex<VecDeque<...>>` of scripted responses. Behavior:
//!   * If the queue is non-empty, the next response is consumed and
//!     returned.
//!   * If the queue is empty, a sensible default is returned (per-trait,
//!     documented inline).
//!
//! Example:
//!
//! ```ignore
//! use pb_testkit::fixture::mock_platform;
//! use pb_platform::PermissionState;
//!
//! let bundle = mock_platform();
//! bundle
//!     .notification
//!     .script_request_permission([PermissionState::Prompt, PermissionState::Granted]);
//!
//! assert_eq!(
//!     bundle.notification.request_permission().unwrap(),
//!     PermissionState::Prompt,
//! );
//! assert_eq!(
//!     bundle.notification.request_permission().unwrap(),
//!     PermissionState::Granted,
//! );
//! ```

use pb_platform::{
    Connectivity, FileHandle, FilePickerOptions, FileSystemAdapter, GestureToken, IconRef,
    InputAdapter, InputEvent, NetworkAdapter, Notification, NotificationAdapter, PermissionState,
    PlatformError, Position, ProxyConfig, Size, WindowAdapter, WindowId, WindowOptions,
};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

// ── Bundle ───────────────────────────────────────────────────────────────────

/// All five mocks held behind `Arc` so call sites can clone the bundle
/// into multiple test threads / tasks without losing the script handle.
#[derive(Clone)]
pub struct MockPlatformBundle {
    pub notification: Arc<MockNotificationAdapter>,
    pub filesystem: Arc<MockFileSystemAdapter>,
    pub window: Arc<MockWindowAdapter>,
    pub network: Arc<MockNetworkAdapter>,
    pub input: Arc<MockInputAdapter>,
}

/// Build a bundle of default mocks. Each trait method returns a sensible
/// default until the test scripts a different response.
pub fn mock_platform() -> MockPlatformBundle {
    MockPlatformBundle {
        notification: Arc::new(MockNotificationAdapter::default()),
        filesystem: Arc::new(MockFileSystemAdapter::default()),
        window: Arc::new(MockWindowAdapter::default()),
        network: Arc::new(MockNetworkAdapter::default()),
        input: Arc::new(MockInputAdapter::default()),
    }
}

// ── NotificationAdapter ──────────────────────────────────────────────────────

/// Captured `show()` call. Tests assert against `shown()` to verify what
/// was passed to the OS-level layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownNotification {
    pub title: String,
    pub body: String,
    pub icon: Option<IconRef>,
}

#[derive(Default)]
pub struct MockNotificationAdapter {
    permission_q: Mutex<VecDeque<PermissionState>>,
    request_q: Mutex<VecDeque<PermissionState>>,
    shown: Mutex<Vec<ShownNotification>>,
}

impl MockNotificationAdapter {
    /// Script the next N return values for `permission()`. Empty queue
    /// => fall back to `PermissionState::Prompt`.
    pub fn script_permission<I: IntoIterator<Item = PermissionState>>(&self, seq: I) {
        self.permission_q.lock().unwrap().extend(seq);
    }

    /// Script the next N return values for `request_permission()`. The
    /// canonical "Prompt then Granted" cadence the phase file calls out
    /// is just `[Prompt, Granted]`.
    pub fn script_request_permission<I: IntoIterator<Item = PermissionState>>(&self, seq: I) {
        self.request_q.lock().unwrap().extend(seq);
    }

    /// Recorded notifications, in order of `show()` calls.
    pub fn shown(&self) -> Vec<ShownNotification> {
        self.shown.lock().unwrap().clone()
    }
}

impl NotificationAdapter for MockNotificationAdapter {
    fn permission(&self) -> Result<PermissionState, PlatformError> {
        Ok(self
            .permission_q
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(PermissionState::Prompt))
    }

    fn request_permission(&self) -> Result<PermissionState, PlatformError> {
        Ok(self
            .request_q
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(PermissionState::Granted))
    }

    fn show(&self, n: Notification) -> Result<(), PlatformError> {
        self.shown.lock().unwrap().push(ShownNotification {
            title: n.title,
            body: n.body,
            icon: n.icon,
        });
        Ok(())
    }
}

// ── FileSystemAdapter ────────────────────────────────────────────────────────

/// Stubbed filesystem adapter. Picker calls return scripted handles;
/// `read_handle` returns scripted bytes, `write_handle` records calls.
#[derive(Default)]
pub struct MockFileSystemAdapter {
    open_q: Mutex<VecDeque<Option<FileHandle>>>,
    save_q: Mutex<VecDeque<Option<FileHandle>>>,
    read_responses: Mutex<VecDeque<Vec<u8>>>,
    writes: Mutex<Vec<(FileHandle, Vec<u8>)>>,
    filename_responses: Mutex<VecDeque<String>>,
    released: Mutex<Vec<FileHandle>>,
}

impl MockFileSystemAdapter {
    pub fn script_open<I: IntoIterator<Item = Option<FileHandle>>>(&self, seq: I) {
        self.open_q.lock().unwrap().extend(seq);
    }

    pub fn script_save<I: IntoIterator<Item = Option<FileHandle>>>(&self, seq: I) {
        self.save_q.lock().unwrap().extend(seq);
    }

    pub fn script_read_bytes<I: IntoIterator<Item = Vec<u8>>>(&self, seq: I) {
        self.read_responses.lock().unwrap().extend(seq);
    }

    pub fn script_filename<I: IntoIterator<Item = String>>(&self, seq: I) {
        self.filename_responses.lock().unwrap().extend(seq);
    }

    pub fn writes(&self) -> Vec<(FileHandle, Vec<u8>)> {
        self.writes.lock().unwrap().clone()
    }

    pub fn released(&self) -> Vec<FileHandle> {
        self.released.lock().unwrap().clone()
    }
}

impl FileSystemAdapter for MockFileSystemAdapter {
    fn open_picker(&self, _opts: FilePickerOptions) -> Result<Option<FileHandle>, PlatformError> {
        Ok(self
            .open_q
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Some(FileHandle::new())))
    }

    fn save_picker(&self, _opts: FilePickerOptions) -> Result<Option<FileHandle>, PlatformError> {
        Ok(self
            .save_q
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Some(FileHandle::new())))
    }

    fn register_dropped_path(&self, _path: &Path) -> Result<FileHandle, PlatformError> {
        Ok(FileHandle::new())
    }

    fn read_handle(&self, _handle: FileHandle) -> Result<Vec<u8>, PlatformError> {
        Ok(self
            .read_responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default())
    }

    fn write_handle(&self, handle: FileHandle, bytes: &[u8]) -> Result<(), PlatformError> {
        self.writes.lock().unwrap().push((handle, bytes.to_vec()));
        Ok(())
    }

    fn handle_filename(&self, _handle: FileHandle) -> Result<String, PlatformError> {
        Ok(self
            .filename_responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| "test.bin".to_string()))
    }

    fn release_handle(&self, handle: FileHandle) {
        self.released.lock().unwrap().push(handle);
    }
}

// ── WindowAdapter ────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MockWindowAdapter {
    next_id: Mutex<u64>,
    screen_size: Mutex<Option<Size>>,
    dpr_milli: Mutex<Option<u32>>,
    position: Mutex<Option<Position>>,
    creates: Mutex<Vec<WindowOptions>>,
}

/// Cohort-fixed fallback values returned by the mock when nothing is
/// scripted. These match the §5.5 Standard-mode bucket defaults so a
/// fingerprint test that forgets to script gets a stable cohort, not
/// platform-specific numbers.
pub const DEFAULT_MOCK_SCREEN_SIZE: Size = Size {
    width: 1920,
    height: 1080,
};
pub const DEFAULT_MOCK_DPR_MILLI: u32 = 1000;
pub const DEFAULT_MOCK_POSITION: Position = Position { x: 0, y: 0 };

impl MockWindowAdapter {
    pub fn set_screen_size(&self, size: Size) {
        *self.screen_size.lock().unwrap() = Some(size);
    }

    pub fn set_device_pixel_ratio_milli(&self, dpr: u32) {
        *self.dpr_milli.lock().unwrap() = Some(dpr);
    }

    pub fn set_position(&self, p: Position) {
        *self.position.lock().unwrap() = Some(p);
    }

    pub fn creates(&self) -> Vec<WindowOptions> {
        self.creates.lock().unwrap().clone()
    }
}

impl WindowAdapter for MockWindowAdapter {
    fn create(&self, opts: WindowOptions) -> Result<WindowId, PlatformError> {
        self.creates.lock().unwrap().push(opts);
        let mut n = self.next_id.lock().unwrap();
        *n += 1;
        Ok(WindowId(*n))
    }

    fn destroy(&self, _id: WindowId) -> Result<(), PlatformError> {
        Ok(())
    }

    fn set_title(&self, _id: WindowId, _title: &str) -> Result<(), PlatformError> {
        Ok(())
    }

    fn set_size(&self, _id: WindowId, _size: Size) -> Result<(), PlatformError> {
        Ok(())
    }

    fn focus(&self, _id: WindowId) -> Result<(), PlatformError> {
        Ok(())
    }

    fn screen_size(&self) -> Result<Size, PlatformError> {
        Ok(self
            .screen_size
            .lock()
            .unwrap()
            .unwrap_or(DEFAULT_MOCK_SCREEN_SIZE))
    }

    fn device_pixel_ratio_milli(&self, _id: WindowId) -> Result<u32, PlatformError> {
        Ok(self
            .dpr_milli
            .lock()
            .unwrap()
            .unwrap_or(DEFAULT_MOCK_DPR_MILLI))
    }

    fn window_position(&self, _id: WindowId) -> Result<Position, PlatformError> {
        Ok(self
            .position
            .lock()
            .unwrap()
            .unwrap_or(DEFAULT_MOCK_POSITION))
    }
}

// ── NetworkAdapter ───────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MockNetworkAdapter {
    connectivity_q: Mutex<VecDeque<Connectivity>>,
    proxy_q: Mutex<VecDeque<ProxyConfig>>,
    dns_q: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl MockNetworkAdapter {
    pub fn script_connectivity<I: IntoIterator<Item = Connectivity>>(&self, seq: I) {
        self.connectivity_q.lock().unwrap().extend(seq);
    }

    pub fn script_proxy<I: IntoIterator<Item = ProxyConfig>>(&self, seq: I) {
        self.proxy_q.lock().unwrap().extend(seq);
    }

    pub fn script_dns<I: IntoIterator<Item = Vec<IpAddr>>>(&self, seq: I) {
        self.dns_q.lock().unwrap().extend(seq);
    }
}

impl NetworkAdapter for MockNetworkAdapter {
    fn connectivity(&self) -> Result<Connectivity, PlatformError> {
        Ok(self
            .connectivity_q
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Connectivity::Online))
    }

    fn proxy_config(&self) -> Result<ProxyConfig, PlatformError> {
        Ok(self
            .proxy_q
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(ProxyConfig::Direct))
    }

    fn system_dns_servers(&self) -> Result<Vec<IpAddr>, PlatformError> {
        Ok(self.dns_q.lock().unwrap().pop_front().unwrap_or_default())
    }
}

// ── InputAdapter ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MockInputAdapter {
    poll_q: Mutex<VecDeque<Vec<InputEvent>>>,
    clipboard_read_q: Mutex<VecDeque<String>>,
    clipboard_writes: Mutex<Vec<String>>,
}

impl MockInputAdapter {
    pub fn script_poll<I: IntoIterator<Item = Vec<InputEvent>>>(&self, seq: I) {
        self.poll_q.lock().unwrap().extend(seq);
    }

    pub fn script_clipboard_read<I: IntoIterator<Item = String>>(&self, seq: I) {
        self.clipboard_read_q.lock().unwrap().extend(seq);
    }

    pub fn clipboard_writes(&self) -> Vec<String> {
        self.clipboard_writes.lock().unwrap().clone()
    }
}

impl InputAdapter for MockInputAdapter {
    fn poll(&self) -> Result<Vec<InputEvent>, PlatformError> {
        Ok(self.poll_q.lock().unwrap().pop_front().unwrap_or_default())
    }

    fn clipboard_read(&self, _gesture: GestureToken) -> Result<String, PlatformError> {
        Ok(self
            .clipboard_read_q
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default())
    }

    fn clipboard_write(&self, _gesture: GestureToken, text: &str) -> Result<(), PlatformError> {
        self.clipboard_writes.lock().unwrap().push(text.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_scripted_prompt_then_granted() {
        let bundle = mock_platform();
        bundle
            .notification
            .script_request_permission([PermissionState::Prompt, PermissionState::Granted]);
        assert_eq!(
            bundle.notification.request_permission().unwrap(),
            PermissionState::Prompt
        );
        assert_eq!(
            bundle.notification.request_permission().unwrap(),
            PermissionState::Granted
        );
    }

    #[test]
    fn notification_records_show_calls() {
        let bundle = mock_platform();
        bundle
            .notification
            .show(Notification {
                title: "t".into(),
                body: "b".into(),
                icon: None,
            })
            .unwrap();
        let shown = bundle.notification.shown();
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].title, "t");
    }

    #[test]
    fn filesystem_writes_recorded() {
        let bundle = mock_platform();
        let h = FileHandle::new();
        bundle.filesystem.write_handle(h, b"hello").unwrap();
        assert_eq!(bundle.filesystem.writes(), vec![(h, b"hello".to_vec())]);
    }

    #[test]
    fn network_default_is_online_direct_no_dns() {
        let bundle = mock_platform();
        assert_eq!(bundle.network.connectivity().unwrap(), Connectivity::Online);
        assert!(matches!(
            bundle.network.proxy_config().unwrap(),
            ProxyConfig::Direct
        ));
        assert!(bundle.network.system_dns_servers().unwrap().is_empty());
    }

    #[test]
    fn window_dpr_default_is_1000_milli() {
        let bundle = mock_platform();
        let id = bundle
            .window
            .create(WindowOptions {
                title: "x".into(),
                size: Size {
                    width: 800,
                    height: 600,
                },
                resizable: true,
            })
            .unwrap();
        assert_eq!(bundle.window.device_pixel_ratio_milli(id).unwrap(), 1000);
    }

    #[test]
    fn input_clipboard_write_recorded() {
        let bundle = mock_platform();
        bundle
            .input
            .clipboard_write(GestureToken::new(), "copied")
            .unwrap();
        assert_eq!(bundle.input.clipboard_writes(), vec!["copied".to_string()]);
    }
}
