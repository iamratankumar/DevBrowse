//! Send tab to device — Module 90.
//!
//! One-shot tab push to a named paired device. Encrypted to the
//! recipient device's X25519 key (per-recipient envelope, Module 89),
//! so even if the message rides through the hub-peer the hub cannot
//! read it.
//!
//! Payload: { url, title, scroll_position_y_pct, sent_at, source_device_id }.
//!
//! UX:
//!   * Recipient browser is foreground: tab opens in a new background
//!     tab. Toast banner at the top of the window: "Tab from {device}"
//!     with `Open / Dismiss / Undo` actions for 5 seconds.
//!   * Recipient browser is closed (or backgrounded on mobile): the
//!     blob queues at the hub-peer (or in the recipient's local pending
//!     queue if it was online and connected). On next launch (or
//!     foreground) the recipient shows a banner above the tab strip:
//!     "1 tab from {device} - Open / Dismiss." Never auto-opens
//!     without user action when the browser was closed.
//!   * Always show source device name + URL preview before opening.
//!     Defeats a compromised paired device shoving a phishing URL
//!     silently. No silent open path exists.
//!
//! TODO(Module 90):
//!   * Toolbar action wired in pb-ui: "Send tab to..." button opens
//!     a dropdown of paired devices (live status: online via mDNS,
//!     queued via hub, offline). Disabled if no paired devices.
//!   * Encrypt payload to recipient X25519 pubkey (sealed-box
//!     construction or HPKE, decision in Module 90 implementation).
//!   * Receiver-side queue: encrypted blobs land in a small SQLite
//!     table on the recipient with TTL (default 30 days). Banner
//!     reads from this table on browser launch.
//!   * Auto-open behaviour controlled by a per-device setting: default
//!     is "ask me" (toast with explicit Open). User can flip to
//!     "auto-open from trusted devices" if they want.
//!   * Source-device label and URL preview rendered with care: clamp
//!     URL length, render IDN punycode visibly, never auto-resolve
//!     URLs in the toast.
