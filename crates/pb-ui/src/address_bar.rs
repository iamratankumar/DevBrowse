//! pb-ui::address_bar - Module 43.
//!
//! Floating URL bar (440 px centered, 36 px height). Owns UrlInput,
//! SuggestionList, and BadgeSlot. Emits three events to the shell:
//! NavigationCommitted, ConvertToStrictClicked, NetworkViewerRequested.
//!
//! UX spec: docs/design/modules/43.md
//! Impl design: docs/ui/43-address-bar.md
//! Patterns: blocked-counter.md, mode-indicator.md
//! Invariants: L18, L31, L32, L40, L41
//!
//! TODO Module 43 wiring: NavigationCommitted -> pb-network::NavigationBroker (Phase 11, Module 80)
//! TODO Module 43 wiring: SuggestionProvider -> pb-network::SuggestionBroker (Phase 11, Module 80)
//! TODO Module 43 wiring: BadgeEvent::BlockIncrement <- ChromeCommand::BlockOccurred (Module 21 via shell)
//! TODO Module 43 wiring: NetworkViewerRequested -> ChromeCommand::OpenNetworkViewer (Module 60)
//! TODO Module 43 wiring: partition_key <- real profile_id from AppState (Phase 11)
//! TODO Module 43 wiring: search engine preference <- pb-storage::Settings::search_engine (Module 64)

use std::future::Future;
use std::pin::Pin;
#[allow(unused_imports)] // forward-declared for Module 43 struct impls (Tasks 2-5)
use std::sync::Arc;
#[allow(unused_imports)] // forward-declared for Module 43 struct impls (Tasks 2-5)
use std::time::Duration;

#[allow(unused_imports)] // forward-declared for Module 43 struct impls (Tasks 2-5)
use iced::widget::{button, column, container, row, text, text_input};
#[allow(unused_imports)] // forward-declared for Module 43 struct impls (Tasks 2-5)
use iced::{task, Element, Length, Task};

#[allow(unused_imports)] // forward-declared for Module 43 struct impls (Tasks 2-5)
use crate::glass::GlassPanel;
use crate::shell::Mode;
#[allow(unused_imports)] // forward-declared for Module 43 struct impls (Tasks 2-5)
use crate::tokens;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Address bar state machine (docs/design/modules/43.md §State machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BarState {
    #[default]
    Rest,
    Focused,
    Navigating,
    /// Compact pill on scroll-down. Only reachable from Rest.
    Pill,
    /// Red lock + error message. Terminal until user dismisses.
    ErrorInterstitial,
}

// ---------------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------------

/// What the badge slot in the URL bar shows (blocked-counter.md).
/// Strict always shows the "Strict" pill regardless of count (L41).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeMode {
    Hidden,
    Blocked(u32),
    Strict,
}

impl BadgeMode {
    /// Derive the badge mode from the browsing mode and current block count.
    pub fn from_mode_and_count(mode: Mode, count: u32) -> Self {
        match mode {
            Mode::Strict => Self::Strict,
            Mode::Standard if count > 0 => Self::Blocked(count),
            Mode::Standard => Self::Hidden,
        }
    }

    /// Badge label text. Count caps at "999+" (blocked-counter.md edge case).
    pub fn label(self) -> Option<String> {
        match self {
            Self::Hidden => None,
            Self::Blocked(n) => Some(if n > 999 {
                "999+".to_string()
            } else {
                n.to_string()
            }),
            Self::Strict => Some("Strict".to_string()),
        }
    }
}

/// One row in the blocked-counter popover.
#[derive(Debug, Clone)]
pub struct BlockRow {
    pub domain: String,
    pub count: u32,
}

// ---------------------------------------------------------------------------
// Suggestions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Suggestion {
    pub text: String,
    pub kind: SuggestionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionKind {
    Search,
    Url,
    History,  // TODO Module 43 wiring: populate from pb-storage::HistoryStore (Module 48)
    Bookmark, // TODO Module 43 wiring: populate from pb-storage::BookmarkStore (Module 49)
}

/// Async suggestion source. Implement for DDG (Phase 11) or mock (tests).
///
/// L40: no keystrokes reach the provider before the 200 ms debounce fires.
/// The `partition_key` is the active profile_id - never a URL or display name.
pub trait SuggestionProvider: Send + Sync + 'static {
    fn suggest<'a>(
        &'a self,
        query: &'a str,
        partition_key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Suggestion>> + Send + 'a>>;
}

// ---------------------------------------------------------------------------
// URL validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UrlValidation {
    #[default]
    Empty,
    Valid,
    /// User typed something that is not a URL; will search on Enter.
    Invalid,
}

impl UrlValidation {
    pub fn classify(text: &str) -> Self {
        if text.is_empty() {
            Self::Empty
        } else if text.starts_with("http://")
            || text.starts_with("https://")
            || (text.contains('.') && !text.contains(' '))
        {
            Self::Valid
        } else {
            Self::Invalid
        }
    }
}

// ---------------------------------------------------------------------------
// Sub-component event enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum UrlInputEvent {
    Changed(String),
}

#[derive(Debug, Clone)]
pub enum SuggestionEvent {
    Loaded(Vec<Suggestion>),
    Selected(usize),
    Dismissed,
}

#[derive(Debug, Clone)]
pub enum BadgeEvent {
    /// One domain was blocked on the current page.
    BlockIncrement {
        domain: String,
    },
    PopoverToggled,
    PopoverClosed,
    /// Navigation started - reset count and close popover.
    Reset,
}

/// All messages handled by AddressBar.
#[derive(Debug, Clone)]
pub enum AddressBarMsg {
    UrlInput(UrlInputEvent),
    Suggestion(SuggestionEvent),
    Badge(BadgeEvent),
    FocusGained,
    FocusLost,
    NavigatePressed,
    EscPressed,
    ScrolledDown,
    ScrolledUp,
    InterstitialDismissed,
    ConvertToStrictClicked,
    ModeChanged(Mode),
    ReducedMotionChanged(bool),
}

/// Events emitted to the shell (the only cross-module boundary).
#[derive(Debug, Clone)]
pub enum AddressBarEvent {
    NavigationCommitted { url: String, mode: Mode },
    ConvertToStrictClicked,
    NetworkViewerRequested,
}
