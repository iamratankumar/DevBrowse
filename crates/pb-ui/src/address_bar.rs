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
//! TODO Module 43 wiring: BadgeEvent::Reset <- ChromeCommand::PageLoadStarted (Module 21 via shell); NOT fired here
//! TODO Module 43 wiring: NavigatedExternally(url) <- ChromeCommand::ExternalNavigation (Module 80 orchestrator)
//! TODO Module 43 wiring: NetworkViewerRequested -> ChromeCommand::OpenNetworkViewer (Module 60)
//! TODO Module 43 wiring: partition_key <- real profile_id from AppState (Phase 11)
//! TODO Module 43 wiring: search engine preference <- pb-storage::Settings::search_engine (Module 64)
//! TODO Module 52 wiring: NavigatedExternally skips chip (ChipState::Hidden) when link-click-opens-as=Standard

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
use crate::design;
#[allow(unused_imports)] // forward-declared for Module 43 struct impls (Tasks 2-5)
use crate::glass::GlassPanel;
use crate::shell::Mode;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

/// Controls whether and why the Convert-to-Strict chip is visible.
///
/// Transitions are strictly forward: FreshTab → Hidden, ExternalUrl → Hidden.
/// No backward transition exists (§3.6: once Standard is committed, it stays).
///
/// TODO Module 52 wiring: link-click-opens-as preference from pb-config::Settings
/// determines whether ExternalUrl triggers ChipState::ExternalUrl or skips to Hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChipState {
    /// New tab, no URL committed yet. Chip shown until Enter pressed or dismissed.
    #[default]
    FreshTab,
    /// URL pushed externally (app link, protocol handler, link-click-new-tab).
    /// Chip shown for 30 s then auto-dismissed unless user acts first.
    ExternalUrl,
    /// Chip is permanently gone for this tab. Set when:
    /// - user pressed Enter (committed to Standard), or
    /// - 30 s auto-dismiss timer fired (ExternalUrl case), or
    /// - user clicked the × dismiss button.
    Hidden,
}

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

/// Test-only suggestion provider. Gated behind the `mock` feature so it
/// cannot ship in production builds. Never makes network requests (L40).
#[cfg(feature = "mock")]
pub struct MockSuggestionProvider;

#[cfg(feature = "mock")]
impl SuggestionProvider for MockSuggestionProvider {
    fn suggest<'a>(
        &'a self,
        query: &'a str,
        _partition_key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Suggestion>> + Send + 'a>> {
        let query = query.to_string();
        Box::pin(async move {
            if query.is_empty() {
                return Vec::new();
            }
            vec![
                Suggestion {
                    text: format!("search DuckDuckGo for \"{query}\""),
                    kind: SuggestionKind::Search,
                },
                Suggestion {
                    text: format!("https://{query}.com"),
                    kind: SuggestionKind::Url,
                },
            ]
        })
    }
}

// ---------------------------------------------------------------------------
// BadgeSlot
// ---------------------------------------------------------------------------

/// Live badge state for the current page (blocked-counter.md).
/// Owns the domain-level ring buffer (capped at 256 rows) and drives
/// the popover open/close state.
///
/// TODO Module 43 wiring: receive BadgeEvent::BlockIncrement from ChromeCommand::BlockOccurred (Module 21 via shell)
/// TODO Module 43 wiring: call sync_mode when shell emits ModeChanged
#[derive(Debug)]
pub struct BadgeSlot {
    pub mode: BadgeMode,
    pub popover_open: bool,
    pub rows: Vec<BlockRow>,
    /// Running total of blocks since last navigation reset. Not necessarily equal
    /// to the sum of `rows[*].count` when the ring buffer has evicted old entries.
    pub block_count: u32,
}

impl BadgeSlot {
    pub fn new(browsing_mode: Mode) -> Self {
        Self {
            mode: BadgeMode::from_mode_and_count(browsing_mode, 0),
            popover_open: false,
            rows: Vec::new(),
            block_count: 0,
        }
    }

    pub fn update(&mut self, event: BadgeEvent) {
        match event {
            BadgeEvent::BlockIncrement { domain } => {
                self.block_count += 1;
                self.mode = BadgeMode::from_mode_and_count(
                    match self.mode {
                        BadgeMode::Strict => Mode::Strict,
                        _ => Mode::Standard,
                    },
                    self.block_count,
                );
                if let Some(row) = self.rows.iter_mut().find(|r| r.domain == domain) {
                    row.count += 1;
                } else {
                    self.rows.push(BlockRow { domain, count: 1 });
                }
                // Cap ring buffer at 256 entries (blocked-counter.md edge case).
                if self.rows.len() > 256 {
                    self.rows.drain(..1);
                }
            }
            BadgeEvent::PopoverToggled => {
                self.popover_open = !self.popover_open;
            }
            BadgeEvent::PopoverClosed => {
                self.popover_open = false;
            }
            BadgeEvent::Reset => {
                self.block_count = 0;
                self.mode = match self.mode {
                    BadgeMode::Strict => BadgeMode::Strict,
                    _ => BadgeMode::Hidden,
                };
                self.rows.clear();
                self.popover_open = false;
            }
        }
    }

    /// Re-derive the badge mode when the browsing mode changes.
    pub fn sync_mode(&mut self, browsing_mode: Mode) {
        self.mode = BadgeMode::from_mode_and_count(browsing_mode, self.block_count);
        // Strict badge shows no clickable count pill, so close any open popover
        // to avoid leaving it stuck with no affordance to dismiss it.
        if browsing_mode == Mode::Strict {
            self.popover_open = false;
        }
    }
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
// UrlInput
// ---------------------------------------------------------------------------

/// Owns the text field value, its validation state, and the in-flight debounce
/// abort handle (L40: no keystroke reaches the provider until 200 ms passes).
pub struct UrlInput {
    pub text: String,
    pub validation: UrlValidation,
    /// Abort handle for the in-flight debounce task (L40).
    pub debounce_handle: Option<task::Handle>,
}

impl UrlInput {
    pub fn new() -> Self {
        Self {
            text: String::new(),
            validation: UrlValidation::Empty,
            debounce_handle: None,
        }
    }

    /// Called when the text field changes. Cancels the previous debounce task
    /// and spawns a new one. Returns the task to be returned from update().
    ///
    /// L40: no keystroke reaches the provider until the 200 ms sleep fires.
    pub fn on_changed(
        &mut self,
        new_text: String,
        provider: Arc<dyn SuggestionProvider>,
        partition_key: &str,
    ) -> Option<Task<AddressBarMsg>> {
        // Cancel previous debounce.
        if let Some(handle) = self.debounce_handle.take() {
            handle.abort();
        }

        self.text = new_text.clone();
        self.validation = UrlValidation::classify(&new_text);

        if new_text.is_empty() {
            return None;
        }

        let key = partition_key.to_string();
        let (debounce_task, handle) = Task::perform(
            async move {
                tokio::time::sleep(Duration::from_millis(200)).await;
                provider.suggest(&new_text, &key).await
            },
            |suggestions| AddressBarMsg::Suggestion(SuggestionEvent::Loaded(suggestions)),
        )
        .abortable();

        self.debounce_handle = Some(handle);
        Some(debounce_task)
    }

    pub fn clear(&mut self) {
        if let Some(h) = self.debounce_handle.take() {
            h.abort();
        }
        self.text.clear();
        self.validation = UrlValidation::Empty;
    }
}

impl Default for UrlInput {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SuggestionList
// ---------------------------------------------------------------------------

/// Dropdown suggestion list state (docs/design/modules/43.md §Suggestions).
///
/// Opens only when at least one item is loaded (empty Loaded -> closed).
/// Out-of-bounds Selected events are silently ignored to guard against
/// races between async provider responses and UI dismissal.
///
/// TODO Module 43 wiring: drive via SuggestionProvider debounce task from UrlInput
#[derive(Debug, Default)]
pub struct SuggestionList {
    pub items: Vec<Suggestion>,
    pub selected: Option<usize>,
    pub open: bool,
}

impl SuggestionList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, event: SuggestionEvent) {
        match event {
            SuggestionEvent::Loaded(items) => {
                self.open = !items.is_empty();
                self.items = items;
                self.selected = None;
            }
            SuggestionEvent::Selected(idx) => {
                if idx < self.items.len() {
                    self.selected = Some(idx);
                }
            }
            SuggestionEvent::Dismissed => {
                self.open = false;
                self.selected = None;
            }
        }
    }

    /// Returns the text of the currently selected suggestion, if any.
    pub fn selected_text(&self) -> Option<&str> {
        self.selected
            .and_then(|i| self.items.get(i))
            .map(|s| s.text.as_str())
    }
}

// ---------------------------------------------------------------------------
// AddressBar
// ---------------------------------------------------------------------------

/// Floating URL bar coordinator. Owns UrlInput, SuggestionList, and BadgeSlot.
///
/// Emits AddressBarEvent to the shell on navigation commit and mode change requests.
///
/// TODO Module 43 wiring: wire AddressBar into shell update loop (ChromeCommand dispatch)
pub struct AddressBar {
    pub bar_state: BarState,
    pub url_input: UrlInput,
    pub suggestions: SuggestionList,
    pub badge: BadgeSlot,
    pub mode: Mode,
    pub reduced_motion: bool,
    /// Opaque profile ID used as suggestion partition_key (L40).
    partition_key: String,
    provider: Arc<dyn SuggestionProvider>,
    /// Chip visibility state. See `ChipState` for transition rules.
    chip_state: ChipState,
    /// The last committed URL shown in Rest state. Empty until first navigation.
    pub current_url: String,
    /// True while the mouse is over the Convert-to-Strict chip (drives hover popup).
    convert_chip_hovered: bool,
    /// True while the cursor is inside the strict hover popup (keeps it visible).
    convert_popup_hovered: bool,
    /// True during the 150 ms grace period after ConvertChipExited fires but
    /// before we know whether the cursor is heading into the popup.
    strict_popup_grace: bool,
}

impl std::fmt::Debug for AddressBar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddressBar")
            .field("bar_state", &self.bar_state)
            .field("suggestions", &self.suggestions)
            .field("badge", &self.badge)
            .field("mode", &self.mode)
            .field("reduced_motion", &self.reduced_motion)
            .field("chip_state", &self.chip_state)
            .finish_non_exhaustive()
    }
}

impl AddressBar {
    pub fn new(provider: Arc<dyn SuggestionProvider>, mode: Mode, partition_key: String) -> Self {
        Self {
            bar_state: BarState::Rest,
            url_input: UrlInput::new(),
            suggestions: SuggestionList::new(),
            badge: BadgeSlot::new(mode),
            mode,
            reduced_motion: false,
            partition_key,
            provider,
            chip_state: ChipState::FreshTab,
            current_url: String::new(),
            convert_chip_hovered: false,
            convert_popup_hovered: false,
            strict_popup_grace: false,
        }
    }

    /// Stub constructor for builds without a real provider wired yet.
    pub fn new_stub(mode: Mode) -> Self {
        struct NoopProvider;
        impl SuggestionProvider for NoopProvider {
            fn suggest<'a>(
                &'a self,
                _query: &'a str,
                _partition_key: &'a str,
            ) -> Pin<Box<dyn Future<Output = Vec<Suggestion>> + Send + 'a>> {
                Box::pin(async { Vec::new() })
            }
        }
        let mut bar = Self::new(Arc::new(NoopProvider), mode, "default".to_string());
        // Demo: seed 12 blocked trackers so the badge is visible during development.
        // TODO Module 21 wiring: replace with real ChromeCommand::BlockOccurred events;
        // badge should only appear after a page navigation (NavigationCommitted). Remove
        // this seed block entirely when Phase 11 wiring lands.
        for i in 0..12_u32 {
            bar.badge.update(BadgeEvent::BlockIncrement {
                domain: format!("tracker{i}.io"),
            });
        }
        bar
    }

    /// True when the Convert-to-Strict chip should be rendered.
    /// Hidden in Strict (L41). Hidden once the user commits to Standard (Enter pressed).
    /// Shown briefly for externally-opened URLs, then auto-dismissed after 30 s.
    pub fn show_convert_chip(&self) -> bool {
        self.mode == Mode::Standard && self.chip_state != ChipState::Hidden
    }

    /// True when the current tab has never committed a navigation (no URL loaded).
    /// Used by the shell to decide whether converting to Strict can be done in-place.
    pub fn is_fresh_tab(&self) -> bool {
        self.chip_state == ChipState::FreshTab
    }

    /// Sync mode from shell (ChromeCommand::ModeChanged).
    pub fn sync_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.badge.sync_mode(mode);
        // Clear transient popup state so switching tabs never auto-opens
        // the convert chip popup on the newly active tab.
        self.convert_chip_hovered = false;
        self.convert_popup_hovered = false;
        self.strict_popup_grace = false;
    }

    /// Renders the floating URL bar as an Iced element.
    ///
    /// Rest state:  [nav stub] [reload stub] [fav] [lock] [domain] [path] [badge] [convert chip]
    /// Focused:     [nav stub] [reload stub] [text input                 ] [badge] [convert chip]
    ///
    /// Suggestion dropdown renders as a styled panel below when open (Focused only).
    /// Nav/reload/fav/lock are visual stubs; interaction wired in Phase 11 (Module 80).
    /// TODO Module 43 wiring: pass reduced_transparency from AppState
    pub fn view(&self, bar_width: f32) -> Element<'_, AddressBarMsg> {
        let is_strict = self.mode == Mode::Strict;

        let focused = self.bar_state == BarState::Focused;

        // ---------- color palette ----------
        let [ar, ag, ab, _] = design::palette::ACCENT;
        let [sr, sg, sb, _] = design::palette::STRICT;
        let [tr, tg, tb, _] = design::palette::TEXT_PRIMARY_DARK;
        let [mr, mg, mb, _] = design::palette::TEXT_MUTED_DARK;
        let [dr, dg, db, _] = design::palette::TEXT_DIM_DARK;
        let [gtr, gtg, gtb, gta] = design::palette::GLASS_TINT_DARK;

        // Mode-aware pill color: champagne (Standard) or terracotta (Strict). L41.
        let (pr, pg, pb) = if is_strict {
            (sr, sg, sb)
        } else {
            (ar, ag, ab)
        };
        let pill_color = iced::Color::from_rgb(pr, pg, pb);
        let text_primary = iced::Color::from_rgb(tr, tg, tb);
        let _text_dim = iced::Color::from_rgb(dr, dg, db); // available for future use

        let pill_border = iced::Border {
            color: iced::Color::TRANSPARENT,
            width: 0.0,
            radius: design::radius::PILL_PX.into(),
        };

        // ---------- nav stub (back / forward) ----------
        // Plain containers — no button widget — since interaction is Phase 11 (Module 80).
        // Using button here causes Iced's default box style to bleed through.
        let nav_h = design::layout::URL_BAR_CONTROL_HEIGHT_PX; // 26 px
                                                               // Exact mock values: rgba(255,250,240,0.05) bg, rgba(255,250,240,0.07) border.
        let ctrl_bg = iced::Color::from_rgba(1.0, 0.98, 0.94, 0.05);
        let ctrl_border_color = iced::Color::from_rgba(1.0, 0.98, 0.94, 0.07);
        let ctrl_border_radius: iced::border::Radius = design::radius::BUTTON_PX.into();
        // Mock icon color: #b0b4be
        let icon_color = iced::Color::from_rgba(0.690, 0.706, 0.745, 1.0);
        // Dim icon color: #4a4d56 (inactive nav direction)
        let icon_dim = iced::Color::from_rgba(0.290, 0.302, 0.337, 1.0);

        // Back and forward combined in one capsule chip: ‹ | ›
        // Each side is a button so hover brightens it independently.
        // Inside a chip → circular hover fill, no button border (chip owns the border).
        let nav_btn = |glyph: &'static str, color: iced::Color| {
            iced::widget::button(
                container(text(glyph).size(18.0).color(color))
                    .width(Length::Fixed(28.0))
                    .height(Length::Fixed(nav_h))
                    .center_x(Length::Fixed(28.0))
                    .center_y(Length::Fixed(nav_h)),
            )
            .width(Length::Fixed(28.0))
            .height(Length::Fixed(nav_h))
            .padding(0)
            .on_press(AddressBarMsg::Noop)
            .style(|_, status| {
                let hovered = matches!(
                    status,
                    iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed
                );
                iced::widget::button::Style {
                    background: Some(iced::Background::Color(if hovered {
                        iced::Color::from_rgba(1.0, 0.98, 0.94, 0.08)
                    } else {
                        iced::Color::TRANSPARENT
                    })),
                    border: iced::Border {
                        radius: 99.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            })
        };

        let nav_back = chrome_tip("Previous page", nav_btn("\u{2039}", icon_color).into());
        // Forward is dim when there is no forward history (stub — always dim for now).
        let nav_fwd = chrome_tip("Next page", nav_btn("\u{203A}", icon_dim).into());

        let nav_divider: Element<AddressBarMsg> = container(
            text("|")
                .size(12.0)
                .color(iced::Color::from_rgba(1.0, 0.98, 0.94, 0.20)),
        )
        .width(Length::Fixed(12.0))
        .height(Length::Fixed(nav_h))
        .center_x(Length::Fixed(12.0))
        .center_y(Length::Fixed(nav_h))
        .into();

        let nav_combined: Element<AddressBarMsg> =
            container(row![nav_back, nav_divider, nav_fwd].spacing(0.0))
                .style(move |_| iced::widget::container::Style {
                    background: Some(iced::Background::Color(ctrl_bg)),
                    border: iced::Border {
                        color: ctrl_border_color,
                        width: 1.0,
                        radius: ctrl_border_radius,
                    },
                    ..Default::default()
                })
                .height(Length::Fixed(nav_h))
                .into();

        // ---------- reload stub: ↺ counterclockwise arrow (U+21BA) ----------
        let reload: Element<AddressBarMsg> = iced::widget::button(
            container(text("\u{21BA}").size(17.0).color(icon_color))
                .width(Length::Fixed(26.0))
                .height(Length::Fixed(nav_h))
                .center_x(Length::Fixed(26.0))
                .center_y(Length::Fixed(nav_h)),
        )
        .width(Length::Fixed(26.0))
        .height(Length::Fixed(nav_h))
        .padding(0)
        .on_press(AddressBarMsg::Noop)
        .style(move |_, status| {
            let hovered = matches!(
                status,
                iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed
            );
            iced::widget::button::Style {
                background: Some(iced::Background::Color(if hovered {
                    iced::Color::from_rgba(1.0, 0.98, 0.94, 0.08)
                } else {
                    ctrl_bg
                })),
                border: iced::Border {
                    color: ctrl_border_color,
                    width: 1.0,
                    radius: ctrl_border_radius,
                },
                ..Default::default()
            }
        })
        .into();
        let reload = chrome_tip("Refresh", reload);

        // ---------- url body ----------
        // Show text input when: focused OR no URL yet (new tab — skip the extra click).
        let has_url = !Self::split_url(&self.current_url).0.is_empty();
        let show_input = focused || !has_url;

        let url_body: Element<AddressBarMsg> = if show_input {
            text_input("Search or enter address", &self.url_input.text)
                .on_input(|s| AddressBarMsg::UrlInput(UrlInputEvent::Changed(s)))
                .on_submit(AddressBarMsg::NavigatePressed)
                .size(design::type_scale::BODY_LG_PX)
                .style(move |_t, _s| iced::widget::text_input::Style {
                    background: iced::Background::Color(iced::Color::TRANSPARENT),
                    border: iced::Border {
                        color: iced::Color::TRANSPARENT,
                        width: 0.0,
                        radius: 0.0.into(),
                    },
                    icon: pill_color,
                    placeholder: iced::Color::from_rgb(mr, mg, mb),
                    value: text_primary,
                    selection: iced::Color::from_rgba(pr, pg, pb, 0.30),
                })
                .into()
        } else {
            let (domain, path) = Self::split_url(&self.current_url);

            // URL loaded: show lock (HTTPS only) + domain + path.
            // Favicon stub omitted until Module 56 (favicon cache) is wired.
            // TODO Module 43 wiring: add favicon from pb-ui::favicon::FaviconCache (Module 56)
            let is_https = self.current_url.starts_with("https://");

            let mut url_row = iced::widget::Row::new()
                .spacing(design::space::S2)
                .align_y(iced::alignment::Vertical::Center);

            // Lock: bullet placeholder for HTTPS. No icon for HTTP (interstitial
            // handles that case via ErrorInterstitial state).
            if is_https {
                url_row = url_row.push(text("\u{2022}").size(10.0).color(pill_color));
            }

            url_row = url_row
                .push(
                    text(domain)
                        .size(design::type_scale::BODY_LG_PX)
                        .color(text_primary),
                )
                .push(
                    text(path)
                        .size(design::type_scale::BODY_LG_PX)
                        .color(iced::Color::from_rgb(mr, mg, mb)),
                );

            button(url_row)
                .on_press(AddressBarMsg::FocusGained)
                .width(Length::Fill)
                .padding([0.0, design::space::S2])
                .style(move |_t, _s| iced::widget::button::Style {
                    background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
                    text_color: text_primary,
                    border: iced::Border::default(),
                    shadow: iced::Shadow::default(),
                    snap: false,
                })
                .into()
        };

        // ---------- badge slot ----------
        let badge_widget: Element<AddressBarMsg> = match self.badge.mode {
            BadgeMode::Hidden => container(text("")).width(Length::Shrink).into(),
            BadgeMode::Blocked(_) => chrome_tip("Ad & tracker blocker", {
                let label = self.badge.mode.label().unwrap_or_default();
                button(
                    text(label)
                        .size(design::type_scale::LABEL_UPPER_PX)
                        .color(pill_color),
                )
                .on_press(AddressBarMsg::Badge(BadgeEvent::PopoverToggled))
                .padding([design::space::S1, design::space::S5])
                .style(move |_t, status| {
                    let a = if matches!(
                        status,
                        iced::widget::button::Status::Hovered
                            | iced::widget::button::Status::Pressed
                    ) {
                        0.28_f32
                    } else {
                        0.16_f32
                    };
                    iced::widget::button::Style {
                        background: Some(iced::Background::Color(iced::Color::from_rgba(
                            ar, ag, ab, a,
                        ))),
                        text_color: pill_color,
                        border: pill_border,
                        shadow: iced::Shadow::default(),
                        snap: false,
                    }
                })
                .into()
            }),
            BadgeMode::Strict => {
                // L41: non-interactive terracotta "Strict" pill. Non-customizable.
                // Filled shield signals the tab IS strict (contrast with outlined chip).
                let strict_shield_handle = iced::widget::svg::Handle::from_memory(
                    include_bytes!("../assets/shield.svg").as_ref(),
                );
                let strict_shield: Element<AddressBarMsg> = iced::widget::svg(strict_shield_handle)
                    .width(Length::Fixed(11.0))
                    .height(Length::Fixed(11.0))
                    .style(move |_t, _s| iced::widget::svg::Style {
                        color: Some(iced::Color::from_rgb(sr, sg, sb)),
                    })
                    .into();
                container(
                    row![
                        strict_shield,
                        text("Strict")
                            .size(design::type_scale::LABEL_UPPER_PX)
                            .color(iced::Color::from_rgb(sr, sg, sb)),
                    ]
                    .spacing(design::space::S2)
                    .align_y(iced::alignment::Vertical::Center),
                )
                .padding([design::space::S1, design::space::S5])
                .style(move |_t| iced::widget::container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        sr, sg, sb, 0.16,
                    ))),
                    border: iced::Border {
                        color: iced::Color::from_rgba(sr, sg, sb, 0.4),
                        width: 1.0,
                        radius: design::radius::PILL_PX.into(),
                    },
                    text_color: None,
                    shadow: iced::Shadow::default(),
                    snap: false,
                })
                .into()
            }
        };

        // ---------- convert chip (Standard only). L41: absent in Strict ----------
        // The chip sits in the inner row. The popup is built separately and
        // attached BELOW the full bar element so it is never clipped by the
        // 36 px glass capsule.
        let chip_hovered = self.convert_chip_hovered;
        let convert_chip: Option<Element<AddressBarMsg>> = if self.show_convert_chip() {
            let chip_bg_a = if chip_hovered { 0.32_f32 } else { 0.18_f32 };
            let chip_border_a = if chip_hovered { 0.60_f32 } else { 0.40_f32 };
            let chip_text = iced::Color::from_rgb(0.957, 0.729, 0.627);

            let dismiss = button(
                text("\u{00D7}")
                    .size(11.0)
                    .color(iced::Color::from_rgba(0.54, 0.42, 0.35, 1.0)),
            )
            .on_press(AddressBarMsg::DismissConvertChip)
            .padding([0.0, design::space::S1])
            .style(move |_t, _s| iced::widget::button::Style {
                background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
                text_color: iced::Color::from_rgba(0.54, 0.42, 0.35, 1.0),
                border: iced::Border::default(),
                shadow: iced::Shadow::default(),
                snap: false,
            });

            // Outlined shield on the chip — signals "not yet Strict, this converts it".
            let shield_handle = iced::widget::svg::Handle::from_memory(
                include_bytes!("../assets/shield-outline.svg").as_ref(),
            );
            let shield_icon: Element<AddressBarMsg> = iced::widget::svg(shield_handle)
                .width(Length::Fixed(11.0))
                .height(Length::Fixed(11.0))
                .style(move |_t, _s| iced::widget::svg::Style {
                    color: Some(chip_text),
                })
                .into();

            let chip_btn: Element<AddressBarMsg> = button(
                row![
                    shield_icon,
                    text("Make it Strict")
                        .size(design::type_scale::LABEL_UPPER_PX)
                        .color(chip_text),
                    dismiss
                ]
                .align_y(iced::alignment::Vertical::Center)
                .spacing(design::space::S3),
            )
            .on_press(AddressBarMsg::ConvertToStrictClicked)
            .padding([design::space::S1, design::space::S5])
            .style(move |_t, _s| iced::widget::button::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    sr, sg, sb, chip_bg_a,
                ))),
                text_color: chip_text,
                border: iced::Border {
                    color: iced::Color::from_rgba(sr, sg, sb, chip_border_a),
                    width: 1.0,
                    radius: design::radius::PILL_PX.into(),
                },
                shadow: iced::Shadow::default(),
                snap: false,
            })
            .into();

            Some(
                iced::widget::mouse_area(chip_btn)
                    .on_enter(AddressBarMsg::ConvertChipEntered)
                    .on_exit(AddressBarMsg::ConvertChipExited)
                    .into(),
            )
        } else {
            None
        };

        // Popup built separately — rendered below bar_element, not inside it.
        // strict_popup is now rendered as a floating overlay by the shell
        // (shell.rs view() → view_strict_popup). Removed from the column here
        // so it cannot push the tab bar or other content downward.

        // ---------- badge popover — tracker breakdown (blocked-counter.md) ----------
        // Renders below bar when badge.popover_open is true.
        // TODO Module 43 wiring: close on navigation (BadgeEvent::Reset already fires PopoverClosed)
        let badge_popover: Option<Element<AddressBarMsg>> =
            if self.badge.popover_open && !self.badge.rows.is_empty() {
                let total = self.badge.block_count;
                let overflow = self.badge.rows.len().saturating_sub(10);

                let domain_rows: Vec<Element<AddressBarMsg>> = self
                    .badge
                    .rows
                    .iter()
                    .take(10)
                    .map(|row| {
                        let domain = row.domain.clone();
                        let count = row.count;
                        container(
                            iced::widget::row![
                                text(domain)
                                    .size(design::type_scale::BODY_SM_PX)
                                    .color(iced::Color::from_rgb(0.847, 0.855, 0.878))
                                    .width(Length::Fill),
                                container(
                                    text(count.to_string())
                                        .size(design::type_scale::LABEL_UPPER_PX)
                                        .color(pill_color),
                                )
                                .padding([1.0, design::space::S3])
                                .style(move |_t| {
                                    iced::widget::container::Style {
                                        background: Some(iced::Background::Color(
                                            iced::Color::from_rgba(pr, pg, pb, 0.16),
                                        )),
                                        border: iced::Border {
                                            color: iced::Color::from_rgba(pr, pg, pb, 0.30),
                                            width: 1.0,
                                            radius: design::radius::PILL_PX.into(),
                                        },
                                        text_color: None,
                                        shadow: iced::Shadow::default(),
                                        snap: false,
                                    }
                                }),
                            ]
                            .spacing(design::space::S3)
                            .align_y(iced::alignment::Vertical::Center),
                        )
                        .padding([design::space::S2, design::space::S5])
                        .into()
                    })
                    .collect();

                let header: Element<AddressBarMsg> = container(
                    iced::widget::row![
                        text(format!("{total} blocked"))
                            .size(design::type_scale::BODY_LG_PX)
                            .color(pill_color)
                            .width(Length::Fill),
                        button(
                            text("\u{00D7}")
                                .size(14.0)
                                .color(iced::Color::from_rgb(mr, mg, mb)),
                        )
                        .on_press(AddressBarMsg::Badge(BadgeEvent::PopoverClosed))
                        .padding([0.0, design::space::S1])
                        .style(move |_t, _s| iced::widget::button::Style {
                            background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
                            text_color: iced::Color::from_rgb(mr, mg, mb),
                            border: iced::Border::default(),
                            shadow: iced::Shadow::default(),
                            snap: false,
                        }),
                    ]
                    .align_y(iced::alignment::Vertical::Center),
                )
                .padding(iced::Padding {
                    top: design::space::S4,
                    right: design::space::S4,
                    bottom: design::space::S3,
                    left: design::space::S5,
                })
                .into();

                let sep1: Element<AddressBarMsg> = container(text(""))
                    .width(Length::Fill)
                    .height(Length::Fixed(1.0))
                    .style(move |_t| iced::widget::container::Style {
                        background: Some(iced::Background::Color(iced::Color::from_rgba(
                            1.0, 0.98, 0.94, 0.07,
                        ))),
                        border: iced::Border::default(),
                        text_color: None,
                        shadow: iced::Shadow::default(),
                        snap: false,
                    })
                    .into();

                let sep2: Element<AddressBarMsg> = container(text(""))
                    .width(Length::Fill)
                    .height(Length::Fixed(1.0))
                    .style(move |_t| iced::widget::container::Style {
                        background: Some(iced::Background::Color(iced::Color::from_rgba(
                            1.0, 0.98, 0.94, 0.07,
                        ))),
                        border: iced::Border::default(),
                        text_color: None,
                        shadow: iced::Shadow::default(),
                        snap: false,
                    })
                    .into();

                let mut col = column![header, sep1].spacing(0.0);
                col = col.push(column(domain_rows).spacing(0.0));
                if overflow > 0 {
                    col = col.push(
                        container(
                            text(format!("+ {overflow} more"))
                                .size(design::type_scale::BODY_SM_PX)
                                .color(iced::Color::from_rgb(mr, mg, mb)),
                        )
                        .padding([design::space::S2, design::space::S5]),
                    );
                }
                col = col.push(sep2);
                col = col.push(
                    button(
                        text("Open Network Viewer \u{2192}")
                            .size(design::type_scale::BODY_SM_PX)
                            .color(pill_color),
                    )
                    .on_press(AddressBarMsg::NetworkViewerRequested)
                    .width(Length::Fill)
                    .padding(iced::Padding {
                        top: design::space::S3,
                        right: design::space::S4,
                        bottom: design::space::S3,
                        left: design::space::S5,
                    })
                    .style(move |_t, status| {
                        let bg_a = if matches!(
                            status,
                            iced::widget::button::Status::Hovered
                                | iced::widget::button::Status::Pressed
                        ) {
                            0.08_f32
                        } else {
                            0.0_f32
                        };
                        iced::widget::button::Style {
                            background: Some(iced::Background::Color(iced::Color::from_rgba(
                                pr, pg, pb, bg_a,
                            ))),
                            text_color: pill_color,
                            border: iced::Border::default(),
                            shadow: iced::Shadow::default(),
                            snap: false,
                        }
                    }),
                );

                let popup = container(col).width(Length::Fixed(280.0)).style(move |_t| {
                    iced::widget::container::Style {
                        background: Some(iced::Background::Color(iced::Color::from_rgba(
                            0.055, 0.071, 0.118, 0.96,
                        ))),
                        border: iced::Border {
                            color: iced::Color::from_rgba(ar, ag, ab, 0.25),
                            width: 1.5,
                            radius: design::radius::PANEL_PX.into(),
                        },
                        text_color: None,
                        shadow: iced::Shadow {
                            color: iced::Color::from_rgba(0.0, 0.0, 0.0, 0.50),
                            offset: iced::Vector::new(0.0, 16.0),
                            blur_radius: 40.0,
                        },
                        snap: false,
                    }
                });

                Some(
                    container(popup)
                        .width(Length::Fixed(bar_width))
                        .align_x(iced::alignment::Horizontal::Right)
                        .into(),
                )
            } else {
                None
            };

        // ---------- assemble inner row ----------
        let mut inner = row![nav_combined, reload, url_body, badge_widget]
            .spacing(design::space::S2)
            .align_y(iced::alignment::Vertical::Center);
        if let Some(chip) = convert_chip {
            inner = inner.push(chip);
        }

        // ---------- glass capsule + border overlay + shadow ----------
        // Border is a Stack overlay so it renders ON TOP of the GlassPanel canvas,
        // not underneath it (which would make it invisible).
        let glass = GlassPanel {
            tint_rgba: design::palette::GLASS_TINT_DARK,
            blur_sigma_px: design::glass::URL_BAR_BLUR_SIGMA,
            saturate: design::glass::URL_BAR_SATURATE,
            corner_radius_px: design::radius::CAPSULE_PX,
            width: Length::Fixed(bar_width),
            height: Length::Fixed(design::layout::TOP_BAR_HEIGHT_PX),
            reduced_transparency: false,
        };

        // Inset border ring rendered as the topmost Stack layer.
        // Mock spec: 1px rgba(255,250,240,0.08). Using 0.14 for wgpu gamma.
        let border_ring: Element<AddressBarMsg> = container(text(""))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_t| iced::widget::container::Style {
                background: None,
                border: iced::Border {
                    color: iced::Color::from_rgba(1.0, 0.98, 0.94, 0.14),
                    width: 1.0,
                    radius: design::radius::CAPSULE_PX.into(),
                },
                text_color: None,
                shadow: iced::Shadow::default(),
                snap: false,
            })
            .into();

        let bar_element: Element<AddressBarMsg> = container(
            iced::widget::Stack::new()
                .push(glass.view())
                .push(
                    container(inner)
                        .width(Length::Fill)
                        .center_y(Length::Fill)
                        .padding(iced::Padding {
                            top: 0.0,
                            right: design::space::S4,
                            bottom: 0.0,
                            left: design::space::S4,
                        }),
                )
                .push(border_ring),
        )
        .width(Length::Fixed(bar_width))
        .height(Length::Fixed(design::layout::TOP_BAR_HEIGHT_PX))
        .style(move |_t| iced::widget::container::Style {
            // Must be Some (not None) — Iced skips the quad when background is None,
            // which drops the shadow on re-renders triggered by hover events.
            // TRANSPARENT gives Iced a real quad to attach the shadow to.
            background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
            // Width 0 so it's invisible, but radius must match CAPSULE_PX so the
            // shadow renderer follows the rounded shape instead of drawing a rectangle.
            border: iced::Border {
                color: iced::Color::TRANSPARENT,
                width: 0.0,
                radius: design::radius::CAPSULE_PX.into(),
            },
            text_color: None,
            shadow: iced::Shadow {
                color: iced::Color::from_rgba(0.0, 0.0, 0.0, 0.35),
                offset: iced::Vector::new(0.0, 12.0),
                blur_radius: 30.0,
            },
            snap: false,
        })
        .into();

        // ---------- suggestion dropdown + strict popup ----------
        let base: Element<AddressBarMsg> =
            if self.suggestions.open && !self.suggestions.items.is_empty() {
                let rows: Vec<Element<AddressBarMsg>> = self
                    .suggestions
                    .items
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        let label = s.text.clone();
                        button(
                            text(label)
                                .size(design::type_scale::BODY_LG_PX)
                                .color(text_primary),
                        )
                        .on_press(AddressBarMsg::Suggestion(SuggestionEvent::Selected(i)))
                        .width(Length::Fill)
                        .padding([design::space::S3, design::space::S4])
                        .style(move |_t, status| {
                            let a = if matches!(
                                status,
                                iced::widget::button::Status::Hovered
                                    | iced::widget::button::Status::Pressed
                            ) {
                                0.12_f32
                            } else {
                                0.0_f32
                            };
                            iced::widget::button::Style {
                                background: Some(iced::Background::Color(iced::Color::from_rgba(
                                    ar, ag, ab, a,
                                ))),
                                text_color: text_primary,
                                border: iced::Border {
                                    color: iced::Color::TRANSPARENT,
                                    width: 0.0,
                                    radius: design::radius::INPUT_PX.into(),
                                },
                                shadow: iced::Shadow::default(),
                                snap: false,
                            }
                        })
                        .into()
                    })
                    .collect();

                let dropdown = container(column(rows))
                    .width(Length::Fixed(bar_width))
                    .padding(design::space::S2)
                    .style(move |_t| iced::widget::container::Style {
                        background: Some(iced::Background::Color(iced::Color::from_rgba(
                            gtr,
                            gtg,
                            gtb,
                            (gta + 0.2).min(1.0),
                        ))),
                        border: iced::Border {
                            color: iced::Color::from_rgba(ar, ag, ab, 0.12),
                            width: 1.0,
                            radius: design::radius::PANEL_PX.into(),
                        },
                        text_color: None,
                        shadow: iced::Shadow::default(),
                        snap: false,
                    });

                column![bar_element, dropdown]
                    .spacing(design::space::S1)
                    .into()
            } else {
                bar_element
            };

        // badge_popover is placed as a floating window-level overlay by the
        // shell (shell.rs → view_badge_popover). Drop it here so it cannot
        // push the tab bar or any other content downward.
        let _ = badge_popover;
        base
    }

    /// Returns the "Make it Strict" hover popup as a floating element, or `None`.
    ///
    /// The shell places this in the window-level Stack so it overlays content
    /// without affecting the layout of the address bar or anything below it.
    /// `bar_width` must match the value passed to `view()`.
    pub fn view_strict_popup(&self, bar_width: f32) -> Option<Element<'_, AddressBarMsg>> {
        // Keep popup visible while: hovering chip, cursor is inside popup, or
        // the 150 ms grace period after chip-exit hasn't elapsed yet (lets slow
        // users move cursor from chip to popup without it vanishing).
        if !self.show_convert_chip()
            || (!self.convert_chip_hovered
                && !self.convert_popup_hovered
                && !self.strict_popup_grace)
        {
            return None;
        }
        let [sr, sg, sb, _] = design::palette::STRICT;

        let popup = container(
            column![
                column![
                    text("Strict mode (higher privacy)")
                        .size(design::type_scale::BODY_LG_PX)
                        .color(iced::Color::from_rgb(0.957, 0.729, 0.627)),
                    text("recommended for banking, sensitive sites")
                        .size(design::type_scale::BODY_SM_PX)
                        .color(iced::Color::from_rgb(0.784, 0.659, 0.596)),
                ]
                .spacing(design::space::S1),
                text("Opens this page in a new tab with extra privacy protections. Original tab stays unchanged.")
                    .size(design::type_scale::BODY_SM_PX)
                    .color(iced::Color::from_rgb(0.847, 0.855, 0.878)),
                column![
                    row![
                        text("\u{2713}").size(12.0).color(iced::Color::from_rgb(0.353, 0.541, 0.431)),
                        text("Separate cookies & storage from this site").size(design::type_scale::BODY_SM_PX).color(iced::Color::from_rgb(0.847, 0.855, 0.878)),
                    ].spacing(design::space::S3).align_y(iced::alignment::Vertical::Center),
                    row![
                        text("\u{2713}").size(12.0).color(iced::Color::from_rgb(0.353, 0.541, 0.431)),
                        text("No browsing history saved").size(design::type_scale::BODY_SM_PX).color(iced::Color::from_rgb(0.847, 0.855, 0.878)),
                    ].spacing(design::space::S3).align_y(iced::alignment::Vertical::Center),
                    row![
                        text("\u{2713}").size(12.0).color(iced::Color::from_rgb(0.353, 0.541, 0.431)),
                        text("Maximum fingerprint protection").size(design::type_scale::BODY_SM_PX).color(iced::Color::from_rgb(0.847, 0.855, 0.878)),
                    ].spacing(design::space::S3).align_y(iced::alignment::Vertical::Center),
                ]
                .spacing(design::space::S2),
                container(
                    row![
                        text("\u{2139}").size(11.0).color(iced::Color::from_rgb(0.910, 0.729, 0.627)),
                        text("Close the tab to exit Strict mode")
                            .size(design::type_scale::BODY_SM_PX)
                            .color(iced::Color::from_rgb(0.910, 0.729, 0.627)),
                    ]
                    .spacing(design::space::S2)
                    .align_y(iced::alignment::Vertical::Center),
                )
                .padding([design::space::S3, design::space::S4])
                .style(move |_t| iced::widget::container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(sr, sg, sb, 0.15))),
                    border: iced::Border { color: iced::Color::TRANSPARENT, width: 0.0, radius: design::radius::BUTTON_PX.into() },
                    text_color: None,
                    shadow: iced::Shadow::default(),
                    snap: false,
                }),
                iced::widget::button(
                    iced::widget::container(
                        text("Make it Strict")
                            .size(design::type_scale::BODY_LG_PX)
                            .color(iced::Color::from_rgb(0.957, 0.729, 0.627)),
                    )
                    .width(Length::Fill)
                    .center_x(Length::Fill)
                    .padding([design::space::S3, design::space::S4]),
                )
                .on_press(AddressBarMsg::ConvertToStrictClicked)
                .width(Length::Fill)
                .padding(0)
                .style(move |_t, status| {
                    let a = if matches!(status, iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed) { 0.28_f32 } else { 0.18_f32 };
                    iced::widget::button::Style {
                        background: Some(iced::Background::Color(iced::Color::from_rgba(sr, sg, sb, a))),
                        border: iced::Border { color: iced::Color::from_rgba(sr, sg, sb, 0.50), width: 1.0, radius: design::radius::BUTTON_PX.into() },
                        text_color: iced::Color::from_rgb(0.957, 0.729, 0.627),
                        shadow: iced::Shadow::default(),
                        snap: false,
                    }
                }),
            ]
            .spacing(design::space::S4),
        )
        .width(Length::Fixed(300.0))
        .padding([design::space::S6, design::space::S6])
        .style(move |_t| iced::widget::container::Style {
            background: Some(iced::Background::Color(iced::Color::from_rgba(0.055, 0.071, 0.118, 0.96))),
            border: iced::Border {
                color: iced::Color::from_rgba(sr, sg, sb, 0.40),
                width: 1.5,
                radius: design::radius::PANEL_PX.into(),
            },
            text_color: None,
            shadow: iced::Shadow {
                color: iced::Color::from_rgba(0.0, 0.0, 0.0, 0.50),
                offset: iced::Vector::new(0.0, 24.0),
                blur_radius: 60.0,
            },
            snap: false,
        });

        // Wrap in mouse_area so moving into the popup keeps it visible.
        // ConvertPopupEntered/Exited update convert_popup_hovered in state.
        Some(
            iced::widget::mouse_area(
                container(popup)
                    .width(Length::Fixed(bar_width))
                    .align_x(iced::alignment::Horizontal::Right),
            )
            .on_enter(AddressBarMsg::ConvertPopupEntered)
            .on_exit(AddressBarMsg::ConvertPopupExited)
            .into(),
        )
    }

    /// Returns the tracker-count badge popover as a floating element, or `None`.
    ///
    /// The shell places this in the window-level Stack so it overlays content
    /// without pushing the tab bar or other layout down.
    pub fn view_badge_popover(&self, bar_width: f32) -> Option<Element<'_, AddressBarMsg>> {
        if !self.badge.popover_open || self.badge.rows.is_empty() {
            return None;
        }
        let [ar, ag, ab, _] = design::palette::ACCENT;
        let [sr, sg, sb, _] = design::palette::STRICT;
        let [mr, mg, mb, _] = design::palette::TEXT_MUTED_DARK;
        let is_strict = self.mode == Mode::Strict;
        let (pr, pg, pb) = if is_strict {
            (sr, sg, sb)
        } else {
            (ar, ag, ab)
        };
        let pill_color = iced::Color::from_rgb(pr, pg, pb);

        let total = self.badge.block_count;
        let overflow = self.badge.rows.len().saturating_sub(10);

        let domain_rows: Vec<Element<AddressBarMsg>> = self
            .badge
            .rows
            .iter()
            .take(10)
            .map(|row| {
                let domain = row.domain.clone();
                let count = row.count;
                container(
                    iced::widget::row![
                        text(domain)
                            .size(design::type_scale::BODY_SM_PX)
                            .color(iced::Color::from_rgb(0.847, 0.855, 0.878))
                            .width(Length::Fill),
                        container(
                            text(count.to_string())
                                .size(design::type_scale::LABEL_UPPER_PX)
                                .color(pill_color),
                        )
                        .padding([1.0, design::space::S3])
                        .style(move |_t| iced::widget::container::Style {
                            background: Some(iced::Background::Color(iced::Color::from_rgba(
                                pr, pg, pb, 0.16
                            ),)),
                            border: iced::Border {
                                color: iced::Color::from_rgba(pr, pg, pb, 0.30),
                                width: 1.0,
                                radius: design::radius::PILL_PX.into(),
                            },
                            text_color: None,
                            shadow: iced::Shadow::default(),
                            snap: false,
                        }),
                    ]
                    .spacing(design::space::S3)
                    .align_y(iced::alignment::Vertical::Center),
                )
                .padding([design::space::S2, design::space::S5])
                .into()
            })
            .collect();

        let header: Element<AddressBarMsg> = container(
            iced::widget::row![
                text(format!("{total} blocked"))
                    .size(design::type_scale::BODY_LG_PX)
                    .color(pill_color)
                    .width(Length::Fill),
                button(
                    text("\u{00D7}")
                        .size(14.0)
                        .color(iced::Color::from_rgb(mr, mg, mb)),
                )
                .on_press(AddressBarMsg::Badge(BadgeEvent::PopoverClosed))
                .padding([0.0, design::space::S1])
                .style(move |_t, _s| iced::widget::button::Style {
                    background: Some(iced::Background::Color(iced::Color::TRANSPARENT)),
                    text_color: iced::Color::from_rgb(mr, mg, mb),
                    border: iced::Border::default(),
                    shadow: iced::Shadow::default(),
                    snap: false,
                }),
            ]
            .align_y(iced::alignment::Vertical::Center),
        )
        .padding(iced::Padding {
            top: design::space::S4,
            right: design::space::S4,
            bottom: design::space::S3,
            left: design::space::S5,
        })
        .into();

        let sep = |_: ()| -> Element<AddressBarMsg> {
            container(text(""))
                .width(Length::Fill)
                .height(Length::Fixed(1.0))
                .style(|_t| iced::widget::container::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        1.0, 0.98, 0.94, 0.07,
                    ))),
                    ..Default::default()
                })
                .into()
        };

        let mut col = column![header, sep(())].spacing(0.0);
        col = col.push(column(domain_rows).spacing(0.0));
        if overflow > 0 {
            col = col.push(
                container(
                    text(format!("+ {overflow} more"))
                        .size(design::type_scale::BODY_SM_PX)
                        .color(iced::Color::from_rgb(mr, mg, mb)),
                )
                .padding([design::space::S2, design::space::S5]),
            );
        }
        col = col.push(sep(()));
        col = col.push(
            button(
                text("Open Network Viewer \u{2192}")
                    .size(design::type_scale::BODY_SM_PX)
                    .color(pill_color),
            )
            .on_press(AddressBarMsg::NetworkViewerRequested)
            .width(Length::Fill)
            .padding(iced::Padding {
                top: design::space::S3,
                right: design::space::S4,
                bottom: design::space::S3,
                left: design::space::S5,
            })
            .style(move |_t, status| {
                let bg_a = if matches!(
                    status,
                    iced::widget::button::Status::Hovered | iced::widget::button::Status::Pressed
                ) {
                    0.08_f32
                } else {
                    0.0_f32
                };
                iced::widget::button::Style {
                    background: Some(iced::Background::Color(iced::Color::from_rgba(
                        pr, pg, pb, bg_a,
                    ))),
                    text_color: pill_color,
                    border: iced::Border::default(),
                    shadow: iced::Shadow::default(),
                    snap: false,
                }
            }),
        );

        let popup = container(col).width(Length::Fixed(280.0)).style(move |_t| {
            iced::widget::container::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgba(
                    0.055, 0.071, 0.118, 0.96,
                ))),
                border: iced::Border {
                    color: iced::Color::from_rgba(ar, ag, ab, 0.25),
                    width: 1.5,
                    radius: design::radius::PANEL_PX.into(),
                },
                text_color: None,
                shadow: iced::Shadow {
                    color: iced::Color::from_rgba(0.0, 0.0, 0.0, 0.50),
                    offset: iced::Vector::new(0.0, 16.0),
                    blur_radius: 40.0,
                },
                snap: false,
            }
        });

        Some(
            container(popup)
                .width(Length::Fixed(bar_width))
                .align_x(iced::alignment::Horizontal::Right)
                .into(),
        )
    }

    /// Split a URL into (domain, path) for Rest-state display.
    fn split_url(url: &str) -> (&str, &str) {
        let stripped = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        match stripped.find('/') {
            Some(pos) => (&stripped[..pos], &stripped[pos..]),
            None => (stripped, ""),
        }
    }

    /// Main update. Returns the shell-visible event (if any) and a Task.
    pub fn update(&mut self, msg: AddressBarMsg) -> (Option<AddressBarEvent>, Task<AddressBarMsg>) {
        match msg {
            AddressBarMsg::FocusGained => {
                self.bar_state = BarState::Focused;
                (None, Task::none())
            }
            AddressBarMsg::FocusLost => {
                if self.bar_state == BarState::Focused {
                    self.bar_state = BarState::Rest;
                    self.suggestions.update(SuggestionEvent::Dismissed);
                }
                (None, Task::none())
            }
            AddressBarMsg::EscPressed => {
                if self.bar_state == BarState::Focused {
                    self.bar_state = BarState::Rest;
                    self.suggestions.update(SuggestionEvent::Dismissed);
                }
                (None, Task::none())
            }
            AddressBarMsg::ScrolledDown => {
                if self.bar_state == BarState::Rest {
                    self.bar_state = BarState::Pill;
                }
                (None, Task::none())
            }
            AddressBarMsg::ScrolledUp => {
                if self.bar_state == BarState::Pill {
                    self.bar_state = BarState::Rest;
                }
                (None, Task::none())
            }
            AddressBarMsg::NavigatePressed => {
                if self.bar_state != BarState::Focused {
                    return (None, Task::none());
                }
                let url = match self.url_input.validation {
                    UrlValidation::Valid => self.url_input.text.clone(),
                    _ => format!("https://duckduckgo.com/?q={}", self.url_input.text),
                };
                self.current_url = url.clone();
                // User committed to Standard by pressing Enter — chip gone permanently.
                self.chip_state = ChipState::Hidden;
                self.bar_state = BarState::Navigating;
                // Badge reset is NOT done here. The network layer (Module 21 via shell)
                // fires BadgeEvent::Reset when the new page begins loading and sends
                // BlockIncrement events as trackers are blocked. Resetting here would
                // clear the count before the page even starts, leaving the badge empty
                // with no replacement in stub builds.
                self.url_input.clear();
                self.suggestions.update(SuggestionEvent::Dismissed);
                (
                    Some(AddressBarEvent::NavigationCommitted {
                        url,
                        mode: self.mode,
                    }),
                    Task::none(),
                )
            }
            AddressBarMsg::InterstitialDismissed => {
                self.bar_state = BarState::Rest;
                (None, Task::none())
            }
            AddressBarMsg::ConvertToStrictClicked => {
                if self.mode == Mode::Standard {
                    (Some(AddressBarEvent::ConvertToStrictClicked), Task::none())
                } else {
                    (None, Task::none())
                }
            }
            AddressBarMsg::UrlInput(UrlInputEvent::Changed(text)) => {
                // Auto-focus when the user types into the input while bar is in Rest state.
                // This happens on fresh tabs where the input is visible without an explicit
                // click (show_input = !has_url), so NavigatePressed would otherwise be
                // rejected by the Focused guard.
                if self.bar_state == BarState::Rest {
                    self.bar_state = BarState::Focused;
                }
                let task = self
                    .url_input
                    .on_changed(text, Arc::clone(&self.provider), &self.partition_key)
                    .unwrap_or_else(Task::none);
                if self.url_input.text.is_empty() {
                    self.suggestions.update(SuggestionEvent::Dismissed);
                }
                (None, task)
            }
            AddressBarMsg::Suggestion(ev) => {
                self.suggestions.update(ev);
                (None, Task::none())
            }
            AddressBarMsg::Badge(ev) => {
                self.badge.update(ev);
                (None, Task::none())
            }
            AddressBarMsg::ModeChanged(mode) => {
                self.sync_mode(mode);
                (None, Task::none())
            }
            AddressBarMsg::ReducedMotionChanged(v) => {
                self.reduced_motion = v;
                (None, Task::none())
            }
            AddressBarMsg::DismissConvertChip => {
                self.chip_state = ChipState::Hidden;
                self.convert_chip_hovered = false;
                (None, Task::none())
            }
            AddressBarMsg::NavigatedExternally(url) => {
                // URL pushed from outside (app link, protocol handler, link-click new-tab).
                // Show chip for 30 s then auto-dismiss (architecture mode-indicator.md).
                // TODO Module 52 wiring: skip to Hidden if user set link-click-opens-as=Standard
                self.current_url = url;
                self.chip_state = ChipState::ExternalUrl;
                self.convert_chip_hovered = false;
                let task = Task::perform(
                    async {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                    },
                    |()| AddressBarMsg::AutoDismissConvertChip,
                );
                (None, task)
            }
            AddressBarMsg::AutoDismissConvertChip => {
                if self.chip_state == ChipState::ExternalUrl {
                    self.chip_state = ChipState::Hidden;
                    self.convert_chip_hovered = false;
                }
                (None, Task::none())
            }
            AddressBarMsg::ConvertChipEntered => {
                self.convert_chip_hovered = true;
                (None, Task::none())
            }
            AddressBarMsg::ConvertChipExited => {
                self.convert_chip_hovered = false;
                self.strict_popup_grace = true;
                // Start 150 ms grace period. If cursor enters popup before it
                // fires, ConvertPopupEntered clears the pending flag. If not,
                // StrictPopupGracePeriodEnd hides the popup.
                let task = iced::Task::perform(
                    async {
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    },
                    |_| AddressBarMsg::StrictPopupGracePeriodEnd,
                );
                (None, task)
            }
            AddressBarMsg::ConvertPopupEntered => {
                self.convert_popup_hovered = true;
                self.strict_popup_grace = false; // grace period no longer needed
                (None, Task::none())
            }
            AddressBarMsg::ConvertPopupExited => {
                self.convert_popup_hovered = false;
                (None, Task::none())
            }
            AddressBarMsg::StrictPopupGracePeriodEnd => {
                self.strict_popup_grace = false;
                // popup hides automatically if convert_chip_hovered and
                // convert_popup_hovered are both false (view_strict_popup condition)
                (None, Task::none())
            }
            AddressBarMsg::NetworkViewerRequested => {
                self.badge.update(BadgeEvent::PopoverClosed);
                (Some(AddressBarEvent::NetworkViewerRequested), Task::none())
            }
            AddressBarMsg::Noop => (None, Task::none()),
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
    /// User dismissed the Convert-to-Strict chip for this tab. L41: one-time per tab.
    DismissConvertChip,
    /// Mouse entered the Convert-to-Strict chip — show the hover popup.
    ConvertChipEntered,
    /// Mouse left the Convert-to-Strict chip — starts a 150 ms grace timer.
    ConvertChipExited,
    /// Mouse entered the strict hover popup — keeps popup visible.
    ConvertPopupEntered,
    /// Mouse left the strict hover popup — hide the popup.
    ConvertPopupExited,
    /// 150 ms grace timer fired after chip exit; hides popup if cursor is gone.
    StrictPopupGracePeriodEnd,
    ModeChanged(Mode),
    ReducedMotionChanged(bool),
    /// URL pushed externally — show chip with 30 s auto-dismiss.
    NavigatedExternally(String),
    /// 30 s auto-dismiss timer fired for an externally-opened URL.
    AutoDismissConvertChip,
    /// User clicked "Open Network Viewer" in the badge popover.
    NetworkViewerRequested,
    /// Stub for nav/reload buttons not yet wired to TabBroker (Module 80).
    Noop,
}

fn chrome_tip<'a>(
    label: &'static str,
    el: iced::Element<'a, AddressBarMsg>,
) -> iced::Element<'a, AddressBarMsg> {
    use iced::widget::{container, text, tooltip};
    let card = container(text(label).size(12.0).color(iced::Color {
        r: 0.933,
        g: 0.941,
        b: 0.961,
        a: 1.0,
    }))
    .padding(iced::Padding {
        top: 5.0,
        right: 8.0,
        bottom: 5.0,
        left: 8.0,
    })
    .style(|_| chrome_tip_card_style());
    tooltip(el, card, tooltip::Position::Bottom)
        .gap(4.0)
        .delay(std::time::Duration::from_secs(1))
        .style(|_| iced::widget::container::Style::default())
        .into()
}

fn chrome_tip_card_style() -> iced::widget::container::Style {
    use iced::{Background, Border, Color, Gradient, Shadow, Vector};
    let bg = iced::gradient::Linear::new(iced::Radians(std::f32::consts::PI))
        .add_stop(0.0, Color::from_rgba(0.133, 0.149, 0.204, 0.86))
        .add_stop(1.0, Color::from_rgba(0.110, 0.125, 0.173, 0.82));
    iced::widget::container::Style {
        background: Some(Background::Gradient(Gradient::Linear(bg))),
        border: Border {
            color: Color::from_rgba(1.0, 0.98, 0.94, 0.10),
            width: 1.0,
            radius: 8.0.into(),
        },
        shadow: Shadow {
            color: Color::from_rgba(0.0, 0.0, 0.0, 0.45),
            offset: Vector::new(0.0, 6.0),
            blur_radius: 20.0,
        },
        ..Default::default()
    }
}

/// Events emitted to the shell (the only cross-module boundary).
#[derive(Debug, Clone)]
pub enum AddressBarEvent {
    NavigationCommitted { url: String, mode: Mode },
    ConvertToStrictClicked,
    NetworkViewerRequested,
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use super::*;

    // --- BadgeSlot ---

    #[test]
    fn badge_mode_strict_always_strict() {
        assert_eq!(
            BadgeMode::from_mode_and_count(Mode::Strict, 0),
            BadgeMode::Strict
        );
        assert_eq!(
            BadgeMode::from_mode_and_count(Mode::Strict, 500),
            BadgeMode::Strict
        );
    }

    #[test]
    fn badge_mode_standard_hidden_at_zero() {
        assert_eq!(
            BadgeMode::from_mode_and_count(Mode::Standard, 0),
            BadgeMode::Hidden
        );
    }

    #[test]
    fn badge_mode_standard_shows_count() {
        assert_eq!(
            BadgeMode::from_mode_and_count(Mode::Standard, 5),
            BadgeMode::Blocked(5)
        );
    }

    #[test]
    fn badge_count_caps_at_999_plus() {
        assert_eq!(BadgeMode::Blocked(1000).label(), Some("999+".to_string()));
        assert_eq!(BadgeMode::Blocked(999).label(), Some("999".to_string()));
    }

    #[test]
    fn badge_slot_block_increment_updates_count() {
        let mut slot = BadgeSlot::new(Mode::Standard);
        slot.update(BadgeEvent::BlockIncrement {
            domain: "tracker.io".to_string(),
        });
        assert_eq!(slot.block_count, 1);
        assert_eq!(slot.mode, BadgeMode::Blocked(1));
    }

    #[test]
    fn badge_slot_popover_toggle() {
        let mut slot = BadgeSlot::new(Mode::Standard);
        slot.update(BadgeEvent::BlockIncrement {
            domain: "a.com".to_string(),
        });
        slot.update(BadgeEvent::PopoverToggled);
        assert!(slot.popover_open);
        slot.update(BadgeEvent::PopoverToggled);
        assert!(!slot.popover_open);
    }

    #[test]
    fn badge_slot_reset_clears_count_and_closes_popover() {
        let mut slot = BadgeSlot::new(Mode::Standard);
        slot.update(BadgeEvent::BlockIncrement {
            domain: "x.com".to_string(),
        });
        slot.update(BadgeEvent::PopoverToggled);
        slot.update(BadgeEvent::Reset);
        assert_eq!(slot.block_count, 0);
        assert!(!slot.popover_open);
        assert_eq!(slot.mode, BadgeMode::Hidden);
    }

    #[test]
    fn badge_slot_sync_mode_to_strict() {
        let mut slot = BadgeSlot::new(Mode::Standard);
        slot.update(BadgeEvent::BlockIncrement {
            domain: "a.com".to_string(),
        });
        assert_eq!(slot.mode, BadgeMode::Blocked(1));
        slot.sync_mode(Mode::Strict);
        // L41: once synced to Strict the count is irrelevant - badge is always Strict.
        assert_eq!(slot.mode, BadgeMode::Strict);
    }

    #[test]
    fn badge_slot_ring_buffer_caps_at_256() {
        let mut slot = BadgeSlot::new(Mode::Standard);
        for i in 0..=256 {
            slot.update(BadgeEvent::BlockIncrement {
                domain: format!("domain{i}.com"),
            });
        }
        // 257 unique domains pushed; ring buffer must hold at most 256.
        assert_eq!(slot.rows.len(), 256);
        // Running total is still accurate (not trimmed).
        assert_eq!(slot.block_count, 257);
    }

    // --- SuggestionProvider ---

    #[cfg(feature = "mock")]
    #[tokio::test]
    async fn mock_provider_returns_suggestions_for_nonempty_query() {
        let p = MockSuggestionProvider;
        let results = p.suggest("rust", "profile-1").await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].kind, SuggestionKind::Search);
        assert_eq!(results[1].kind, SuggestionKind::Url);
    }

    #[cfg(feature = "mock")]
    #[tokio::test]
    async fn mock_provider_ignores_partition_key_no_panic() {
        // The mock discards partition_key by design (L40 - real provider will use it).
        let p = MockSuggestionProvider;
        let _ = p.suggest("anything", "my-profile-id").await;
    }

    #[cfg(feature = "mock")]
    #[tokio::test]
    async fn mock_provider_empty_query_returns_empty() {
        let p = MockSuggestionProvider;
        let results = p.suggest("", "profile-1").await;
        assert!(results.is_empty());
    }

    // --- UrlInput ---

    #[test]
    fn url_validation_classify_empty() {
        assert_eq!(UrlValidation::classify(""), UrlValidation::Empty);
    }

    #[test]
    fn url_validation_classify_https_url() {
        assert_eq!(
            UrlValidation::classify("https://example.com"),
            UrlValidation::Valid
        );
    }

    #[test]
    fn url_validation_classify_bare_domain() {
        assert_eq!(UrlValidation::classify("example.com"), UrlValidation::Valid);
    }

    #[test]
    fn url_validation_classify_search_query() {
        assert_eq!(
            UrlValidation::classify("what is rust"),
            UrlValidation::Invalid
        );
    }

    #[cfg(feature = "mock")]
    #[test]
    fn debounce_cancel_aborts_previous_handle() {
        let provider: Arc<dyn SuggestionProvider> = Arc::new(MockSuggestionProvider);
        let mut input = UrlInput::new();
        let _t1 = input.on_changed("r".to_string(), Arc::clone(&provider), "p1");
        let _t2 = input.on_changed("ru".to_string(), Arc::clone(&provider), "p1");
        // Second call must have cancelled the first handle; only one handle held.
        assert!(input.debounce_handle.is_some());
    }

    // --- SuggestionList ---

    #[test]
    fn suggestion_list_loaded_opens_list() {
        let mut list = SuggestionList::new();
        list.update(SuggestionEvent::Loaded(vec![Suggestion {
            text: "a".into(),
            kind: SuggestionKind::Search,
        }]));
        assert!(list.open);
        assert_eq!(list.items.len(), 1);
    }

    #[test]
    fn suggestion_list_dismissed_closes_and_clears_selection() {
        let mut list = SuggestionList::new();
        list.update(SuggestionEvent::Loaded(vec![Suggestion {
            text: "a".into(),
            kind: SuggestionKind::Search,
        }]));
        list.update(SuggestionEvent::Dismissed);
        assert!(!list.open);
        assert!(list.selected.is_none());
    }

    #[test]
    fn suggestion_list_selected_valid_index() {
        let mut list = SuggestionList::new();
        list.update(SuggestionEvent::Loaded(vec![
            Suggestion {
                text: "a".into(),
                kind: SuggestionKind::Search,
            },
            Suggestion {
                text: "b".into(),
                kind: SuggestionKind::Url,
            },
        ]));
        list.update(SuggestionEvent::Selected(0));
        assert_eq!(list.selected, Some(0));
    }

    #[test]
    fn suggestion_list_selected_out_of_bounds_ignored() {
        let mut list = SuggestionList::new();
        list.update(SuggestionEvent::Loaded(vec![Suggestion {
            text: "a".into(),
            kind: SuggestionKind::Search,
        }]));
        list.update(SuggestionEvent::Selected(0));
        list.update(SuggestionEvent::Selected(99));
        assert_eq!(list.selected, Some(0)); // unchanged
    }

    #[test]
    fn suggestion_list_empty_loaded_stays_closed() {
        let mut list = SuggestionList::new();
        list.update(SuggestionEvent::Loaded(vec![]));
        assert!(!list.open);
    }

    #[test]
    fn suggestion_list_selected_text_returns_correct_item() {
        let mut list = SuggestionList::new();
        list.update(SuggestionEvent::Loaded(vec![
            Suggestion {
                text: "hello".into(),
                kind: SuggestionKind::Search,
            },
            Suggestion {
                text: "world".into(),
                kind: SuggestionKind::Url,
            },
        ]));
        list.update(SuggestionEvent::Selected(1));
        assert_eq!(list.selected_text(), Some("world"));
    }

    // --- AddressBar state machine ---

    fn make_bar() -> AddressBar {
        #[cfg(feature = "mock")]
        {
            AddressBar::new(
                Arc::new(MockSuggestionProvider),
                Mode::Standard,
                "p1".into(),
            )
        }
        #[cfg(not(feature = "mock"))]
        {
            AddressBar::new_stub(Mode::Standard)
        }
    }

    #[test]
    fn typing_in_rest_state_auto_focuses_bar() {
        // Fresh tab: input is visible while bar_state == Rest (show_input = !has_url).
        // Typing must auto-transition to Focused so Enter submits navigation.
        let mut bar = make_bar();
        assert_eq!(bar.bar_state, BarState::Rest);
        bar.update(AddressBarMsg::UrlInput(UrlInputEvent::Changed(
            "google.com".to_string(),
        )));
        assert_eq!(bar.bar_state, BarState::Focused);
        // Now Enter should commit navigation.
        bar.url_input.validation = UrlValidation::Valid;
        let (event, _) = bar.update(AddressBarMsg::NavigatePressed);
        assert!(matches!(
            event,
            Some(AddressBarEvent::NavigationCommitted { .. })
        ));
    }

    #[test]
    fn state_rest_to_focused_on_focus_gained() {
        let mut bar = make_bar();
        assert_eq!(bar.bar_state, BarState::Rest);
        let (event, _task) = bar.update(AddressBarMsg::FocusGained);
        assert_eq!(bar.bar_state, BarState::Focused);
        assert!(event.is_none());
    }

    #[test]
    fn state_focused_to_rest_on_esc() {
        let mut bar = make_bar();
        bar.update(AddressBarMsg::FocusGained);
        bar.update(AddressBarMsg::EscPressed);
        assert_eq!(bar.bar_state, BarState::Rest);
    }

    #[test]
    fn state_pill_only_from_rest() {
        let mut bar = make_bar();
        bar.update(AddressBarMsg::ScrolledDown);
        assert_eq!(bar.bar_state, BarState::Pill);

        let mut bar2 = make_bar();
        bar2.update(AddressBarMsg::FocusGained);
        bar2.update(AddressBarMsg::ScrolledDown);
        assert_eq!(bar2.bar_state, BarState::Focused); // scroll ignored while focused
    }

    #[test]
    fn state_pill_to_rest_on_scroll_up() {
        let mut bar = make_bar();
        bar.update(AddressBarMsg::ScrolledDown);
        bar.update(AddressBarMsg::ScrolledUp);
        assert_eq!(bar.bar_state, BarState::Rest);
    }

    #[test]
    fn navigate_pressed_while_focused_emits_committed_event() {
        let mut bar = make_bar();
        bar.update(AddressBarMsg::FocusGained);
        bar.url_input.text = "https://example.com".to_string();
        bar.url_input.validation = UrlValidation::Valid;
        let (event, _task) = bar.update(AddressBarMsg::NavigatePressed);
        assert!(matches!(
            event,
            Some(AddressBarEvent::NavigationCommitted { .. })
        ));
        assert_eq!(bar.bar_state, BarState::Navigating);
    }

    #[test]
    fn navigate_invalid_url_uses_ddg_search() {
        let mut bar = make_bar();
        bar.update(AddressBarMsg::FocusGained);
        bar.url_input.text = "what is rust".to_string();
        bar.url_input.validation = UrlValidation::Invalid;
        let (event, _) = bar.update(AddressBarMsg::NavigatePressed);
        if let Some(AddressBarEvent::NavigationCommitted { url, .. }) = event {
            assert!(
                url.contains("duckduckgo.com"),
                "expected DDG search URL, got: {url}"
            );
        } else {
            panic!("expected NavigationCommitted");
        }
    }

    #[test]
    fn no_convert_chip_in_strict_mode() {
        let mut bar = make_bar();
        bar.sync_mode(Mode::Strict);
        assert!(!bar.show_convert_chip());
    }

    #[test]
    fn convert_chip_visible_on_fresh_standard_tab() {
        let bar = make_bar();
        assert_eq!(bar.chip_state, ChipState::FreshTab);
        assert!(bar.is_fresh_tab());
        assert!(bar.show_convert_chip());
    }

    #[test]
    fn convert_chip_hidden_after_navigation() {
        let mut bar = make_bar();
        assert!(bar.show_convert_chip());
        bar.update(AddressBarMsg::FocusGained);
        bar.url_input.text = "https://example.com".to_string();
        bar.url_input.validation = UrlValidation::Valid;
        bar.update(AddressBarMsg::NavigatePressed);
        // User committed to Standard — chip permanently hidden.
        assert_eq!(bar.chip_state, ChipState::Hidden);
        assert!(!bar.show_convert_chip());
    }

    #[test]
    fn external_url_shows_chip_and_sets_external_state() {
        let mut bar = make_bar();
        // Simulate pressing Enter first so tab is no longer fresh.
        bar.update(AddressBarMsg::FocusGained);
        bar.url_input.text = "https://a.com".to_string();
        bar.url_input.validation = UrlValidation::Valid;
        bar.update(AddressBarMsg::NavigatePressed);
        assert!(!bar.show_convert_chip()); // gone after user navigation

        // Now a link opens the bar externally.
        bar.update(AddressBarMsg::NavigatedExternally(
            "https://b.com".to_string(),
        ));
        assert_eq!(bar.chip_state, ChipState::ExternalUrl);
        assert!(bar.show_convert_chip()); // chip back for external URL
        assert_eq!(bar.current_url, "https://b.com");
    }

    #[test]
    fn auto_dismiss_hides_chip_only_when_external() {
        let mut bar = make_bar();
        // On fresh tab, AutoDismiss is a no-op (timer only fires for ExternalUrl).
        bar.update(AddressBarMsg::AutoDismissConvertChip);
        assert_eq!(bar.chip_state, ChipState::FreshTab);

        // On ExternalUrl, AutoDismiss hides the chip.
        bar.update(AddressBarMsg::NavigatedExternally(
            "https://c.com".to_string(),
        ));
        bar.update(AddressBarMsg::AutoDismissConvertChip);
        assert_eq!(bar.chip_state, ChipState::Hidden);
        assert!(!bar.show_convert_chip());
    }

    #[test]
    fn dismiss_button_hides_chip_from_external_url() {
        let mut bar = make_bar();
        bar.update(AddressBarMsg::NavigatedExternally(
            "https://x.com".to_string(),
        ));
        assert!(bar.show_convert_chip());
        bar.update(AddressBarMsg::DismissConvertChip);
        assert_eq!(bar.chip_state, ChipState::Hidden);
    }

    #[test]
    fn convert_chip_stays_hidden_on_second_navigation() {
        let mut bar = make_bar();
        bar.update(AddressBarMsg::FocusGained);
        bar.url_input.text = "https://a.com".to_string();
        bar.url_input.validation = UrlValidation::Valid;
        bar.update(AddressBarMsg::NavigatePressed);
        // Simulate second navigation.
        bar.update(AddressBarMsg::FocusGained);
        bar.url_input.text = "https://b.com".to_string();
        bar.url_input.validation = UrlValidation::Valid;
        bar.update(AddressBarMsg::NavigatePressed);
        assert!(!bar.show_convert_chip());
    }

    #[test]
    fn convert_to_strict_clicked_emits_event() {
        let mut bar = make_bar();
        let (event, _) = bar.update(AddressBarMsg::ConvertToStrictClicked);
        assert!(matches!(
            event,
            Some(AddressBarEvent::ConvertToStrictClicked)
        ));
    }

    // --- Badge popover ---

    #[test]
    fn badge_popover_opens_on_toggle() {
        let mut bar = make_bar();
        // Seed one block so popover has rows to show.
        bar.badge.update(BadgeEvent::BlockIncrement {
            domain: "ads.example.com".to_string(),
        });
        bar.update(AddressBarMsg::Badge(BadgeEvent::PopoverToggled));
        assert!(bar.badge.popover_open);
    }

    #[test]
    fn badge_popover_closes_on_toggle_twice() {
        let mut bar = make_bar();
        bar.badge.update(BadgeEvent::BlockIncrement {
            domain: "ads.example.com".to_string(),
        });
        bar.update(AddressBarMsg::Badge(BadgeEvent::PopoverToggled));
        bar.update(AddressBarMsg::Badge(BadgeEvent::PopoverToggled));
        assert!(!bar.badge.popover_open);
    }

    #[test]
    fn network_viewer_requested_closes_popover_and_emits_event() {
        let mut bar = make_bar();
        bar.badge.update(BadgeEvent::BlockIncrement {
            domain: "tracker.io".to_string(),
        });
        bar.update(AddressBarMsg::Badge(BadgeEvent::PopoverToggled));
        assert!(bar.badge.popover_open);
        let (event, _) = bar.update(AddressBarMsg::NetworkViewerRequested);
        assert!(!bar.badge.popover_open);
        assert!(matches!(
            event,
            Some(AddressBarEvent::NetworkViewerRequested)
        ));
    }

    #[test]
    fn badge_popover_resets_on_navigation() {
        let mut bar = make_bar();
        bar.badge.update(BadgeEvent::BlockIncrement {
            domain: "x.com".to_string(),
        });
        bar.update(AddressBarMsg::Badge(BadgeEvent::PopoverToggled));
        // Navigation fires BadgeEvent::Reset which closes the popover.
        bar.badge.update(BadgeEvent::Reset);
        assert!(!bar.badge.popover_open);
    }

    #[test]
    fn address_bar_noop_returns_no_event() {
        let mut bar = make_bar();
        let (event, _) = bar.update(AddressBarMsg::Noop);
        assert!(event.is_none());
    }
}
