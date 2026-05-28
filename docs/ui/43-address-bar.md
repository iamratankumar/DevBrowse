# Module 43 — Address Bar

Phase 8, `crates/pb-ui/src/address_bar.rs`
UX spec: `docs/design/modules/43.md`
Invariants: L18, L31, L32, L40, L41

## Components

```
AddressBar                  bar_state, mode, reduced_motion
  ├── UrlInput              text, cursor, validation, debounce_token
  ├── SuggestionList        items, selected, open
  │   └── SuggestionProvider trait + MockSuggestionProvider
  └── BadgeSlot             BadgeMode { Blocked(u32) | Strict | Hidden },
                            popover_open, rows
```

Internal events stay inside the module. Only three events reach the shell:
`NavigationCommitted`, `ConvertToStrictClicked`, `NetworkViewerRequested`.

## Data flow

```
Shell
  │  ChromeCommand::ModeChanged(mode)
  │  ChromeCommand::ActiveTabChanged { tab_count }
  ▼
AddressBar::update(ChromeCommand)
  ├── UrlInput::update(UrlInputEvent)       -> Option<AddressBarEvent>
  ├── SuggestionList::update(SuggestionEvent) -> Option<AddressBarEvent>
  └── BadgeSlot::update(BadgeEvent)         -> Option<AddressBarEvent>

AddressBarEvent (shell-visible only):
  NavigationCommitted { url, mode }
  ConvertToStrictClicked
  NetworkViewerRequested
```

## State machine

| State | Trigger in | Trigger out |
|---|---|---|
| `Rest` | app start / Esc / blur | click / Cmd+L |
| `Focused` | click / Cmd+L | Enter / Esc / blur |
| `Navigating` | Enter commit | response / error |
| `Pill` | scroll-down (from Rest only) | scroll-up |
| `ErrorInterstitial` | HTTP nav in Standard or Strict | user dismisses |

`Pill` is only reachable from `Rest`. `ErrorInterstitial` blocks further nav
until dismissed. No `Strict -> Standard` path (§3.6).

## Suggestion pipeline

1. `UrlInput::Changed` cancels the previous `AbortHandle`.
2. Spawns a tokio task: `sleep(200ms)` then `provider.suggest(query, partition_key)`.
3. `partition_key` = active `profile_id` (never a URL or display name).
4. Result populates `SuggestionList`. Failure is silent.

`SuggestionProvider` trait:
```rust
pub trait SuggestionProvider: Send + Sync + 'static {
    async fn suggest(&self, query: &str, partition_key: &str) -> Vec<Suggestion>;
}
pub struct Suggestion { pub text: String, pub kind: SuggestionKind }
pub enum SuggestionKind { Search, Url, History, Bookmark }
```

`MockSuggestionProvider` is gated behind `#[cfg(test)]` + `mock` feature flag.

## Error handling

| Case | Response |
|---|---|
| Suggestion failure | Silent. Retries on next keystroke. |
| Invalid URL | Tooltip: "That doesn't look like a web address. Try searching instead." |
| HTTP nav (Standard) | Interstitial: "This site is not encrypted. Open anyway?" |
| HTTP nav (Strict) | Interstitial: "Strict mode does not load unencrypted sites." No open option. |

## Tests (unit, in `#[cfg(test)] mod tests`)

- State machine: all valid transitions; invalid transitions are no-ops.
- Debounce fires after 200ms; cancels on rapid keystrokes.
- `BadgeMode` derived correctly from `Mode` + block count.
- Badge count caps at "999+".
- No Convert chip when `Mode::Strict`.
- `suggestion partition_key` matches `profile_id`, never a URL.
- `std::ptr::eq` identity check on `BadgeSlot::rows` across re-renders.
- Pill morph instant when `reduced_motion: true`.
