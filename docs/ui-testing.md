# UI Testing Guide

## RULE — Test cases are permanent

**You must not edit or delete an existing regression scenario unless the change
is a breaking architectural decision approved by the team.** Existing scenarios
are the living contract of what the UI guarantees. If your new code breaks a
scenario, fix the code — not the test.

The only legitimate reasons to modify an existing scenario:
- The feature it covers was intentionally removed
- A breaking architecture change (e.g. message renamed, state field restructured)
  that has been explicitly approved

When in doubt, add a new scenario — do not touch old ones.

---

## How to run

```bash
# Quick signal — run only regression flows after a big change
cargo test -p pb-ui regression

# Full suite — unit tests + regression
cargo test -p pb-ui

# Single scenario
cargo test -p pb-ui regression_<name>
```

---

## File layout

```
crates/pb-ui/src/
  lib.rs          — declares `#[cfg(test)] mod regression;`
  regression.rs   — all regression scenarios live here
  shell.rs        — helpers: update(), view(), ready_state_for_test()
  sidebar.rs      — unit tests: sidebar state machine, pill colours
  tab_bar/        — unit tests: tab lifecycle
  address_bar.rs  — unit tests: address bar messages
```

All test code is gated behind `#[cfg(test)]`. It is never compiled into
production or release builds — zero overhead.

---

## Helpers

### `ready_state_for_test() -> AppState`

Returns a fully booted `AppState`: phase Ready, mode Standard, 1440×900 window,
5 stub tabs. Use this as the starting point for every scenario.

### `step(state, msg)`

Sends one `Message` through `update()`. Async timers do not run — only
synchronous state changes apply. This is intentional.

### `assert_view_stable(state)`

Calls `view()` and discards the result. Passes if the widget tree builds
without panicking. Does not check layout or visual output.

---

## How to add a scenario

### When

Add a scenario whenever you ship:
- A new user-facing interaction
- A bug fix that changed state machine logic
- A refactor that touched `update()` or `view()`

### Template

```rust
/// One sentence describing the user action and expected outcome.
#[test]
fn regression_<group>_<flow_name>() {
    let mut state = ready_state_for_test();

    // Drive the flow — one step per user action.
    step(&mut state, Message::Sidebar(SidebarMsg::PillEntered(0)));
    step(&mut state, Message::HideTooltip);

    // Assert the expected outcome.
    assert_eq!(state.sidebar.tooltip_pill_id, None);

    // Optionally verify view() doesn't panic.
    assert_view_stable(&state);
}
```

### Naming convention

`regression_<group>_<flow_name>`

| Group | What it covers |
|---|---|
| `view_stable` | `view()` must not panic |
| `tab` | Tab open / close / activate |
| `sidebar_tooltip` | Pill hover card lifecycle |
| `sidebar_drag` | Drag-to-reorder |
| `strict` | L41 / §3.6 invariants |
| `window` | Resize / fullscreen |
| `address_bar` | Navigation, badge, mode chip |

Add the scenario inside the matching group in `regression.rs`. If no group
fits, add a new one with a comment banner following the existing format.

### Checklist before committing

1. `cargo test -p pb-ui` — all tests must pass, including old ones
2. `cargo clippy -p pb-ui -- -D warnings` — must be clean
3. `cargo build --release -p pb-ui` — confirms no test code in production binary

---

## What scenarios verify

- State machine transitions are correct after each user action
- `view()` does not panic for any reachable state
- UI invariants hold (Strict lock, one active tab, tooltip grace period)

## What scenarios do not verify

- Visual layout or pixel positions — verify against the UI directly
- Hover animation colours — state is discrete, no intermediate frames
- Iced widget positioning — requires a live renderer

For visual checks, run the app: `cargo run -p pb-ui --bin devbrowse_ui`
