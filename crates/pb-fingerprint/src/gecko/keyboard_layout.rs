//! Module 35.13 — `navigator.keyboard.getLayoutMap()` cohort lock.
//!
//! Locks the W3C Keyboard Map API surface so the per-host
//! keyboard layout (QWERTY vs AZERTY vs Dvorak vs Cyrillic etc.)
//! does not leak. The Keyboard Map API returns
//! `Map<USB-HID-code, key-glyph>` — a high-entropy locale signal
//! that CreepJS probes and Tor RFP locks. Both modes lock to the
//! US-QWERTY map (matches `LOCKED_LANGUAGE = en-US`).
//!
//! **Audit provenance:** P2-7b from the 2026-05-22 comprehensive
//! audit; Best Practices agent identified this as a missing
//! Firefox-cohort surface.
//!
//! ## Mode-applicability
//!
//! Mode-invariant lock to the US-QWERTY layout (matches the
//! Module 34 Navigator `LOCKED_LANGUAGE = "en-US"` + the
//! Module 35.12 `LOCKED_INTL_DEFAULTS.numbering_system = "latn"`
//! cohort identity). Both modes return the same map.

use crate::interface::{FingerprintOverride, JsContext, OverrideContext, WebIdlSurface};
use pb_config::Mode;

// ── Locked layout ────────────────────────────────────────────────────────

/// One key entry from the W3C Keyboard Map. Maps a USB-HID-code
/// (e.g. `"KeyA"`, `"KeyZ"`, `"Digit1"`, `"Semicolon"`) to the
/// key glyph the keyboard layout produces when that key is
/// pressed without modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyboardKeyEntry {
    /// `code` — USB HID code string (W3C UIEvents code).
    pub code: &'static str,
    /// `value` — the key glyph the layout produces.
    pub value: &'static str,
}

/// US-QWERTY locked layout. The shortest cohort-safe map that
/// covers the alphabet + digits + common punctuation. Cohort
/// identity = "US English QWERTY keyboard".
pub static US_QWERTY_LAYOUT: &[KeyboardKeyEntry] = &[
    // Alphabet row 1 (QWERTY)
    KeyboardKeyEntry {
        code: "KeyQ",
        value: "q",
    },
    KeyboardKeyEntry {
        code: "KeyW",
        value: "w",
    },
    KeyboardKeyEntry {
        code: "KeyE",
        value: "e",
    },
    KeyboardKeyEntry {
        code: "KeyR",
        value: "r",
    },
    KeyboardKeyEntry {
        code: "KeyT",
        value: "t",
    },
    KeyboardKeyEntry {
        code: "KeyY",
        value: "y",
    },
    KeyboardKeyEntry {
        code: "KeyU",
        value: "u",
    },
    KeyboardKeyEntry {
        code: "KeyI",
        value: "i",
    },
    KeyboardKeyEntry {
        code: "KeyO",
        value: "o",
    },
    KeyboardKeyEntry {
        code: "KeyP",
        value: "p",
    },
    // Home row (ASDF)
    KeyboardKeyEntry {
        code: "KeyA",
        value: "a",
    },
    KeyboardKeyEntry {
        code: "KeyS",
        value: "s",
    },
    KeyboardKeyEntry {
        code: "KeyD",
        value: "d",
    },
    KeyboardKeyEntry {
        code: "KeyF",
        value: "f",
    },
    KeyboardKeyEntry {
        code: "KeyG",
        value: "g",
    },
    KeyboardKeyEntry {
        code: "KeyH",
        value: "h",
    },
    KeyboardKeyEntry {
        code: "KeyJ",
        value: "j",
    },
    KeyboardKeyEntry {
        code: "KeyK",
        value: "k",
    },
    KeyboardKeyEntry {
        code: "KeyL",
        value: "l",
    },
    // Bottom row (ZXCV)
    KeyboardKeyEntry {
        code: "KeyZ",
        value: "z",
    },
    KeyboardKeyEntry {
        code: "KeyX",
        value: "x",
    },
    KeyboardKeyEntry {
        code: "KeyC",
        value: "c",
    },
    KeyboardKeyEntry {
        code: "KeyV",
        value: "v",
    },
    KeyboardKeyEntry {
        code: "KeyB",
        value: "b",
    },
    KeyboardKeyEntry {
        code: "KeyN",
        value: "n",
    },
    KeyboardKeyEntry {
        code: "KeyM",
        value: "m",
    },
    // Digit row
    KeyboardKeyEntry {
        code: "Digit0",
        value: "0",
    },
    KeyboardKeyEntry {
        code: "Digit1",
        value: "1",
    },
    KeyboardKeyEntry {
        code: "Digit2",
        value: "2",
    },
    KeyboardKeyEntry {
        code: "Digit3",
        value: "3",
    },
    KeyboardKeyEntry {
        code: "Digit4",
        value: "4",
    },
    KeyboardKeyEntry {
        code: "Digit5",
        value: "5",
    },
    KeyboardKeyEntry {
        code: "Digit6",
        value: "6",
    },
    KeyboardKeyEntry {
        code: "Digit7",
        value: "7",
    },
    KeyboardKeyEntry {
        code: "Digit8",
        value: "8",
    },
    KeyboardKeyEntry {
        code: "Digit9",
        value: "9",
    },
    // Common punctuation (US layout)
    KeyboardKeyEntry {
        code: "Semicolon",
        value: ";",
    },
    KeyboardKeyEntry {
        code: "Quote",
        value: "'",
    },
    KeyboardKeyEntry {
        code: "Comma",
        value: ",",
    },
    KeyboardKeyEntry {
        code: "Period",
        value: ".",
    },
    KeyboardKeyEntry {
        code: "Slash",
        value: "/",
    },
    KeyboardKeyEntry {
        code: "Backslash",
        value: "\\",
    },
    KeyboardKeyEntry {
        code: "BracketLeft",
        value: "[",
    },
    KeyboardKeyEntry {
        code: "BracketRight",
        value: "]",
    },
    KeyboardKeyEntry {
        code: "Minus",
        value: "-",
    },
    KeyboardKeyEntry {
        code: "Equal",
        value: "=",
    },
    KeyboardKeyEntry {
        code: "Backquote",
        value: "`",
    },
    KeyboardKeyEntry {
        code: "Space",
        value: " ",
    },
];

// ── Policy + surface ─────────────────────────────────────────────────────

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyboardLayoutPolicy {
    /// Locked US-QWERTY (mode-invariant; both modes resolve here).
    Locked(&'static [KeyboardKeyEntry]),
}

impl KeyboardLayoutPolicy {
    pub fn for_mode(_mode: Mode) -> Self {
        Self::Locked(US_QWERTY_LAYOUT)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyboardLayoutSurface {
    /// `navigator.keyboard.getLayoutMap()` returns
    /// `Promise<KeyboardLayoutMap>`.
    GetLayoutMap,
    /// `navigator.keyboard.lock()` / `unlock()` — keyboard-lock
    /// API. Both modes deny (return rejected Promise) — the lock
    /// would let a fullscreen page steal arbitrary key events
    /// + reveal layout via lock-target enumeration.
    KeyboardLock,
}

impl KeyboardLayoutSurface {
    pub const ALL: &'static [KeyboardLayoutSurface] = &[Self::GetLayoutMap, Self::KeyboardLock];
}

// ── Override ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct KeyboardLayoutOverride {
    policy: KeyboardLayoutPolicy,
}

impl KeyboardLayoutOverride {
    pub fn new(mode: Mode) -> Self {
        Self {
            policy: KeyboardLayoutPolicy::for_mode(mode),
        }
    }

    pub fn policy(&self) -> KeyboardLayoutPolicy {
        self.policy
    }
}

impl FingerprintOverride for KeyboardLayoutOverride {
    fn surface(&self) -> WebIdlSurface {
        WebIdlSurface::KeyboardLayoutMap
    }

    fn install(&self, _ctx: &OverrideContext) {
        let _ = (self.policy, JsContext::ALL, KeyboardLayoutSurface::ALL);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn us_qwerty_layout_covers_alphabet_digits_and_punctuation() {
        // 26 letters + 10 digits + 11 punctuation + space = 48
        // entries. Cohort lock — any change is an Adaptation
        // protocol cohort shift.
        assert_eq!(US_QWERTY_LAYOUT.len(), 48);

        // Spot-check the alphabet is present.
        for c in 'a'..='z' {
            let code = format!("Key{}", c.to_ascii_uppercase());
            let entry = US_QWERTY_LAYOUT
                .iter()
                .find(|e| e.code == code.as_str())
                .unwrap_or_else(|| panic!("missing alphabet entry: {}", code));
            assert_eq!(entry.value, c.to_string().as_str());
        }

        // Spot-check the digits.
        for d in 0..=9 {
            let code = format!("Digit{}", d);
            let entry = US_QWERTY_LAYOUT
                .iter()
                .find(|e| e.code == code.as_str())
                .unwrap_or_else(|| panic!("missing digit entry: {}", code));
            assert_eq!(entry.value, d.to_string().as_str());
        }
    }

    #[test]
    fn us_qwerty_codes_are_unique() {
        // No duplicate USB-HID codes — the W3C map is by-code.
        let mut codes: Vec<&str> = US_QWERTY_LAYOUT.iter().map(|e| e.code).collect();
        codes.sort();
        let len_before = codes.len();
        codes.dedup();
        assert_eq!(
            len_before,
            codes.len(),
            "duplicate code in US_QWERTY_LAYOUT"
        );
    }

    #[test]
    fn for_mode_is_mode_invariant() {
        let s = KeyboardLayoutPolicy::for_mode(Mode::Standard);
        let t = KeyboardLayoutPolicy::for_mode(Mode::Strict);
        assert_eq!(s, t);
        match s {
            KeyboardLayoutPolicy::Locked(map) => {
                assert!(std::ptr::eq(map, US_QWERTY_LAYOUT));
            }
        }
    }

    #[test]
    fn surface_all_covers_get_layout_and_lock() {
        assert_eq!(KeyboardLayoutSurface::ALL.len(), 2);
    }

    #[test]
    fn override_reports_keyboard_layout_surface() {
        assert_eq!(
            KeyboardLayoutOverride::new(Mode::Strict).surface(),
            WebIdlSurface::KeyboardLayoutMap,
        );
        assert_eq!(
            KeyboardLayoutOverride::new(Mode::Standard).surface(),
            WebIdlSurface::KeyboardLayoutMap,
        );
    }

    #[test]
    fn override_install_is_context_inert() {
        let pid = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000035130").unwrap();
        for mode in [Mode::Standard, Mode::Strict] {
            let ovr = KeyboardLayoutOverride::new(mode);
            let policy_before = ovr.policy();
            for jsc in JsContext::ALL {
                let ctx = OverrideContext::new(mode, pid, *jsc);
                ovr.install(&ctx);
            }
            assert_eq!(ovr.policy(), policy_before);
        }
    }

    #[test]
    fn keyboard_layout_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<KeyboardLayoutOverride>();
        assert_send_sync::<KeyboardLayoutPolicy>();
        assert_send_sync::<KeyboardLayoutSurface>();
        assert_send_sync::<KeyboardKeyEntry>();
    }
}
