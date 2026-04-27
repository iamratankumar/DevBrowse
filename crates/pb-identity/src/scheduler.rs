// Renderer scheduler — Module 8.
//
// SECURITY INVARIANT — never refactor silently:
//   strict tab  → always new renderer process, never shared, bypasses cap
//   standard tab → shared within same profile_id only, never across profiles
