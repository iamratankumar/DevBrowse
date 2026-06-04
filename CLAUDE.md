## Approach
- Read files only when context is needed; never preload.
- Thorough in reasoning, concise in output.
- Skip files over 100KB unless required.
- No sycophantic openers or closing fluff.
- No emojis or em-dashes.
- Do not guess APIs, versions, flags, commit SHAs, or package names — verify first.
- **Before implementing any module: `grep -n "TODO Module <N>" <target-files>` and read every matching TODO. These carry wiring points, edge cases, and deferred decisions from prior sessions. Address TODOs owned by the current module; leave all others untouched.**
- **When looking up design or architecture docs: `grep` for the section first, then `Read` with `offset`+`limit`. Never read an entire file to find one fact.**
- Test placement: unit tests in each file's `#[cfg(test)] mod tests` block. Cross-module coupling regressions in `pb-testkit/tests/`. Phase 10 adversarial suite in `pb-testkit/tests/` only.

## Session start
Open `project-plan/README.md` first — reading order, phase index, glossaries, and acceptance criteria live there.

**Phase boundary:** when a phase is fully done (all modules + exit gate), start the next phase in a fresh chat. Re-read README + the next phase file. Plan files + architecture + memory + code are the full handoff; do not rely on chat history.

## Per-module status report ritual
After each module's acceptance criteria pass (cargo check + test + clippy `-D warnings`), post a concise status report and wait for explicit approval before advancing.

**For UI modules:** also run the application and visually confirm the window renders before flipping status. Cargo green does not mean the UI works.

Format:
```
Module N — <name> — done
- Files: <crates/.../*.rs paths>
- Tests added: <count> (<one-line summary>)
- Edge cases covered: <list from phase file>
- Architecture invariants enforced: <L-numbers>
- cargo check / test / clippy: green
- Status flipped in: project-plan/phase-N-*.md + README snapshot
- Notes / surprises: <anything new to flush>
```

## Module status updates — ONLY after explicit user approval
**Never flip phase file status or README snapshot until the user explicitly approves the module.**
The sequence is: code → cargo check/test/clippy green → run app visually → post status report → **wait for approval** → then and only then flip:
- The module's status in its phase file from `(next)` to `done`.
- Promote the next pending module to `(next)` — exactly one `(next)` across all phase files.
- Update the README status snapshot.

## End-of-session checkpoint
Before ending a chat, flush everything to the canonical place:

| Insight | Destination |
|---|---|
| Architectural decision | `docs/architecture.md` revision log |
| Threat-model change | `docs/threat-model.md` |
| Edge case discovered | Phase file "Edge cases" section |
| Flaky test | Comment in the test file |
| User feedback / preference | Auto-memory + MEMORY.md |
| Cross-phase coupling | Dependencies line of both modules + pb-testkit note |
| Work in progress | TODO comments in the file |

## UI design docs (docs/ui/)
Write one only when the feature has two or more of: non-trivial state machine, multiple sub-components, L-invariant enforcement, async pipeline, cross-module event boundary. Simple widgets and style changes do not need one.

## Phase exit cumulative test gate
Checklist lives in `project-plan/README.md` §"Phase exit — cumulative test gate". Run it before starting any module in the next phase.
