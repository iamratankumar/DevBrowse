## Approach
- dont all existing files before writing. read if and only if context needed.
- Thorough in reasoning, concise in output.
- Skip files over 100KB unless required.
- No sycophantic openers or closing fluff.
- Use prior context only when directly relevant.
- Otherwise do not go back to previous chat until it is asked to go back after request.
- Comment out consistant to-do in each files so you have context for later sessions so we are not losing any contaxt.
- When editing a file, scan its existing TODOs first: address any whose owner is the current module; leave TODOs targeting other modules / phases / future work alone.
- Test placement: co-locate unit tests + cohort-lock value tests + address-identity (`std::ptr::eq`) tests in each source file's `#[cfg(test)] mod tests` block. Land cross-module coupling regressions in `pb-testkit/tests/` (not in a sibling `pb-fingerprint/tests/` directory). Phase 10 adversarial-fingerprint suite belongs entirely in `pb-testkit/tests/`.
- No emojis or em-dashes.
- Do not guess APIs, versions, flags, commit SHAs, or package names. Verify by reading code or docs before asserting.

## Session start
Reading order, phase index, glossaries, and the canonical acceptance-criteria checklist live in `project-plan/README.md` §"How to use this folder" + §"Acceptance criteria for declaring a module `done`". Open that first; do not duplicate its content here.

## Plan files (project-plan/)
- The master plan is split phase-by-phase under `project-plan/`. Root `plan.md` is a pointer file only.
- **Phase boundary discipline:** when a phase is fully `done` (all modules + Phase exit gate), start the next phase in a fresh chat. Re-read README + the next phase file fresh; the plan files plus architecture + memory + code are a complete handoff bundle.
- **Carry-forward exception:** only carry information across the chat clear if a genuinely new and important step has been taken that is not yet captured in the plan files, the architecture docs, or the auto-memory. In that case, write it to the appropriate place **before** ending the session (see end-of-session checkpoint below) so future sessions can recover it without chat history.

## Per-module status report ritual
After each module's acceptance criteria pass (cargo check + test + clippy `-D warnings`, cross-platform build, doc comment), post a concise status report and wait for explicit approval before advancing. Format:

```
Module N — <name> — done
- Files: <crates/.../*.rs paths>
- Tests added: <count> (<one-line summary>)
- Edge cases covered: <list from phase file Edge cases section>
- Architecture invariants enforced: <L-numbers>
- cargo check / test / clippy: green
- Status flipped in: project-plan/phase-N-*.md (and README status snapshot)
- Notes / surprises: <anything that should be in plan or memory but isn't yet>
```

The "Notes / surprises" line feeds the end-of-session checkpoint update related phase file like did in previous files.

## Module status updates on green tests
- When all acceptance criteria for a module pass, update that module's status in its phase file from `(next)` to `done` in the same commit as the code change.
- Promote the next pending module to `(next)` so the plan keeps exactly one `(next)` marker across all phase files.
- Refresh the **Status snapshot** section at the bottom of `project-plan/README.md` in the same commit (move the just-finished module from "Next" / pending list to "Done").
- This mirrors the convention used through Phases 1-3 (Modules 1-18) and is now codified as part of the acceptance criteria.

## End-of-session checkpoint (before clearing context)
Before ending a chat, audit every item below. Flush anything not yet captured to the canonical place. Do **not** rely on chat history to carry it forward.

| Type of insight | Lands in |
|---|---|
| Architectural decision (new lock, refined invariant) | `docs/architecture.md` revision log entry + body update |
| Threat-model adjustment (new attacker shape, new mitigation) | `docs/threat-model.md` (and revision log) |
| Edge case discovered while implementing | The active module's "Edge cases" section in the phase file |
| Test that was demonstrated to flake | Comment in the test file naming the flake mode |
| User feedback / lock / preference | Auto-memory file under `~/.claude/projects/.../memory/` + MEMORY.md index |
| Cross-phase coupling discovered | The "Dependencies" line of both modules + a note in `pb-testkit` (Module 0.5) for the cross-phase fixture |
| Mid-module work-in-progress | TODO comments in the file (already mandated above) + uncommitted code |

If a session ends without flushing, the next session will rediscover the issue or, worse, miss it. The plan + docs + memory + code is the canonical handoff; the chat is not.

## Phase exit cumulative test gate
The cumulative-gate checklist (commands + Phase 10 adversarial-suite rule + pb-testkit cross-phase contract tests) lives in `project-plan/README.md` §"Phase exit — cumulative test gate". Run it at every Phase N exit before claiming any Phase N+1 module.

</content>
</invoke>