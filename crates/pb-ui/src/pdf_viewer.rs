// Module 62 — Inline PDF viewer (Phase 8).
//
// Architecture L17: pdf.js sandboxed renderer + explicit download fallback.
// No external PDF helper process; the sandboxing boundary matches the
// renderer process model (§5.1). The download fallback must go through
// the capability model (FileHandle via save_picker) — never a raw path write.
//
// TODO Module 62: implement the pdf.js embedding, sandboxed renderer wiring
// through Gecko's WebIDL surface, page navigation controls, and the
// download-to-FileHandle fallback path.
