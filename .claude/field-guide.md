# Field guide

Facts about this repo that cost an agent time to discover. Read by every
spec-implementer before it starts. Budget: 40 lines — to add one, delete a
line worth less. Coding standards belong in CLAUDE.md, not here.

- `@opentui/react`'s `testRender` sets `globalThis.IS_REACT_ACT_ENVIRONMENT = true` and leaves it set until `renderer.destroy()`. Tests driven by real sockets must set it back to `false`, or every state update logs an act() warning — and polling *inside* an `act()` callback deadlocks, because React only flushes queued updates when act returns.
- `TestRendererSetup.waitFor`/`waitForFrame` (`@opentui/core/testing`) budget in render passes, not milliseconds: ~20 passes of an idle tree elapse in under a millisecond. Anything awaiting real I/O must poll `renderOnce()` + `captureCharFrame()` against a wall-clock deadline instead.
- `testRender(node, { width, height })` takes terminal dimensions explicitly; it does not need `COLUMNS`/`LINES` or a TTY, so headless TUI tests work with stdout redirected to a file.
- `@opentui/react`'s `onSubmit` types are unsatisfiable — `InputProps` declares `(value: string) => void` intersected with `TextareaOptions`' `(event: SubmitEvent) => void`, so no handler with a typed parameter compiles. Use a zero-argument handler and read the draft off the `InputRenderable` ref; the runtime still passes the string.
- Shared test scaffolding (ephemeral-port relay, temp-dir cleanup, `wait`) lives in `test/support/harness.ts`. The rest of `test/` mirrors `src/` file for file, so a new helper that mirrors nothing belongs under `test/support/`.
