# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Termino is end-to-end encrypted terminal chat: two people type the same channel name and
password on different machines and talk through a relay that holds no key. Bun runtime,
React + OpenTUI for the interface, `@noble/*` and WebCrypto for the crypto.

Read `.claude/field-guide.md` too — it holds hard-won facts about OpenTUI, `testRender`,
and flaky cases that are not derivable from the code. It has a 40-line budget: add a line
only by deleting one worth less, and put coding standards here rather than there.

## Commands

```sh
bun install
bun test                          # whole suite; --timeout 30000 for a slow machine
bun test test/trust.test.ts       # one file
bun test -t "shows the channel"   # one case, by title substring
bun run typecheck                 # tsc --noEmit — the only static gate; there is no linter

bun run start:relay               # relay on ws://localhost:8787
bun run start -- --channel demo --nick alice   # a client (password prompted, never a flag)
bun run start -- --help
```

Three grep-based guards enforce properties the type system cannot. Run all three before
calling work done; each fails loudly rather than vacuously.

```sh
bun run check:no-deno      # no Deno references survive anywhere outside node_modules/.git/specs
bun run check:relay-pure   # server/ and shared/protocol/frame.ts import nothing from crypto/
bun run check:readme       # README names the absence of forward secrecy near its caveats heading
```

`specs/` is gitignored; the handoff spec that produced this codebase lives there locally.

## Architecture

Three layers, and the boundaries between them are load-bearing:

```
shared/crypto/     derivation, AEAD, Ed25519 identity, word fingerprints
shared/protocol/   frame.ts (outer, relay-visible) · message.ts (inner, encrypted)
server/relay.ts    a separate deployable; imports frame.ts and nothing else
src/               session.ts (headless client core) · trust.ts · replay.ts · tui/ on top
test/              mirrors the tree above, file for file
```

**The relay's blindness is a property of the import graph, not a promise.** `server/` and
`shared/protocol/frame.ts` must never import from `shared/crypto/`; `check:relay-pure`
fails the build if they do. `frame.ts` duplicates `NONCE_BYTES` rather than importing it
for this reason — the two must be kept in agreement by hand.

**`src/session.ts` is the client core and prints nothing.** It connects, subscribes, seals
outbound, opens and verifies inbound, and reports through callbacks. Everything under
`src/tui/` is a view layer with no protocol knowledge. Anything testable without a terminal
belongs below this line.

**Order of operations on an inbound message is a security property**, encoded in
`session.ts`: decrypt → verify signature → replay/freshness check (`replay.ts`) → trust
store (`trust.ts`) → deliver. The replay check comes *before* the trust store deliberately,
so a recorded old message cannot ring `!! KEY CHANGED` against the key someone holds today.

**Pure cores, thin shells.** `trust.ts` (`classify`, `observe`, `setVerified`, `verifyPeer`),
`replay.ts` (`admit`), and the relay's `takeToken` are pure functions returning new values,
with file and socket I/O confined to their edges. `observe`/`verifyPeer`/`admit` return the
input unchanged when nothing changed, so callers can skip the write. Keep new logic on this
side of the line.

**`src/main.ts` imports lazily on purpose.** The renderer is imported only after key
derivation (constructing one without a TTY hangs, and `--help` must not load it), and
`server/relay.ts` only under `serve` (a client never loads relay code). Argon2id blocks
~850 ms; it is paid on the plain terminal before any renderer exists, so `App` receives
`ChannelKeys` already derived and never derives them itself.

**The composer is uncontrolled.** `Composer.tsx` never receives a `value` prop and reads
the draft off the `InputRenderable` ref. This is the reason the rewrite happened: no
re-render caused by an incoming message may destroy half-typed input.

## Wire contract — do not change casually

These values decide whether two clients can talk. Changing any of them lands a client in a
different channel, or invalidates every signature ever made, *while appearing to work*.

- `ARGON2ID = { t: 3, m: 65536, p: 1, dkLen: 32 }` in `shared/crypto/derive.ts` is **frozen**.
  It is the entire anti-guessing budget, not a performance knob; `derive.test.ts` carries a
  known-answer vector that fails if it is edited.
- The salt label `termino/salt/v1|` and HKDF labels `termino/handle/v1` / `termino/msgkey/v1`.
- `signedBytes()` signs a JSON **array**, `[handle, from, nick, body, ts]` — an array because
  object key order is not guaranteed, handle-first so a message cannot be lifted from one
  channel into another. Reordering breaks every existing signature.
- `PROTOCOL_VERSION = 1` on every frame; unknown versions are rejected, never ignored.
- `readSignature` re-emits the signature in one canonical base64 spelling, because replay
  detection compares signature strings.

The README's *Wire format* section is the user-facing copy of this and must be updated in
step with any change here.

## Conventions

- **Comments explain why, not what.** The existing prose documents the attack a line
  prevents or the failure a shape avoids. Match that; do not add narration of the obvious.
- **Failures are announced, never swallowed.** A message that cannot be shown — undecryptable,
  replayed, stale, rate-limited — produces a notice on screen. A corrupt trust store throws
  rather than starting empty, because an empty store silently re-accepts every key.
- **Nothing touches `~/.termino` in tests.** `terminoDir` is a parameter throughout
  (`loadOrCreateIdentity`, `startSession`, `App`) precisely so tests can pass a temp dir.
  Same for injectable `now()` in `session.ts` and `startRelay`.
- **Tests use `bun:test` and mirror the source tree.** Shared scaffolding — ephemeral-port
  relay, temp dirs, `wait` — lives in `test/support/harness.ts`; TUI mounting in
  `test/support/tui.tsx`. A helper that mirrors no source file belongs under `test/support/`.
- **TUI tests render headlessly** through `testRender` at an explicit width/height and assert
  against `captureCharFrame()`. Anything awaiting real I/O must poll against a wall-clock
  deadline — see the field guide for why `waitFor`/`waitForFrame` do not work here.
- `bun.lock` is committed deliberately: it pins the pre-1.0 OpenTUI 0.5.1 builds.
