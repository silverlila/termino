# Termino

End-to-end encrypted chat that runs in your terminal.

One person runs `termino new`. It generates a secret and prints an **invite**: one token carrying
that secret and the address of a relay. They carry it to the other person by some route they
trust, that person pastes it into `termino join`, and the two of them can talk. The server in the
middle — the **relay** — never learns the secret, never holds a key, and never sees anything but a
routing label and a blob of ciphertext it forwards byte for byte.

```
┌─────────┐   handle + ciphertext    ┌───────┐    handle + ciphertext   ┌─────────┐
│ alice   │ ───────────────────────► │ relay │ ───────────────────────► │  bob    │
│ has key │                          │ no key│                          │ has key │
└─────────┘                          └───────┘                          └─────────┘
```

A channel holds exactly two people. There are no accounts, no passwords, no channel names, and
nothing is written to disk — not even by termino itself.

> ⚠ **This is unaudited software.** Nobody outside this project has reviewed how these
> primitives were assembled into a protocol, and assembly is where the mistakes live. Read
> [THREAT-MODEL.md](THREAT-MODEL.md) — it says in plain words who this protects you from and
> who it does not — before trusting it with anything that would hurt to lose.

## Running it

```sh
bun install

bun run start:relay                                     # a relay on ws://localhost:8787
bun run start -- new --relay wss://relay.example:8787    # mints an invite, then waits
bun run start -- join <invite>                           # the other machine
```

`new` prints the invite — and nothing else — to **stdout**, so it can be piped or copied. It looks
like this:

```
ginger-engine-tuna-desert-fleet-eight-lower-meadow-muscle-desert-club-tuna-fluid-honey-captain-diver@relay.example:8787
```

A one-line warning goes to **stderr** instead, because the invite is now in your terminal
scrollback and that is the most likely way it leaks. Clear the scrollback once the other side has
it.

The invite *is* the secret. Whoever holds it can talk to you, so hand it over the way you would
hand over a key: in person, on a USB stick, over a call, through a messenger you already trust.
Sending it through the relay you are about to use would be pointless.

There is no password to choose and no channel name to agree on. Both are deliberate: a secret a
person picks is one an attacker can guess offline, and a second value to agree out of band is one
more thing to get subtly wrong and land silently in an empty channel.

`--relay` is required on `new` and rejected on `join` — a join reads its relay out of the invite,
so the two ends cannot disagree about where to meet. A `--relay` with no scheme is read as `wss://`.
Plain `ws://` is refused for every host but `localhost`, `127.0.0.1` and `[::1]`: nothing
authenticates a relay, so an unencrypted connection to a remote one can be dropped or delayed by
anyone on the path. `--insecure` accepts that and connects anyway, which is for a relay you are
tunnelling to yourself. An invite carries a host and no scheme, and is dialled over `wss://` unless
it names loopback — nothing issues a certificate for `localhost`, so an invite naming it can only
have come from the machine you are on.

`--nick <name>` names you in the transcript; without it you are asked at the prompt. Run
`bun run start -- --help` for the full flag set.

Both sides block until the other one answers. Until then the status bar says
`waiting for the other side…`, and after twenty seconds the client gives up and says which of the
two things went wrong.

## Somebody has to run the relay, and it is not us

This project **operates no relay**. There is no public address to point a client at, no free
tier and no paid one: the relay in the diagram is a program in this repository that you or the
person you are talking to has to run somewhere. Carrying strangers' traffic that nobody can
inspect means abuse reports nobody can verify and legal demands nobody can answer usefully,
which is a thing to take on deliberately or not at all.

That has a consequence worth being clear about, because it is not the encryption's problem to
solve. Whoever runs a relay cannot read a single message, but
**sees who connects, from what IP and when** — and if the relay is carrying exactly one
conversation, as a self-hosted one usually is, then everyone who connects to it is a participant
in that conversation. The client dials the
relay **directly**: there is no proxy option and no Tor support in this version, so the real
addresses of both ends reach that host, and reach anyone who seizes, subpoenas or shares it.
`THREAT-MODEL.md` sets out what that does and does not expose.

## Who you are talking to

Every session runs its own key exchange, and the invite's secret is folded into it as proof of who
is on the other end. If both ends do not hold the same secret, no session is established at all
and both of them say so:

```
⚠ could not establish a session — wrong invite, or somebody is in the middle
```

That failure is the interesting one. The relay is in a position to run its own exchange with each
side and sit in the middle reading everything, and the secret is what makes that attempt fail
closed rather than succeed silently. But a relay could also have handed you the invite in the
first place, so the software cannot prove on its own that the exchange was clean.

That is what the **session words** are for. Both clients show the same eight words in the status
bar:

```
session words: dinner bottle surf urban sweater haven view nurse
read them aloud to each other — if they differ, somebody is in the middle
```

Read them to each other over some channel an attacker would have to compromise separately — a
phone call, a room. Matching words mean nobody is in the middle. Words that differ mean somebody
is, and the conversation should stop.

There is nothing to type and nothing to remember. The words are derived from that session's key
exchange, so they are different every time you connect and there is nothing to store, verify once,
or keep in a file. They only defend you if you actually read them.

## Commands

Anything typed into the composer that does not begin with `/` is sent as a message. These are the
commands, and `/help` prints the same list in the app:

```
/help    list these commands
/exit    leave the channel and close termino
```

An unrecognised command is reported to you and sent to nobody — a mistyped command going out as
chat is how people say in public what they meant to type privately.

Two other things appear on screen unprompted, because silence would be worse:

```
⚠ 3 messages from bob never arrived
⚠ a third party tried to join this channel
```

The first means messages were numbered, stepped over, and never turned up — the relay can drop or
withhold traffic, and this is what makes that visible instead of silent. The second means a second
key exchange was offered on a channel that already has two participants; it is ignored, and said
out loud.

## What Termino does not protect you against

Read this section before trusting it with anything. [THREAT-MODEL.md](THREAT-MODEL.md) says the
same things at length, with the reasoning, and adds who each of them lets in.

- **Messages already sent are unrecoverable — the live session is not.** Each message gets its own
  key, which is derived, used once, and destroyed. Nobody can recompute it afterwards, including
  the two people who used it, so traffic somebody recorded last week stays shut even if they take
  your secret today. A device compromised *while a session is running* is a different matter
  entirely: the keys for the rest of that session are in its memory, and everything said from that
  point onwards is readable. Termino has no **post-compromise** security — a conversation does not
  heal, and the only cure is to end it, mint a new invite and start again.
- **The relay sees who talks to whom, and when.** It cannot read a message, but it sees your
  connection, your IP address, a routing label, message sizes and timing, and it can tell that the
  same two parties are talking. The client connects directly, so nothing hides those addresses.
  Metadata and traffic analysis are not defended against at all.
- **The routing label is fixed for the life of an invite.** Minting a new invite gives you a new
  one, but that costs another out-of-band handover — the expensive human step — so in practice
  one label carries every session two people ever have on that invite. Whoever runs a relay for
  more than one pair can tell the pairs apart and see that each of them keeps coming back.
- **Whoever holds the invite is in the channel.** There is no membership and no way to revoke: the
  invite *is* the door. If you are not sure who it reached, mint a new one — that is cheap, and the
  old one opens nothing that was recorded under it.
- **The session words defend nothing until two people read them.** Nodding at eight words you did
  not compare is the same as not having them.
- **Nothing authenticates the relay.** Message contents stay encrypted whatever the transport, but
  a network attacker on the path can drop or delay your messages. Plain `ws://` is allowed only to
  loopback, and to a remote host only under `--insecure`; everything else must be `wss://`, which
  at least proves you reached the host you named.
- **A nickname is not an identity.** It is a label the other participant chose, carried inside the
  encrypted payload. It says which of the two of you is speaking — which the keys already settled —
  and nothing about who that is in the world.
- **Nothing is kept.** No history, no backfill, no files. You see what is said while you are
  connected, and messages exist only in the memory of the two clients that were there.
- **Wiping keys from memory is best effort.** Termino overwrites chain keys and message keys as it
  finishes with them and again when a session closes, which bounds how long they are readable. It
  cannot reach a copy the JavaScript engine made, and it cannot help you if the machine is swapping
  or being debugged.
- **The relay can still be crowded out.** It holds at most 1000 connections at once and 10 from any
  one address, refuses a third connection to a channel, drops a connection idle for 120 seconds and
  rate-limits each one to five frames per ten seconds. Somebody spread across enough addresses can
  still fill those slots. None of that exposes a message; it can stop one arriving.
- **This is unaudited software.** The primitives are `@noble/curves`, `@noble/hashes` and
  WebCrypto, which are sound. Assembling primitives into a protocol is where mistakes live, and
  this assembly has had no external review. The banner on the status bar says so on every screen,
  and stays until an audit exists.

## Wire format

These values decide whether two clients can talk to each other. A client that changes any of them
lands in a different channel, or fails to agree a key, while appearing to work perfectly.

The secret is **16 random bytes**, generated by the software and never typed by a person. It is
written as 16 words from a 256-word list, one word per byte, joined by hyphens — the list is built
so that no two words share a three-letter prefix or sit within one edit of each other, so a
misheard or mistyped word fails loudly instead of decoding to something else.

The only thing derived straight from it is the channel address:

```
handle = hkdf(sha256, secret, info = "termino/handle/v2", 16)   → 32 lowercase hex chars
```

The handle travels to the relay in the clear; the secret never leaves the machine. There is no
password hashing anywhere, and none is needed: 128 random bits are not guessable at any rate, so
there is nothing for a slow KDF to slow down.

Both clients then run a fresh **X25519 exchange**, once per session, and fold the secret into it:

```
each side generates an ephemeral keypair and sends the public half in a hello

dh          = X25519(my ephemeral secret, their public key)
transcript  = the two public keys sorted as bytes, concatenated, hex
root        = hkdf(sha256, ikm = dh, salt = secret, info = "termino/session/v2" + transcript, 32)
chain lo→hi = hkdf(sha256, root, info = "termino/chain/lohi/v2", 32)
chain hi→lo = hkdf(sha256, root, info = "termino/chain/hilo/v2", 32)
session words = hkdf(sha256, root, info = "termino/sas/v2", 8) → eight words
```

Three parts of that are load-bearing. The secret is the HKDF **salt** and the exchange output is
the keying material, so somebody who ran their own exchange with each side holds a valid `dh` and
still cannot reach `root` — that is what makes the man-in-the-middle fail closed. The transcript
binds both public keys into the derivation, so a hello cannot be reflected back at its sender or
reordered. And direction is decided by the **byte order of the two public keys**, not by who
connected first: the relay controls delivery order, so letting order decide roles would hand the
relay the roles. The ephemeral secret keys are created at connect and dropped at disconnect, which
is what makes recorded traffic unrecoverable.

Each direction then **ratchets**: one key per message, and the chain hashes only forwards.

```
mk_i        = hkdf(sha256, chain_i, info = "termino/mk/v2", 44)
key         = mk_i[0..32]     → AES-256-GCM
nonce       = mk_i[32..44]    → derived, never transmitted
chain_{i+1} = hkdf(sha256, chain_i, info = "termino/ck/v2", 32)
```

`chain_i` and `mk_i` are overwritten once used. From chain #5 a holder reaches #6, #7, #8 forever
and no arithmetic returns them to #4.

Every frame carries `"v": 2`. Unknown versions are rejected rather than ignored. What the relay
sees:

```jsonc
{ "v": 2, "t": "sub",   "h": "<handle>" }                        // client → relay, first frame
{ "v": 2, "t": "hello", "h": "<handle>",
  "k": "<base64 32-byte X25519 public key>" }                    // client → relay → the other side
{ "v": 2, "t": "msg",   "h": "<handle>", "i": 0,
  "c": "<base64 ciphertext>" }                                   // client → relay → the other side
{ "v": 2, "t": "err",   "code": "rate_limited" }                 // relay → one client only
```

`hello` and `msg` are forwarded byte for byte, and both are routed by the handle the **connection**
subscribed to rather than the one written in the frame — a frame naming a different handle is
answered `bad_frame` and reaches nobody. The counter `i` is in the clear because the relay already
sees how many messages moved and when, and the receiver needs it.

Inside `c`, AES-256-GCM, never visible to the relay:

```jsonc
{ "t": "text",    "nick": "alice", "body": "shipping it now" }
{ "t": "ping",    "nick": "alice" }
{ "t": "confirm", "nick": "alice" }
```

An unknown `t` is rejected, not ignored. There is no signature and no sender key: the session key
is pairwise and each direction has its own chain, so a payload that opens under your receiving
chain was written by the one other party who holds it, and the AEAD tag is the authenticator.
There is no timestamp either — the sender's clock was never believed, and every message is shown
with the receiving client's own arrival time, the only clock it can vouch for.

`confirm` is the first payload each side sends, at counter 0 of its own chain. It is what proves
both ends reached the same keys — without it a mismatched secret would produce silence, and silence
is indistinguishable from nobody having typed yet. `ping` goes out every 15 seconds, and the other
side is shown as present only while something authenticated has opened within 45. Presence is
therefore asserted by the peer rather than by the relay: a relay that withholds traffic shows up as
the other person going quiet, which is what actually happened, instead of the relay claiming they
are still there.

That JSON is **padded to** a size bucket before it is encrypted: a two-byte big-endian length, then
the payload, then zeroes out to the next of `256, 512, 1024, 2048, 4096` bytes. AES-GCM ciphertext
is the plaintext length plus a 16-byte tag, so without this the relay would read the size of every
message to the byte — the difference between "a message moved" and "they typed *yes*". Five buckets
leave it roughly 2.3 bits of length instead. This is why a message body is capped at **1900 UTF-8
bytes**: the padded unit is the serialised payload, and `JSON.stringify` doubles every quote and
backslash, so a larger cap would not fit the top bucket. The two numbers cannot be changed
independently.

There is no replay window and no clock dependency, because there is nothing to replay: a message
key is derived for exactly one counter and destroyed when it is used, so a second copy of a message
finds no key left to open it. A counter already delivered is refused. A counter *ahead* of what has
arrived is serviced by deriving and caching the keys it stepped over, up to **256** of them, so one
dropped frame does not wedge the conversation — a gap filled late is silent, and a gap still open
when the next message arrives is reported on screen. A jump of more than 256, and a cache grown
past 256 entries, are both refused: without those bounds a hostile peer sending counter 2³¹ would
make your client derive two billion keys.

The relay routes nothing and answers an `err` to the sender alone for: any frame over **8 KiB** —
the largest padded message is well under it — any frame whose `h` is not 32 lowercase hex
characters, any `msg` or `hello` sent before a `sub`, a third subscriber to a handle
(`channel_full`), and anything past five frames per ten seconds on one connection.

## Layout

```
shared/crypto/   the secret and invite words, the X25519 handshake, the ratchet,
                 AEAD, and size-bucket padding
shared/protocol/ the wire contract: outer frames, inner encrypted payloads, invites
src/             the client: headless session, and src/tui/ on top
server/relay.ts  the relay — a separate deployable, which imports the outer frame
                 format and nothing else, so it cannot decrypt
test/            mirrors the tree above
```

`bun run check:relay-pure` fails the build if the relay's imports ever reach past that frame
format.

```sh
bun test              # everything
bun run typecheck
```
