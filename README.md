# Termino

End-to-end encrypted chat that runs in your terminal.

Two people type the same channel name and password on different machines and can talk. The
server in the middle — the **relay** — never learns the password, never holds a key, and never
sees anything but a routing label and a blob of ciphertext it forwards byte for byte.

```
┌─────────┐   handle + ciphertext    ┌───────┐    handle + ciphertext   ┌─────────┐
│ alice   │ ───────────────────────► │ relay │ ───────────────────────► │  bob    │
│ has key │                          │ no key│                          │ has key │
└─────────┘                          └───────┘                          └─────────┘
```

## Running it

```sh
bun install

bun run start:relay                          # a relay on ws://localhost:8787
bun run start -- --channel demo --nick alice # a client, on another machine
```

The password is prompted for on stdin and never echoed. It is **never** accepted as a flag —
that would put it in your shell history and in the output of `ps`. Run `bun run start -- --help`
for the full flag set.

`--relay` says which relay to join. A value with no scheme is read as `wss://`, and plain
`ws://` is refused for every host but `localhost`, `127.0.0.1` and `[::1]` — nothing
authenticates a relay, so an unencrypted connection to a remote one can be dropped or delayed
by anyone on the path. `--insecure` accepts that and connects anyway, which is for a relay you
are tunnelling to yourself. Any other scheme is a usage error rather than a silent rewrite.

Joining takes about a second. That pause is argon2id, and it is the entire reason a weak
channel password is not trivially guessable — see *Wire format*.

## Who you are talking to

The channel password is shared by everyone in the channel, so it proves nothing about *who*
wrote a message: any member could otherwise encrypt a message claiming to be from any other
member. So each installation also has its own signing key, generated on first run and kept at
`~/.termino/identity.key` with mode `0600`. Every message is signed with it before it is
encrypted, so the signature travels inside the envelope and the relay cannot see it.

Your own key is shown as eight words in the status bar. That is its **fingerprint**:

```
your fingerprint: tech topic leopard fruit knife brain purple club
```

The first time a nickname speaks, termino remembers the key it used, and marks it `?`:

```
14:02 ?bob   shipping it now
```

`?` means *nobody has checked this*. To check it, get bob to read his eight words to you over
some channel an attacker would have to compromise separately — a phone call, in person — and
type them in:

```
/verify bob tech topic leopard fruit knife brain purple club
```

Spacing and capitalisation do not matter. On a match the marker becomes `✓` and is remembered
in `~/.termino/known_keys.json`. On a mismatch nothing changes and termino says so — a
fingerprint that is *nearly* right is exactly the case this exists to catch.

If a nickname you already know starts signing with a different key, every client that knew the
old one prints:

```
!! KEY CHANGED for bob — verify out of band
```

That is what an impersonation looks like from here. It is also what a reinstall looks like, so
find out which by asking bob somewhere other than this channel.

## Commands

Anything typed into the composer that does not begin with `/` is sent as a message. These are
the commands, and `/help` prints the same list in the app:

```
/verify <nick> <fingerprint>   mark a peer verified, once you have compared
                               fingerprints elsewhere
/help                          list these commands
/exit                          leave the channel and close termino
```

An unrecognised command is reported to you and sent to nobody — a mistyped command going out
as chat is how people say in public what they meant to type privately.

## What Termino does not protect you against

Read this section before trusting it with anything.

- **There is no forward secrecy.** One password protects the whole channel, forever. Anyone who
  learns it can read every message in that channel — including messages sent *before* they
  obtained the password, if they recorded the ciphertext at the time, and every message sent
  after. Changing the password means agreeing a new one out of band; it does not retroactively
  protect anything. Treat a channel password as compromised the moment it is shared carelessly,
  and start a new channel.
- **A weak password is the whole attack.** The channel address is derived from the password, so
  anyone can try to guess it offline against traffic they have recorded. argon2id makes each
  guess cost about a second. That is enough against a bad passphrase and nothing else — use a
  long random one.
- **The relay sees who talks to whom, and when.** It cannot read a message, but it sees a
  connection, a handle, message sizes, and timing. It knows how many people are in a channel.
  Traffic analysis is not defended against at all.
- **Anyone with the password is in the channel.** There are no invites and no membership: the
  password *is* the door. You find out somebody joined from the participant count.
- **Nothing authenticates the relay.** Message contents stay encrypted regardless of transport,
  but a network attacker on the path can drop or delay your messages. Plain `ws://` is allowed
  only to loopback, and to a remote host only under `--insecure`; everything else must be
  `wss://`, which at least proves you reached the host you named.
- **A nickname is not an identity.** The trust store keys on the nickname you see. Two people
  choosing the same nickname raise a false `!! KEY CHANGED` alarm — deliberately, because
  alarming wrongly is the safe direction to fail.
- **Nothing is kept.** No history, no backfill. You see what is said after you join, and
  messages exist only in the memory of the clients that were connected.
- **Both clocks have to be roughly right.** Refusing messages dated far from now is what stops
  recorded traffic being played back at you later — so a machine whose clock is more than five
  minutes out sees nothing from anybody. It says so on each message it refuses rather than
  going quiet.
- **A compromised device is a compromised channel.** The signing key and the message key are in
  memory on your machine; termino defends the wire, not the endpoint.

## Wire format

These values define whether two clients can talk to each other. A client that changes any of
them lands in a different channel while appearing to work perfectly.

Key derivation, from the channel name and password, on the client:

| | |
|---|---|
| salt | `sha256("termino/salt/v1\|" + channelName)` |
| secret | argon2id, **frozen** at `t: 3, m: 65536, p: 1, dkLen: 32` |
| handle | `hkdf(sha256, secret, info = "termino/handle/v1", 16)` → 32 lowercase hex chars, sent to the relay |
| message key | `hkdf(sha256, secret, info = "termino/msgkey/v1", 32)` → AES-256-GCM, never sent |

The argon2id parameters are part of this contract, not a performance knob. Lowering `m` or `t`
to make joining feel faster spends the anti-guessing budget and silently splits the user base
into two groups who cannot see each other.

Every frame carries `"v": 1`. Unknown versions are rejected rather than ignored. What the relay
sees:

```jsonc
{ "v": 1, "t": "sub", "h": "<handle>" }                       // client → relay, first frame
{ "v": 1, "t": "msg", "h": "<handle>",
  "n": "<base64 12-byte nonce>", "c": "<base64 ciphertext>" }  // client → relay → subscribers
{ "v": 1, "t": "presence", "n": 3 }                            // relay → client
{ "v": 1, "t": "err", "code": "rate_limited" }                 // relay → one client only
```

Inside `c`, AES-256-GCM, never visible to the relay:

```jsonc
{ "from": "<hex ed25519 public key>", "nick": "alice",
  "body": "shipping it now", "ts": 1786531200000,
  "sig": "<base64 ed25519 signature>" }
```

The signature covers `JSON.stringify([handle, from, nick, body, ts])` — an array, because JSON
object key order is not guaranteed, and with the handle leading so a message cannot be lifted
out of one channel and replayed into another. Signing happens before encryption, so `sig` is
inside the envelope.

A signature says who wrote a message, not *when* — and a handle travels in the clear, so
anybody watching the wire can subscribe and send a frame they captured back again without ever
holding the password. So a client also refuses any signature it has already shown, and anything
dated more than **five minutes** either side of now. Both are needed: the window stops a
recording being played back tomorrow, the set of delivered signatures stops it being played
back twice this minute. Either way the message is reported on screen rather than dropped
quietly, and it never reaches the trust store — otherwise a recording of the key somebody used
last month would raise `!! KEY CHANGED` against the key they hold today.

The relay drops any frame over 64 KiB, any frame whose `h` is not 32 lowercase hex characters,
and any `msg` sent before a `sub`. It rate-limits per connection, five messages per ten seconds.

## Layout

```
shared/crypto/   derivation, AEAD, identity, fingerprints
shared/protocol/ the wire contract: outer frames, inner signed payloads
src/             the client: headless session, trust store, replay protection,
                 and src/tui/ on top
server/relay.ts  the relay — a separate deployable, which imports the outer
                 frame format and nothing else, so it cannot decrypt
test/            mirrors the tree above
```

```sh
bun test              # everything
bun run typecheck
```
