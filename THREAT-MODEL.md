# Termino — threat model

**Status: unaudited.** Nobody outside this project has reviewed the design or the code. The
primitives underneath it (`@noble/curves`, `@noble/hashes`, WebCrypto) are widely used and sound;
the way they have been assembled into a protocol here has had no external review, and assembly is
where cryptographic mistakes usually live. Treat everything below as a statement of intent that
has been tested but not audited.

This document is written for someone who has never seen the project. It says what Termino is,
what it assumes, who it is meant to defend you against, and — at greater length, because this is
the part that matters — who it does not.

---

## What Termino is

Two people who can meet, call, or otherwise reach each other by some trusted route want to talk
over the internet without the network, or the server in the middle, being able to read them.

One of them runs `termino new`. The program generates a 16-byte secret, prints it as an
**invite** — sixteen words and the address of a server — and waits. They hand that invite to the
other person by whatever route they already trust: in person, over a phone call, on a USB stick,
through a messenger they trust for this purpose. The other person pastes it into `termino join`.
Both clients connect to the server named in the invite, called the **relay**, and from then on
everything between them is encrypted end to end.

```
┌─────────┐   label + ciphertext   ┌───────┐   label + ciphertext   ┌─────────┐
│ alice   │ ─────────────────────► │ relay │ ─────────────────────► │  bob    │
│ has key │                        │ no key│                        │ has key │
└─────────┘                        └───────┘                        └─────────┘
```

The relay is a dumb forwarder. It knows a **routing label** — 32 hex characters derived from the
secret, called the *handle* — and it forwards opaque bytes between the (at most two) connections
that asked for that label. It holds no key and can decrypt nothing. That is not a promise about
how it behaves; it is a property of what it is built from. The relay's code imports the outer
frame format and nothing from the cryptography modules at all, and a build check (`bun run
check:relay-pure`) fails if that ever stops being true.

Concretely, per session:

- Each side generates a fresh **X25519** keypair and sends the public half in the clear.
- Both derive a shared root key from the Diffie–Hellman output **with the invite's secret folded
  in as the HKDF salt**, and with both public keys bound into the derivation. Somebody who ran
  their own exchange with each side separately therefore holds a valid Diffie–Hellman output and
  still cannot reach the root key.
- From the root, each direction gets its own chain. Every message takes one AES-256-GCM key and
  nonce off its chain; the key is used once and overwritten, and the chain only hashes forwards.
- Eight **session words** are derived from the root and shown on both screens, for the two people
  to read aloud to each other.

There is no account, no password, no persistent identity, no key stored anywhere, and nothing
written to disk by the client or the relay.

---

## What it assumes

These are the things Termino cannot check and does not try to. If one of them is false, nothing
below holds.

1. **The invite reached the right person, unread.** The out-of-band route you used is the root of
   all the trust here. Whoever ends up holding the invite is a full participant.
2. **Both devices are honest and uncompromised while the conversation is running.** See
   *A device compromised mid-session*, below.
3. **The code you are running is the code in this repository.** There are no signed releases and
   no reproducible builds yet, so this is currently an assumption you make by reading the source
   or trusting whoever handed you the binary.
4. **X25519, HKDF-SHA256 and AES-256-GCM are sound**, and the implementations of them are correct.
5. **The two people actually compare the session words.** They are the only defence against
   somebody who supplied the invite *and* sits in the middle, and they defend nothing if nobody
   reads them.

---

## Who this defends you against

### Somebody watching the network

They see that two hosts are talking to a relay, how much traffic moves and when. They cannot read
a message, learn a nickname, or tell a chat message from a keep-alive: message contents,
nicknames and the message type are all inside the encryption. Message sizes are padded up to one
of five buckets, so what leaks is roughly "which of five size classes", not the length of what you
typed.

### Somebody who records today and steals the invite tomorrow

Recorded traffic stays shut. Each message key is derived, used once and overwritten, and the
session's Diffie–Hellman keys are generated at connect and dropped at disconnect. Nobody can
recompute an old key later — including the two people who used it. Taking the invite afterwards
lets someone impersonate a party in a **future** session; it does not open a past one.

### Somebody trying to sit in the middle, including the relay itself

The relay is in the ideal position for this: it could answer each side with its own key exchange
and read everything. It fails, because the invite's secret is folded into the derivation as the
HKDF salt. Without that secret, an attacker's exchange produces a root key that neither side
shares, no session is established at all, and both clients say so out loud:

```
⚠ could not establish a session — wrong invite, or somebody is in the middle
```

This fails **closed** — silence is never treated as success. Each side sends an authenticated
`confirm` as its first message, and until the peer's confirm has opened, the other side is not
shown as present and no payload from them is displayed.

The residual case is somebody who handed you the invite in the first place — a compromised
out-of-band channel. Software cannot detect that, which is what the **session words** are for:
both clients show the same eight words, derived from that session's key exchange, and reading
them to each other over a channel the attacker would have to compromise separately closes the
gap. Different sessions produce different words, so there is nothing to remember and nothing to
store — and nothing is defended if the two people nod instead of reading.

### Somebody injecting, replaying, reordering or dropping traffic

Forged frames fail to decrypt and are reported on screen as a count of messages that could not be
opened. A replayed message finds no key left to open it — the key for that counter was destroyed
when it was used — and is refused. Reordering inside a window of 256 messages is absorbed
silently; a message that is stepped over and never turns up produces a visible notice
(`⚠ 1 message from bob never arrived`). Nothing that costs you a message is allowed to be silent.

A third connection that offers a key exchange on a channel that already has two participants is
ignored, and said out loud (`⚠ a third party tried to join this channel`).

---

## Who this does not defend you against

### A device compromised mid-session — *the most important limitation here*

**If somebody controls one of the two devices while a session is running, they can read the rest
of that session.** The chain keys for both directions are in that device's memory, the ratchet
only turns forwards, and nothing in the protocol reaches back in to replace them. Termino has no
**post-compromise security**: a conversation does not heal on its own after an intrusion. The only
cure is to end the session, mint a new invite, hand it over out of band again, and start again.

Adding post-compromise security means attaching a fresh Diffie–Hellman to messages, which is a
deliberate future phase and is not implemented today.

The ordinary version of the same problem: **an open screen is an open screen.** No cryptography
protects a device somebody is holding while it is unlocked, and none of this stops the person you
are talking to from taking a screenshot or simply telling somebody what you said.

### Whoever runs — or seizes — the relay

They cannot read a message. They can see, for every connection: **the IP address it came from,
when it connected, how long it stayed, when each message moved, roughly how large it was, and
which routing label it used.** That is enough to establish who talked to whom and when, which for
many people is the fact they most needed to keep.

Three things make this sharper than it sounds:

- **The client connects to the relay directly.** There is no proxy support and no Tor support in
  this version, so the relay — and anyone who takes the machine, subpoenas its host, or watches
  its uplink — sees the real addresses of both ends. This is the largest unmitigated gap in the
  system and it is a known one, not an oversight.
- **A self-hosted relay has an anonymity set of two.** This project operates no public relay, so
  in practice a relay is run by one of the two people talking, and it carries one conversation.
  On a busy shared server your connection is hidden in a crowd; here there is no crowd, and every
  connection to that host is a participant. Finding the host is most of the way to naming both
  parties — and one of those parties is whoever is paying for it.
- **The routing label is fixed for the life of an invite.** It is derived from the invite's
  secret, so it never changes while that invite is in use. Rotating it is possible but manual:
  mint a new invite, which generates a new secret and therefore a new label — and hand it over
  out of band again, which is the expensive human step this whole design is built around. In
  practice, one label carries every session two people ever have on a given invite, so a relay
  operator carrying several conversations can tell them apart and see each pair coming back.

The relay is built to hold as little of this as it can: it writes nothing to disk and nothing to
its output, in any code path including error paths (`bun run check:relay-silent` enforces that,
and a test spawns the relay and asserts its output is exactly one startup line). It keeps an
in-memory count of open connections per address for its own limits, and drops the entry when the
count reaches zero. But "the operator does not record it" is a promise about a program somebody
can change; **the address is visible to whoever is running it, and no configuration in this
project prevents that.** Assume it is seen.

### Traffic analysis

Timing, session duration, connection patterns and burst structure are all visible to the relay
and to a network observer, and none of them are defended against. There is no cover traffic and
no fixed-rate sending. Padding blunts message length only.

### Anybody who obtains the invite

The invite **is** the door. There is no membership list, no revocation and no second factor:
whoever holds it can complete a session as you. If you are unsure where it went, mint a new one —
that is cheap, and the old invite opens nothing that was recorded under it.

By the same token, a **nickname is not an identity**. It is a label the other party typed,
carried inside the encrypted payload. It says which of the two of you is speaking — which the keys
had already settled — and nothing about who that is in the world.

### Anybody who wants to stop you talking

The relay is a single point of failure and nothing authenticates it. A network attacker on the
path, or the relay itself, can drop or delay messages. `wss://` is required for remote hosts
(plain `ws://` is refused except to loopback, or under an explicit `--insecure`), which at least
proves you reached the host you named — but a host that stops forwarding is still a host that
stops forwarding. The relay also caps itself: 1000 connections in total, 10 from one address, two
subscribers per label, five frames per ten seconds per connection, and a 120-second idle timeout.
Somebody spread across enough addresses can still fill those slots. None of that exposes a
message; all of it can stop one arriving. Loss is at least made visible rather than silent.

### The supply chain

There are no signed releases, no reproducible builds and no published checksums yet. Dependencies
are pinned by a committed lockfile, which pins *versions*, not the integrity of whoever publishes
them. If you did not build this from source you have trusted whoever gave it to you.

### Memory

Termino overwrites chain keys and message keys as it finishes with them, and again when a session
closes, which bounds how long they are reachable. This is **best effort**: JavaScript gives no
guarantee that a copy the engine made is also gone, and none of it helps if the machine is
swapping to disk, hibernating, or being debugged.

---

## Explicitly out of scope

- **Groups.** The design targets exactly two participants; a third is refused.
- **Post-compromise security** (a Diffie–Hellman ratchet). A later phase.
- **Anonymity from the relay** (Tor or SOCKS5 support). Intended, not implemented.
- **A browser, mobile or GUI client.** The relay refuses any connection carrying an `Origin`
  header, which deliberately forecloses a web client.
- **Message history.** Nothing is stored, so there is nothing to seize from a client at rest,
  and equally nothing to recover.
- **Cover traffic and timing resistance.**
- **An actual audit.** This document is the sort of thing an auditor would start from, not a
  substitute for one.

---

## If you find a problem

There is no formal disclosure process and no security contact to write to, because there is no
organisation behind this. Report it through the repository. Given that nothing here has been
audited, assume that reports of real flaws are likely rather than surprising.

## Summary

| You are worried about | Termino helps |
|---|---|
| Your ISP, or a café network, reading your messages | Yes |
| The relay operator reading your messages | Yes |
| Someone recording traffic now and stealing your secret later | Yes |
| Someone who intercepted the invite impersonating your peer | Only if you read the session words aloud |
| The relay operator learning that you two talk, and when | **No** |
| Your IP address being visible to the relay | **No** |
| Somebody who takes over a device mid-conversation | **No** |
| Somebody blocking the conversation entirely | **No — but the loss is visible** |
| Somebody who has the invite | **No — the invite is the door** |
