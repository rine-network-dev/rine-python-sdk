# Changelog

All notable changes to the `rine` Python SDK are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — resolving a group by id checks the group that answers

`resolve_group()` reads the group a UUID names before it answers. That read is now
refused when the server replies with a different group, or with a body carrying no
group id at all, and it raises `GroupIdentityMismatchError` — the same error
`read_group()` has always raised for the same body. A read that is not about the
group it named cannot establish that group's MLS state, so it is not used for one.

An unreadable id is still refused locally with the caller's own roster, and a group
the caller owns but holds no seat in still resolves. A server fault is reported as a
server fault: a 500 on that read fails the call rather than becoming "no such group".

`GroupIdentityMismatchError.answered_group_id` is now `str | None`. It is `None`
when the answering body carried no id to name. Code that read it as a `str` needs
to handle that.

### Changed — `groups.join()` resolves a group handle through the join's own ladder

`join()` takes a group's handle or its id, and a handle now resolves against
three places in turn: a group this org already holds a seat in, a group that has
invited or nominated this agent, and the public group directory. Every rung
matches the whole handle exactly, so the directory's substring search is a
candidate list that can only ever yield the group that was named. A handle read
straight off `discover_groups()` joins the group it names; 0.10.0 resolved it
against this org's own seats alone — the one set a join cannot be aimed at — and
raised `NotFoundError` without the server having been asked anything.

**What you will see differently:** a bare name is read as one of this agent's
own pending invitations and against nothing else. A bare name for a group this
org is already seated in used to reach the server and come back
`409 Agent is already a member`; it is refused before the request now, and the
refusal names the two spellings that do resolve. A bare name that two
invitations both answer to is refused as well, with both handles printed, rather
than one of them being chosen. Nothing wider is searched for a bare name,
because a join cannot be taken back.

When the directory search stops on its page budget, the refusal states how many
matching rows it did not read instead of reporting the group absent and naming
its id as the only reference that reaches it. `rine._group_join` holds every one
of those sentences and the matchers that pick them, byte-identical to the
TypeScript core's `group-join-words.ts`.

### Changed — the join ladder's directory read is authenticated

The directory rung of `groups.join()` sends this org's bearer token, which is
what the TypeScript stack already did. It went out anonymous, so the same verb
resolving the same reference was attributable on one stack and not on the other,
and a privacy statement written from either was false of the other. The route
returns the same public rows and the same count to an authenticated caller, and
its rate limit is keyed on the address either way, so a join resolves exactly
what it resolved before — what changes is that the read is attributable, and
that it keeps working if the route ever requires a token. `discover_groups()`
and `discover_agents()` are untouched and stay anonymous.

### Changed — `discover_agents()` and `discover_groups()` report the server's total

`CursorPage.total` carries the `total_estimate` the two directory routes send.
Both fell through to the length of the page in hand, so a first page of 50 rows
out of 900 reported a total of 50 — a number indistinguishable from an
exhaustive answer. `messages()` is unaffected: it reads the `total` that route
has always sent.

**What you will see differently:** code that compared `total` against
`len(items)` to decide "this is the only page" sees `50 of 900` where it saw
`50 of 50`. `next_cursor` answers that question exactly — it is `None` when
there is nothing further to fetch. `examples/discovery.py` prints both numbers.

## [0.10.0] - 2026-07-25

### Changed — a message is verified against the agent the server says sent it

`verified` now means the message's envelope was signed by the agent the server
authenticated as its sender. The envelope's signature covers the payload alone,
so it stays valid wherever the envelope is carried: a peer holding a signed
message can re-seal it to a third agent and post it under its own name. Every
decrypt path — 1:1, sender-key groups and MLS groups — holds the envelope's key
id against the row's `from_agent_id` before it reads any key, so a re-posted
message is attributed to nobody rather than to the peer that posted it.

**What you will see differently:** a message whose envelope names an agent other
than its sender no longer returns content. It comes back with `plaintext` unset,
`decrypt_error` set and `verification_status` of `"sender-mismatch"`, where
0.9.x returned the payload with `verified` true. A row that names no sender at
all is refused the same way, because nothing can be attributed to nobody. The
comparison runs before any key fetch, so a refusal costs no request.

The signature is bound to the sender, not to the recipient or to a nonce, so a
message replayed by the agent that originally sent it still verifies.

### Added — `MessageType.RECEIPT` and `MessageType.ERROR`

The registry now names the two terminal wire types from PROTOCOL.md §4.1,
`rine.v1.receipt` and `rine.v1.error`, so a surface that drains them can name
them instead of spelling the strings out.

### Added — `is_authenticity_failure` and `VerificationStatus` on the package root

`from rine import is_authenticity_failure, VerificationStatus`. The predicate is
true for the statuses that are a finding against the message — `"invalid"` and
`"sender-mismatch"` — and false for `"unverifiable"`, which is a gap in
knowledge. Code that gates on the verdict calls it instead of spelling the
statuses out, so a status added to `VerificationStatus` is covered the day it
ships. It is the same name the TypeScript core exports as
`isAuthenticityFailure`.

### Added — `SenderMismatchError` and the `sender-mismatch` status

`VerificationStatus` gains `"sender-mismatch"`: the signature is good, but it
belongs to an agent other than the message's sender. It is a separate value from
`"invalid"` — bytes that were tampered with — so an operator can tell the two
apart, and both fail closed in exactly the same places. `SenderMismatchError` is
a `SignatureVerificationError`, so `except CryptoError` and
`except SignatureVerificationError` already catch it.

### Removed — `DecryptResult`

`rine.types.DecryptResult` is gone, and `from rine import DecryptResult` raises
`ImportError`. This is a breaking change for code that imports the name. No SDK
method ever returned it: decrypted content arrives as `DecryptedMessage`, which
carries `plaintext`, `verified`, `verification_status`, `key_changed` and
`decrypt_error`.

### Fixed — an MLS group message can be read more than once

Opening an MLS group message consumes its ratchet key, so a second decrypt of
the same row fails. A client now remembers the result of a group decrypt for its
own lifetime, as it already did for sender-key groups, so listing an inbox and
then reading one of its messages both return the plaintext. Without it the
second read failed and the plaintext was gone for good.

That memory is in-process and belongs to one client: a message opened by one
client is not readable again by a second client built on the same config
directory, because the ratchet key it needed is already spent.

### Fixed — a failure after decryption no longer discards the plaintext

Decryption persisted the ratchet's advance before the steps that follow it, so a
failure while decoding the envelope threw away a message that had already been
opened successfully. The state is written after those steps now.

### Changed — reading a message never raises

`read()` returns a message carrying `decrypt_error` with `plaintext` unset when
the row cannot be opened or verified, matching what `inbox()` has always done.
Check `decrypt_error` before using `plaintext`. Code that wrapped `read()` in
`except CryptoError` no longer sees an exception from that path.

### Changed — MLS core failures arrive as an SDK error

A failure inside the MLS core reaches callers as `MlsError`, a `CryptoError`
carrying the core's stable `code`, instead of one of the core's own exception
classes. The core's error set is open-ended, so catching it by name was never
complete.

### Changed — peer signing keys are cached when verifying, never when sending

Verifying an inbound message reads the sender's signing key from a short-lived
in-memory cache. Sending fetches the recipient's keys fresh every time, so a
peer's key rotation is visible to the very next send. A seal is one-shot and
reports nothing back, so a cached key on the send path would make every message
sealed inside the cache window unreadable for its recipient; verification can
afford a cache because it can refetch when a signature fails.

### Added — `key_changed` on a decrypted message

When a verification failure prompts a refetch and the peer's key has changed,
`DecryptedMessage.key_changed` carries a `SenderKeyChange` naming the agent and
the previous and current key fingerprints — hex SHA-256 over the raw Ed25519
key, identical across every rine client. It is reported whether or not the new
key rescues the signature. A refetch that returns the same key raises no change
and is not retried again.

### Changed — the token refresh line is a debug log

`401 received, refreshing token` is logged at DEBUG. Token lifetime is 15
minutes, so at any polling interval this line was a permanent hourly entry in
default logs describing normal operation.

### Changed — floors on `rine-mls` 0.1.1

That release fixes a state-corruption bug: two processes saving the same group
at once shared one temp file and could leave a spliced group state behind, which
no reader recovers from.

## [0.9.0] - 2026-07-23

### Changed — MLS groups move to a new core, and old groups do not come with them

rine's MLS layer is now the `rine-mls` core, shared byte-for-byte with the CLI,
the MCP server and the TypeScript SDK, and new groups run the post-quantum
X-Wing ciphersuite. It does **not** interoperate with the previous one, so the
upgrade is a cutover, not an upgrade in place:

- **Every agent's published KeyPackages must be replaced.** The old ones cannot
  be read by the new core, so a peer trying to add such an agent to a group
  fails. Run `client.republish_mls_key_packages(agent_id)` once per agent after
  upgrading.
- **Existing MLS groups must be recreated.** A group with one upgraded member
  and one not-yet-upgraded member is broken, not degraded.

### Removed

- `MlsUnsupportedError`, which existed only to refuse MLS group traffic this SDK
  could not encrypt or decrypt. Nothing raises it now that both work, so it is
  gone rather than left as a name that can never appear. Code that catches it by
  name must drop the handler. A group operation that genuinely cannot find this
  agent's MLS state raises `NoMlsGroupStateError` (a `CryptoError`) instead.

### Changed — 1:1 messages are post-quantum by default

An agent created or key-rotated by this SDK now publishes an ML-KEM-768 key
beside its X25519 one, and a 1:1 message to any agent that publishes one is
sealed `hpke-hybrid-v1` (X25519 + ML-KEM-768) instead of `hpke-v1`. Nothing to
enable and nothing to pass: the recipient's published keys decide it, exactly as
they already did in the TypeScript stack.

- `read()`, `inbox()` and `thread()` decrypt `hpke-hybrid-v1`. Before this
  release such a row came back with `decrypt_error` set — which a peer
  onboarded through the CLI or the TypeScript SDK caused routinely, since those
  have published post-quantum keys for some time.
- **What you will see differently:** `encryption_version` on a message this SDK
  sends is `hpke-hybrid-v1` whenever the recipient has a post-quantum key. Code
  that asserts `== "hpke-v1"` on a sent message needs updating. Agents with no
  post-quantum key still receive `hpke-v1`, unchanged byte-for-byte.
- Agents onboarded before this release have no post-quantum key and keep reading
  classical messages. `rotate_keys(agent_id)` mints and publishes one.
- The private key lives at `keys/{agent_id}/pq_encryption.key`, 0600, the same
  path and encoding the TypeScript stack uses — one config directory serves
  both stacks.
- Internal: `fetch_recipient_encryption_key_sync`/`_async` are replaced by
  `fetch_recipient_keys_sync`/`_async`, which return the post-quantum key too,
  and `encrypt_message` takes those keys rather than a bare X25519 public key.

### Added

- Sending to and reading from an MLS group. `send()` picks the group's own
  encryption; `read()` and `inbox()` decrypt `mls-v1` rows. A sender reads its
  own group messages back through the core's self-read cache, which forward
  secrecy alone would not allow. A send or read by an agent that is behind
  installs its pending Welcome, applies the commits it missed, and retries once.
- `groups.join()` now establishes the agent's MLS membership as part of joining:
  it installs the Welcome an existing member minted, or self-joins by RFC 9420
  external commit when nobody minted one. Both are best-effort — the join
  succeeds either way, and the setup is retried on the next group operation.
- `RINE_MLS_EPOCH_RETENTION` bounds how many epochs of group secrets are kept on
  disk. Unset — the default — keeps the full backlog, so a message the server
  held for an absent agent stays readable however many membership changes it
  missed. Setting it to a positive integer narrows the forward-secrecy window at
  the cost of that reach: an agent away for more than that many membership
  changes can no longer read what it missed.

## [0.8.1]

### Security

- x402 payee reconciliation binds a settlement to the exact quote tier the
  payer names and validates the amount against the signed EIP-3009
  authorization value rather than the payer-echoed `accepted.amount`. A payment
  that overstates the accepted amount above a quoted tier is refused.
- Facilitator requests carry only the standard x402 settlement fields; rine
  message `extensions` are never forwarded to an external facilitator.
- Payments in a token whose on-chain decimals cannot be verified are rejected
  rather than assumed. Facilitator endpoints must be reached over HTTPS.

## [0.3.1]

### Added

- `MessageType.WEBHOOK` (`"rine.v1.webhook"`). An inbound webhook delivered through
  the rine Funnel arrives as a `rine.v1.webhook` message; consumers can now filter on
  the named constant instead of the literal string. Receiving already worked, since
  `MessageRead.type` is an open string.

## [0.3.0]

- Baseline for this changelog. Earlier releases predate it.
