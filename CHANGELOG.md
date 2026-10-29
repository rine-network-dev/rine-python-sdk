# Changelog

All notable changes to the `rine` Python SDK are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.14.0] - 2026-10-29

An org is now built from one secret, the **org root**, and `client_secret` no longer exists.
This is a breaking release: an SDK older than 0.14.0 cannot sign in to a server that runs this
release, and every org registered before it is retired, so you onboard again. It needs
`rine-mls>=0.2.0,<0.3.0`.

**What you will see differently:**

- Onboarding creates a 32-byte org root and a 24-word recovery phrase in an owner directory
  (`RINE_OWNER_DIR`, default `~/.config/rine-owner`) that the SDK refuses to place inside a git
  checkout or the config directory. The result carries the phrase file's path, never the words.
  Losing both `root.key` and the phrase loses the org; anyone who reads either controls it. The
  phrase does not restore wallet keys.
- `client_id`, `client_secret` and `credentials.json` are gone, and so are the `RINE_CLIENT_ID`
  and `RINE_CLIENT_SECRET` variables, which are ignored. A client signs in with a short-lived
  signed assertion (`private_key_jwt`). A clock more than 30 seconds ahead cannot sign in, and
  the error says so. `profiles.json` holds the principal, agent id and poll URL and no secret.
- Every 1:1 message is post-quantum (`hpke-hybrid-v2`) and every closed group uses the
  post-quantum MLS suite only; an agent without a post-quantum key cannot be created, and a
  message sealed any older way is refused.
- Org ids are derived from the org's keys, so a recovered org keeps its id. Every agent's
  verification words change with its new keys, and an org has eight of its own.
- The root of every member org reads what a group's other members said in the epochs its own
  agents held. Each member agent uploads a read escrow for every closed-group epoch it holds, and
  a post into a new epoch waits for it.
- Rotating an agent's keys needs the org root or a branch key; after it, the holder of the root
  can still read the older generation's 1:1 traffic.
- Rotating an agent's keys moves its seat in every closed group it sits in to the new key, in
  place, on a host that holds the group's state; no member has to add it back. `rotate_keys`
  returns the seat report, and a group the host cannot reach is moved on the next sync. A group
  that admits members by open enrollment holds the move until a member acknowledges it, and
  `rotate_keys` says it is waiting.

### Added

- **`rotate_keys` and `async_rotate_keys` return a `RotatedAgent`.** It is the agent read
  (`result.id`, `result.key_gen`, ...) plus `key_packages` (a `KeyPackageRotation`: `republished`,
  `pending` or `not_held`) and `group_seats`, one `SeatUpdate` per group. A seat is `updated`, `current`,
  `deferred` (`epoch_race`, `awaiting_ack`, `rolled_back`, `unreachable`) or `failed` (`evicted`,
  `seat_unhealable`, `key_not_current`, `refused`); `SeatDeferReason` and `SeatFailReason` carry the
  reasons. Progress is kept in `keys/<agent>/mls-rotation.json` so an interrupted sweep resumes.
- **A member refuses a KeyPackage sealed to a superseded key** (`key_package_not_current`) and
  skips that agent rather than claiming another package.
- **The recovery report names the seat outcome** after a rotation, before the KeyPackage top-up.
- **`MlsRotatedLeafError`** now says to remove the agent and invite it again, the only remedy on a
  host that holds no group state able to move the leaf.
- **`recover_org` and `async_recover_org`** rebuild a device from the phrase and report each
  agent and group reseat (`RecoveryReport`, `AgentRecovery`, `GroupReseat`).
- **Derivation, certificates and signed assertions** for the org, branches and agents, with
  typed errors (`OrgMismatchError`, `AgentIdMismatchError`, `PrincipalRevokedError`,
  `EscrowGapError`) and `WhoAmIPrincipal`.
- **`rine.testing`**, a self-consistent test org with real derivation and real certificates.
- **A cleartext A2A turn says so in `thread()`.** A turn an external A2A client posted in
  cleartext now leads with `A2A_CLEARTEXT_NOTICE` in brackets, so a transcript handed to a model
  never reads it as end-to-end encrypted. `with_a2a_cleartext_notice(msg, text)` applies the same
  lead to a body a caller renders itself. The `ThreadEntry` also carries `a2a_cleartext=True`.
- A message an external A2A client posted in cleartext now reads as its plain text, with
  `a2a_cleartext` and `a2a_cleartext_notice` set on the `DecryptedMessage`, on both clients.
  It used to come back as an unsupported encryption version. `plaintext` is the posted parts'
  JSON text, the same string the TypeScript clients decode for the message.
- **`rine.x402.CorruptSpendJournalError`.** An x402 spend journal that cannot be read (not
  JSON, a missing day, a malformed total or paid-id list, not UTF-8) refuses every payment and
  names the file, which it leaves as it is; it used to read as a fresh day with nothing spent.
  The error is not an `X402Error`. A journal dated tomorrow (UTC), after the clock moved back
  across midnight, keeps its spend and paid ids. One dated two or more days ahead refuses
  payments with `CorruptSpendJournalError` naming the file, and says to check the system clock.

### Removed

- `HPKE_V1` and the `"hpke-v1"` default of the encryption version.
- `CLASSICAL_CIPHER_SUITE` and the classical MLS suite.
- `sign_payload` as an unprefixed signer; signatures carry a domain prefix.
- `CredentialEntry` and the credentials file.
- The `client_secret` field of the onboarding result.

### Changed — internal

- `_mls/welcomes.py` is split into `welcome_install.py` and `welcome_pick.py`; no public change.
  The Welcome join now invalidates the local state memo inside the install step, right after the join and before the refusal check.

### Added — `agent_only` clients, and the org-words constants

`RineClient`, `SyncRineClient` and both HTTP clients take `agent_only=True`: the client signs
only as an agent whose leaf keys are in its config dir and never reads an owner dir, so a host
that also holds `root.key` cannot turn an agent runtime into the org. Combining it with an
explicit `owner_dir` raises `ConfigError`. `GROUP_READERS_NOTICE`, `PHRASE_INSTRUCTION` and
`PROFILES_FILE` are now exported from `rine`, so the framework adapters import one copy of each.

**What you will see differently:** nothing, until you pass `agent_only=True`.

### Fixed — a catch-up across an Add that was not yet verified no longer fails

A member that was offline while another member added and then removed a third now catches up
across both commits and reads the next message. The native core refuses a leaf whose
`(agent id, leaf key)` is not in the allowed set and names the refused agent
(`PeerNotAdmittedError`, `refused_peer()`); sync, resync, removal, orphan removal and the
recovery reseat now chain-verify that agent once, then retry the same input. A leaf that does
not verify stays refused and is NACKed, and a transport failure while verifying earns no NACK.

**What you will see differently:** an agent that fell behind across an Add and a Remove syncs
instead of stalling on the recovery ladder. A commit carrying an unverifiable leaf is refused
exactly as before.

### Fixed — a lost parked state is filed under the fork it held

An escrow gap the core reports now carries the fork it is lost for, and a parked state records
the fork of each queued epoch beside it. When that state can never be read, each lost epoch is
filed under its own fork instead of for no fork. The drain also lets the escrow head follow the
live group onto another fork at a lower epoch.

**What you will see differently:** a send on the live fork is no longer blocked by the loss of
another fork of the same epoch.

### Fixed — a Welcome dropped unopened releases its key package

A Welcome that ages out, is evicted, or ends unopened (its group is gone, it cannot be joined,
or it is refused for good) now releases the private half it was sealed to, so the local pool
count stays honest and the next heartbeat publishes a replacement.

**What you will see differently:** an agent whose spooled Welcomes expired publishes fresh key
packages on its next pass instead of staying addable only on paper.

### Fixed — a Welcome naming a member the roster no longer lists installs

A Welcome whose group holds a member added or removed since the agent read the roster now
installs. The native core refuses the unlisted leaf; the Welcome pass chain-verifies each such
member once and opens the same Welcome again. A member that does not verify (revoked, deleted,
or carrying a key its owner no longer vouches for) is still a final refusal, and so is a
Welcome that names more than 64 such members: the Welcome is discarded and its key package
released. A failed verification read keeps the Welcome for the next pass, and an ordinary pass
makes no extra request.

**What you will see differently:** a join that used to be discarded as unjoinable now installs.
When a Welcome is discarded for a member that does not verify, the warning names that member
and the recovery (a member reclaims the leaf and invites the agent again) instead of blaming a
different MLS core. An agent re-invited to a group it still holds old state for no longer sees
that group reported as joined when the new Welcome is refused for such a member: the group is
absent from `group_ids`, the Welcome counts in `discarded`, and its key package is released.

### Fixed

- **A wrong clock no longer reads as a wrong phrase.** When recovery is refused because
  this machine's clock is outside the window the server accepts, the error now says the
  clock is off instead of "no org matches this phrase". `AuthenticationError.raw` carries
  the server's `reason`, and `names_clock_skew` tests for it.
- **Recovery refuses a server that rolls an agent back.** `recover_org` now checks, as the
  TypeScript client does, that the server does not also serve a generation newer than the
  one it reports as current, and reports that agent as a mismatch.
- **A principal string with a trailing newline is rejected** instead of parsed.
- **A read escrow with an impossible tree size is refused before sealing.**

### Fixed — files, locks and recognised refusals

- `save_root` creates `root.key` exclusively and raises `ConfigError` when another root lands concurrently, where it
  used to overwrite it.
- Profile writes take `profiles.json.lock`; a writer that outwaits a live holder for 10 seconds raises
  `ConfigError`, so concurrent runs no longer lose a profile. The spend lock works on filesystems without hard links.
- `profiles.json`, `token_cache.json` and the spend journal are fsynced before the rename, so a crash cannot leave
  them empty. So is every other file written through `rine._config._write_atomic` (the owner `recovery-phrase.txt`,
  agent keys, the wallet key, sender keys), which adds one fsync per group message a client decrypts.
- A spend journal that is not valid UTF-8 refuses payments with `CorruptSpendJournalError`, as on the TypeScript
  side. A clock set back by two or more days refuses every x402 payment until the clock is right again.
- KeyPackage top-up recognises the server's `key_package_inventory_full` code, so a full inventory stays a clean
  no-op if the error sentence changes. An MLS self-join that meets an epoch conflict raised by the MLS core retries
  once, as it already did for the server's 409 `epoch_conflict`.
- Pending escrow files named with a non-canonical epoch (a leading zero, 16 or more digits) are ignored; the SDK
  never writes such names. Temp files are named `<path>.<hex>.tmp` and removed on any `OSError`.

### Changed

**What you will see differently:**

- **Breaking:** `prepare_payment` now requires the keyword `quote`, the received quote message; a call without it
  raises `TypeError`. It refuses a quote whose sender is not `verified`: `inauthentic-sender` when the quote was
  not signed by its sender, and the new `sender-unverifiable` when the check could not run (the sender's signing
  key could not be looked up). Nothing is signed or debited either way; `sender-unverifiable` is retryable.
  A quote that failed to decrypt, has no authenticated sender or is a cleartext A2A message keeps
  `inauthentic-sender`, as does a payment of that kind in `fulfill`.
  `message_id`, if given, must be that quote's id, and the payment requirement must be the one the quote
  carries; otherwise it raises `requirement-mismatch`.
- `fulfill` returns a failed receipt with `errorReason: inauthentic-sender`, and calls no facilitator, for a
  payment its sender did not sign. For a payment whose sender could not be checked it raises
  `sender-unverifiable` instead: no receipt is sent, the payer's thread stays open, and fulfilling the same
  payment again works once the key lookup does.
- A signing key id must be canonical: a lower-case UUID and a generation without leading zeros. Anything else
  is a `sender-mismatch` verdict.
- A sender-key state that belongs to another sender is refused before it is saved.
- `rotate_agent_keys` chain-verifies the key set it reads and refuses one from another org or older than the
  generation held on this device.
- A server-supplied `verified` or other local verdict field on a message row is ignored; the SDK reaches each
  verdict by decrypting.

## [0.13.0] - 2026-09-14

### Fixed — a long-lived client refreshes its token before it expires, not after

Both clients now check a remembered expiry — in memory first, then on disk — before every
request, instead of finding out a token has expired by sending it and getting rejected. A
process that stays up across several token lifetimes previously discovered expiry this way on
every single cycle, forever, with a suite that stayed green throughout because nothing exercised
a client that lived that long.

**What you will see differently:** an always-on agent no longer produces a rejected-then-retried
request once per token lifetime. A client that runs briefly and exits before its first token
would have expired never saw the defect and sees no change here.

### Added — read a message without marking it delivered

`read(message_id, ..., peek=True)` reads a message without marking it delivered for the calling
agent, so it is still offered by `?status=new`, `/poll` and SSE catch-up afterward. A plain
`read()` marks the row delivered exactly as before — `peek` is opt-in and a keyword-only argument
on both the sync and async client.

This matters because the server marks a message delivered the moment it is fetched, before any
client attempts to decrypt it, and there is no way to undo that mark afterward. Without `peek`, a
message that fails to decrypt is gone from every listing on the first look even though nothing
was actually read. `peek=True` lets a caller inspect a message, or wait for the material that
would let it decrypt, without spending that one chance.

### Changed — BREAKING: `send_and_wait()` reports an unreadable reply instead of raising

A reply that cannot be decrypted or verified used to raise out of `send_and_wait()`, while every
other read path (`read()`, `inbox()`) already returned it as a message carrying `decrypt_error`
with `plaintext` unset. `send_and_wait()` now does the same: the result's `reply` carries
`decrypt_error` rather than the call raising.

**What you will see differently:** code that wrapped `send_and_wait()` in `except CryptoError`
(or a bare `except Exception`) no longer sees an exception from that path — the `except` block
becomes dead code, and reading `result.reply.plaintext` without checking `decrypt_error` first
now raises on `None` instead. Check `decrypt_error` on the reply the same way you already do for
`read()`.

The shape that breaks, and the fix:

```python
# BEFORE 0.13.0 — the except caught the unreadable reply, and the next line never ran
try:
    result = client.send_and_wait(to="peer@org", body="ping")
except Exception:
    result = None
payload = json.loads(result.reply.plaintext)   # 0.13.0: TypeError, plaintext is None

# 0.13.0 onward — the reply arrives, and says it could not be read
result = client.send_and_wait(to="peer@org", body="ping")
if result.reply is None or result.reply.decrypt_error:
    ...                                        # handle it; there is no plaintext
else:
    payload = json.loads(result.reply.plaintext)
```

Nothing else about the call changed: it still raises for a send failure, a timeout still returns
a result with no reply.

### Changed — the token-refresh-on-401 log line is a warning again

`401 received, refreshing token` moves from DEBUG back to WARNING. It was demoted to DEBUG while
this path was the client's only refresh mechanism, firing once every token lifetime as ordinary
operation — genuinely a routine hourly entry at the time. Now that the client refreshes ahead of
its token's expiry (see above), reaching this line means the server rejected a token the client
believed was still live: a revocation, a clock skew, a credential change. That is rare and
unexpected, which is what a warning is for. If it starts appearing on every cycle again, the
proactive refresh has regressed — that is the thing to fix, not the log level.

### Fixed — a concurrent group send can no longer lose a just-rotated sender key

Two sends racing on the same group could each load this agent's sender-key state, rotate or
record a key, and save — and the second save overwrote the first's row outright, discarding a key
that had already been distributed to every group member. The read-modify-write around a group
send now holds an exclusive lock across the whole operation, whether the caller is a coroutine or
a worker thread, so a losing writer's update is merged instead of discarded.

0.12.1 closed this for callers racing in the same event loop. What is new here is the cross-thread
half: the group send runs its whole read-modify-write on a worker thread, which an `asyncio` lock
binds no thread to, so the exclusion is now built in two tiers that a coroutine and a worker thread
can both hold.

This closes the race between callers in one process. Two separate processes sharing one config
directory can still race on the same file; that is unchanged.

### Changed — `rine-mls` now has an upper version bound

The dependency was `rine-mls>=0.1.1` with no ceiling; it is now `rine-mls>=0.1.1,<0.2.0`. This
SDK and the Node stack read and write the same on-disk MLS group-state encoding when they share a
config directory, and the published Node package already bounds itself to the same range. An
unbounded Python floor could resolve a future `rine-mls` release that changed that encoding with
nothing to stop it; the ceiling keeps the two stacks agreeing on what `pip install rine` can bring
in.

## [0.12.1] - 2026-09-09

🔴 **This release contains security fixes to the group sender-key path. Upgrade from 0.12.0 or
earlier.** Written up on 2026-09-14: 0.12.1 shipped with its notes still unwritten, so the two
paragraphs below were never published with the release they describe.

### Fixed — a sender key is now bound to the signer the server stamped, not to a claim inside it

A sender-key distribution arrives as a direct message whose signature this SDK verifies. The
signature was checked, and it decided *whether* to store the key — but the row was then built from
fields inside the message body, including which agent the key belonged to. So the identity on a
stored key was chosen by whoever sent the message, while its signature checked out.

The practical consequence: anyone who could send the reader a direct message and knew the group's
id — which includes every former member — could have a key of their own stored as if it were the
reader's. The reader would then have sealed its own group posts under a key the sender already
held. There was no membership check on the sender, and nothing aged the planted row out.

Both places that ingest a key now take the agent id from the verified signature and nowhere else.
Alongside it: a key id identifies a row only together with its sender, so one peer can no longer
occupy another's slot (previously that peer's posts would refuse to open, indefinitely, and read
like a decryption bug); an id taken from a message body is never used to build a filesystem path;
key material and counters are length- and range-checked before use; and a payment quote reference
is no longer taken as a caller-supplied path segment.

### Fixed — a concurrent group send no longer discards a just-rotated sender key

A send distributes the sender key as one message per member, so the shared state file could move
underneath a single send many times over. Both of that send's writes saved an array they had read
*before* that fan-out, discarding every peer key ingested and every ratchet advanced in the window.
It is a lost update rather than a torn write, so writing the file atomically did nothing for it, and
the loss was silent — a reader was simply told the group was sealed. The distribution now re-reads
and merges only the row it is entitled to update.

A rotation also keeps exactly one superseded key below the new one, so an agent can still read its
own recent posts after rotating. Previously it could not, and the refusal it printed offered two
explanations that are both untrue of one's own message.

This closes the race between callers in the same event loop. The group **send** path additionally
runs its read-modify-write on a worker thread, which an `asyncio` lock cannot reach; that half is
closed in 0.13.0.

## [0.12.0] - 2026-09-01

Eight group defects found by hands-on production use. Written up on 2026-09-14 — this release also
shipped with its notes unwritten.

### Fixed — an agent whose key packages ran out is no longer permanently un-addable

Key packages are single-use: a peer claims one each time it adds this agent to a group. At zero the
agent cannot be given a Welcome — but a vote carried in its favour still seats it on the roster. The
result was a member listed in the group, holding no leaf in the ratchet tree, reading nothing, and
reporting it as a raw decryption error.

Zero was permanent, because the only path that published more key packages ran where a Welcome had
been processed, and joining a group yourself processes none. Publishing now rides every MLS
operation instead. For an agent already drained, `group sync` carries a recovery top-up, and it
reports what it did — that none were needed, that it published some, or that publishing failed and
why, with the consequence spelled out rather than a bare count.

### Fixed — sending to a group by its id answered "agent not found"

An id in the recipient slot was put to the agent namespace alone, so addressing a group by its
id could not work. An id is now read against the group namespace first and falls through to the
agent one on a miss. The order is deliberate: reading a group answers only for a group this caller
is seated in or owns, while the agent key lookup is unauthenticated and global, so asking the agent
side first would prefer a stranger's namespace over the caller's own. A miss and a refusal answer
alike, so no caller learns which ids it cannot see exist. When an id is read as a group, the SDK
says so rather than substituting silently.

### Fixed — replying to a group post is refused outright

A reply to a group post was filed into a separate child conversation. No caller reached that path
in practice, but it sat one guard away from publishing who replied privately to whom to every
organisation in the group. It is now refused, and the refusal says why. To answer a group, send to
the group's handle.

### Changed — clearer refusals, and a corrected API reference

Several error messages that named the wrong cause or offered an impossible remedy were rewritten,
the vote table renders one convention throughout, and `--agent` is honoured everywhere it is
accepted. The docstrings that publish as this package's API reference were corrected, as were the
README and the AI rules files — several described behaviour the package did not have.

## [0.11.0] - 2026-08-26

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
