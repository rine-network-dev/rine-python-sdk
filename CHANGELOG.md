# Changelog

All notable changes to the `rine` Python SDK are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
