"""High-level payer/payee flow helpers.

Ties the wallet, spend policy, signer, and message builders together so a caller
does the minimum:

- **Payer:** :func:`prepare_payment` — load wallet + policy + today's spend from
  disk, select an acceptable requirement, sign, seal the message, and **reserve
  the spend** as the final local act. The reservation is fail-closed: the daily
  budget is debited at signing, before the caller transmits, and the debit is
  permanent (no refund path). A crash or a failed send leaves the budget spent
  until UTC midnight; retrying the same message needs ``force=True``.
- **Payee:** quote with :func:`rine.x402.messages.build_payment_required`, verify
  and settle via :class:`rine.x402.facilitator.FacilitatorClient`, then wrap the
  settlement with :func:`rine.x402.messages.receipt_from_settlement`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine._crypto.wallet import load_wallet_key
from rine.x402.assets import requirement_canonical_amount
from rine.x402.journal import read_daily_spent, reserve_spend
from rine.x402.messages import X402Message, payment_message
from rine.x402.pay import build_payment_payload, select_requirement
from rine.x402.policy import is_auto_payable, load_policy

if TYPE_CHECKING:
    from rine.x402.types import PaymentRequired, PaymentRequirements


@dataclass
class PreparedPayment:
    """The result of :func:`prepare_payment` — signed message + accounting facts.

    ``auto_payable`` reflects the policy's ``autoPayThreshold``: a caller honoring
    ``--auto-pay`` sends without a human prompt only when this is ``True``.
    """

    message: X402Message
    requirement: PaymentRequirements
    canonical_amount: int
    auto_payable: bool


def prepare_payment(
    config_dir: str,
    agent_id: str,
    payment_required: PaymentRequired,
    *,
    message_id: str | None = None,
    force: bool = False,
    now: int | None = None,
    nonce: bytes | None = None,
    add_marker: bool = True,
) -> PreparedPayment:
    """Payer: select + sign a payment and reserve its spend (fail-closed).

    Loads the agent's spend policy (``None`` → deny-by-default), wallet key, and
    today's spend from disk, selects an acceptable requirement, signs, and seals
    the ``rine.v1.x402_payment`` message. As its FINAL local act it calls
    :func:`rine.x402.policy.reserve_spend`, which re-enforces policy and debits the
    daily journal atomically under a cross-process lock — so the budget is reserved
    at signing, before transmit, and the debit stands regardless of send outcome.

    ``message_id`` (the received ``payment_required`` message id) makes the debit
    idempotent per day: a second prepare for the same id raises ``already-paid``
    unless ``force=True``. It is ALSO stamped into the signed payload's
    ``extensions[X402_QUOTE_REF_KEY]`` so the payee can bind this payment to
    the ONE quote it answers; omitting it leaves the payment unbound and the payee
    then requires explicit expected terms to settle (fail closed). Raises
    :class:`rine.x402.errors.X402Error` if no
    requirement satisfies the policy, if the lock is contended (``wallet-busy``),
    or on a replay (``already-paid``).

    ``add_marker`` threads through to the built message so this high-level flow
    can emit a fully-sealed ``rine.v1.x402_payment`` (no cleartext status marker),
    matching the payer control the TS SDK's ``fulfill``/``sendReceipt`` expose.
    """
    policy = load_policy(config_dir, agent_id)
    daily_spent = read_daily_spent(config_dir, agent_id, now)
    requirement = select_requirement(payment_required, policy, daily_spent)
    wallet_key = load_wallet_key(config_dir, agent_id)
    payload = build_payment_payload(
        payment_required,
        requirement,
        wallet_key,
        now=now,
        nonce=nonce,
        quote_message_id=message_id,
    )
    message = payment_message(payload, add_marker=add_marker)
    auto_payable = policy is not None and is_auto_payable(policy, requirement)
    # Reserve LAST — the message is already signed and sealed; this is the final
    # local act before the caller transmits (fail-closed: the debit is permanent).
    reserve_spend(
        config_dir,
        agent_id,
        policy,
        requirement,
        message_id=message_id,
        force=force,
        now_seconds=now,
    )
    return PreparedPayment(
        message=message,
        requirement=requirement,
        canonical_amount=requirement_canonical_amount(requirement),
        auto_payable=auto_payable,
    )
