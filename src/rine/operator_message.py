"""Classify a :class:`~rine.types.DecryptedMessage` the way a surface hands it to a model.

The classifier works on a decrypt outcome; a client method returns a decrypted message. This
is the one adapter between them, so a connector never rebuilds a :class:`DecryptResult` by
hand, and a row that was sent by this agent, never opened, or posted to a group is data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._crypto.message import DecryptResult
from rine.operator_classify import (
    UNOPENED_VERDICT,
    OperatorRowInput,
    OperatorVerdict,
    classify_operator_row,
)

if TYPE_CHECKING:
    from rine.operator_classify import OperatorContext
    from rine.types import DecryptedMessage

_NOT_RECEIVED = OperatorVerdict("other", "not_direct")


def classify_message(
    ctx: OperatorContext, msg: DecryptedMessage, *, renders_text: bool
) -> OperatorVerdict:
    """The verdict for ``msg``. ``renders_text`` is true when the caller shows its body to a model.

    Only a received row with a sender is ever a candidate; an unopened row is data.
    """
    if msg.direction == "sent" or msg.from_agent_id is None:
        return _NOT_RECEIVED
    if msg.plaintext is None or msg.decrypt_error is not None:
        return UNOPENED_VERDICT
    result = DecryptResult(
        msg.plaintext,
        "",
        msg.verified,
        msg.verification_status,
        msg.verifying_key,
    )
    return classify_operator_row(
        ctx,
        OperatorRowInput(
            row_id=str(msg.id),
            from_agent_id=str(msg.from_agent_id),
            encryption_version=msg.encryption_version,
            encrypted_payload=msg.encrypted_payload,
            result=result,
            renders_text=renders_text,
            context_only=msg.context_only,
        ),
    )
