"""The one place a model-facing row learns its sender class and its notice.

Every row a surface hands a model goes through :func:`frame_row`, on every arm including a
refused or unreadable one. The class and the notice are written last, so a value the server
or the sender put under the same key is overwritten, and the sender's own ``rine.operator``
field is removed from the decrypted body so a stranger's copy never reaches a model. Twin of
``rine-core/src/operator-frame.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine.control_frames import (
    OPERATOR_CONTENT_NOTICE,
    OPERATOR_HISTORY_NOTICE,
    UNTRUSTED_CONTENT_NOTICE,
)
from rine.operator_statement import strip_operator_statement

if TYPE_CHECKING:
    from collections.abc import Mapping

    from rine.operator_classify import OperatorVerdict, SenderClass

_NOTICES: dict[str, str] = {
    "operator": OPERATOR_CONTENT_NOTICE,
    "operator_history": OPERATOR_HISTORY_NOTICE,
    "other": UNTRUSTED_CONTENT_NOTICE,
}


def notice_for_class(sender_class: SenderClass) -> str:
    """The notice that frames a row of this class."""
    return _NOTICES[sender_class]


def frame_row(row: Mapping[str, Any], verdict: OperatorVerdict) -> dict[str, Any]:
    """A copy of ``row`` carrying ``sender_class`` and ``notice`` for ``verdict``.

    The statement field is stripped from ``decrypted``. The caller's row is not changed.
    """
    framed = dict(row)
    if "decrypted" in framed:
        framed["decrypted"] = strip_operator_statement(framed["decrypted"])
    framed["sender_class"] = verdict.sender_class
    framed["notice"] = notice_for_class(verdict.sender_class)
    return framed
