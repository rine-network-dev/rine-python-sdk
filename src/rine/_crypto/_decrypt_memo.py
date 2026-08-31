"""Per-client bounded memo of successful group-message decryptions.

Sender-key group decryption consumes a one-time ratchet key: decrypting the
same row twice fails with ``Message key expired or already consumed``. Any
surface that sees one row more than once — ``inbox()`` after ``read()``, or the
same row on two ``inbox()`` pages before mark-delivered — would therefore
surface an error where it had already surfaced plaintext.

Memoizing the successful result per ``(agent id, message id)`` makes a repeat
decrypt idempotent for the client's lifetime while leaving the ratchet's
forward-secrecy accounting untouched: consumed keys are still discarded, so a
fresh process cannot reopen an already-consumed message.

What is memoized is what a row's bytes said, never whom they are attributed to.
Attribution is decided per read, against the sender the server stamps on the row
that read fetched, so the callers re-check the binding on a memo hit rather than
keying it in here.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rine._crypto.message import DecryptResult


class DecryptMemo:
    """A bounded LRU memo of decrypt results keyed by agent id + message id.

    Args:
        max_entries: Maximum number of memoized messages before
            least-recently-used eviction.
    """

    def __init__(self, max_entries: int) -> None:
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str], DecryptResult] = OrderedDict()

    def get(self, agent_id: str, message_id: str) -> DecryptResult | None:
        """Return the memoized result for a message, or ``None`` if absent.

        A hit refreshes recency (LRU).

        Args:
            agent_id: Agent that decrypted the message.
            message_id: Message UUID.

        Returns:
            The memoized ``DecryptResult``, or ``None``.
        """
        key = (agent_id, message_id)
        entry = self._entries.get(key)
        if entry is None:
            return None
        self._entries.move_to_end(key)
        return entry

    def set(self, agent_id: str, message_id: str, result: DecryptResult) -> None:
        """Memoize a successful decrypt, evicting the LRU entry if over capacity.

        Args:
            agent_id: Agent that decrypted the message.
            message_id: Message UUID.
            result: Decrypt result to memoize.
        """
        key = (agent_id, message_id)
        self._entries[key] = result
        self._entries.move_to_end(key)
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
