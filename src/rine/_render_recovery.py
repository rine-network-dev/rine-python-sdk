"""One render's single chance to go looking for a missing sender key.

A transcript render carries N rows and the recovery it may need is **one**
untargeted scan: :meth:`rine._sync_client.SyncRineClient._fetch_pending_sk_distributions`
lists every pending ``rine.v1.sender_key_distribution`` for the acting agent and
ingests all of them, so a second scan in the same render can only re-read what
the first one already installed. Spending it once per *failing row* would turn a
transcript of eight unopenable rows into eight list calls plus eight fetches per
pending distribution — the cost this budget exists to keep off render paths —
and buy nothing after the first.

So the budget lives here, in the render, rather than inside the self-heal: the
self-heal is shared with ``inbox()`` and ``read()``, which each open **one**
listing's worth of rows and have no render to bound. The two hand-mirrored
clients both walk their rows sequentially, so one object passed down the loop is
the whole mechanism — no lock, no re-render pass, and every row after the scan
sees the state it installed.

⚠️ The TypeScript stacks do NOT hold this bound, and this budget is not a copy of
anything they do. Their renders are ``Promise.all`` over the rows
(``rine-ts-sdk/src/resources/thread.ts``), and both recovering readers —
``rine-core``'s ``decryptGroupMessageWithRecovery`` and ``rine-ts-sdk``'s
``retrySenderKey`` arm — call ``fetchAndIngestPendingSKDistributions`` per
failing row with no in-flight map behind it, so N unopenable rows fire N
concurrent scans. (``GroupDecryptMemo`` is a *result* cache keyed by
``(agentId, messageId)``, which answers a repeat read of the same row and
nothing about a second row's fetch.) Closing that is the TypeScript stacks' own
round; it is written down here because the next reader of this module will
otherwise assume parity that does not exist.
"""

from __future__ import annotations


class RenderRecovery:
    """The one distribution scan a render may spend, and who spent it.

    Not a boolean flag on the client: the budget belongs to a single
    ``thread()`` call, exactly as :class:`~rine.sender_key_words.SenderKeyRefusal`
    belongs to a single render. A client-level flag would leak across calls,
    across groups and across agents — the second transcript an operator reads
    would refuse to go looking because the first one already had.

    Usage, per render::

        recovery = RenderRecovery()
        ...
        if recovery.spend():
            row = self._self_heal_group_decrypt(agent_id, row, error)
    """

    __slots__ = ("_spent",)

    def __init__(self) -> None:
        """Start a render with its one scan unspent."""
        self._spent = False

    def spend(self) -> bool:
        """Claim the scan for this row, once per render.

        Returns:
            ``True`` for the first caller — which must then actually run the
            recovery — and ``False`` for every caller after it, whose row has
            already been offered everything the scan could install.
        """
        if self._spent:
            return False
        self._spent = True
        return True


__all__ = ["RenderRecovery"]
