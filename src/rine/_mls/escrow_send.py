"""The one retry an ``mls-v1`` post gets when its epoch's escrow is not stored.

The server answers a group post with 409 ``escrow_missing`` until the sender's
escrow for (group, epoch, fp) is uploaded. The send path drained before it
encrypted, so the escrow exists on disk: the answer is to upload what is pending
and post exactly once more. Any second failure, and every other error,
propagates unchanged. The TypeScript twin is ``rine-core/src/mls-escrow-send.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar

from rine._mls.bridge import with_sync_http
from rine._mls.escrow_drain import upload_pending_escrow
from rine._mls.heartbeat import MlsActor
from rine._mls.wire import api_error_code
from rine.errors import RineApiError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

T = TypeVar("T")

#: The server's ``error`` key for a post whose (group, epoch, fp) escrow is not stored.
ESCROW_MISSING = "escrow_missing"

_CONFLICT = 409


def is_escrow_missing(err: BaseException) -> bool:
    """Whether ``err`` is the server's 409 ``escrow_missing``."""
    return (
        isinstance(err, RineApiError)
        and err.status == _CONFLICT
        and api_error_code(err) == ESCROW_MISSING
    )


def post_with_escrow_retry(actor: MlsActor, group_id: str, post: Callable[[], T]) -> T:
    """Run ``post``; on 409 ``escrow_missing`` upload the pending escrow and post once more.

    Args:
        actor: The sending agent and its sync client.
        group_id: The group the message is posted to.
        post: Posts the message and returns the server's answer.

    Returns:
        Whatever ``post`` returns.
    """
    try:
        return post()
    except RineApiError as err:
        if not is_escrow_missing(err):
            raise
    upload_pending_escrow(actor, group_id)
    return post()


async def async_post_with_escrow_retry(
    client: Any, agent_id: str, group_id: str, post: Callable[[], Awaitable[T]]
) -> T:
    """The async twin of :func:`post_with_escrow_retry`.

    The upload is the sync flow's, run on a worker thread like the encrypt, so
    both clients retry through the same code.

    Args:
        client: The async client the post goes through.
        agent_id: The sending agent.
        group_id: The group the message is posted to.
        post: Posts the message and returns the server's answer.

    Returns:
        Whatever ``post`` returns.
    """
    try:
        return await post()
    except RineApiError as err:
        if not is_escrow_missing(err):
            raise
    await with_sync_http(
        client,
        lambda http: upload_pending_escrow(
            MlsActor(client=http, config_dir=client._config_dir, agent_id=agent_id), group_id
        ),
    )
    return await post()
