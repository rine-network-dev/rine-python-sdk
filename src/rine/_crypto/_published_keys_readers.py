"""The clients the seal path may read an agent's keys with: ``get`` and the pins, nothing else.

The narrow parameter type is what keeps the outbound-seal read off the client's key cache (see
:mod:`rine._crypto._agent_keys`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from rine._crypto._key_pins import KeyPins


class PublishedKeysReader(Protocol):
    """A client narrowed to the capabilities the seal path may use (sync)."""

    @property
    def key_pins(self) -> KeyPins:
        """The pins every key read is admitted to."""
        ...

    def get(self, path: str, **kwargs: Any) -> Any:
        """Perform an HTTP GET and return the decoded body."""
        ...


class AsyncPublishedKeysReader(Protocol):
    """A client narrowed to the capabilities the seal path may use (async)."""

    @property
    def key_pins(self) -> KeyPins:
        """The pins every key read is admitted to."""
        ...

    async def get(self, path: str, **kwargs: Any) -> Any:
        """Perform an HTTP GET and return the decoded body."""
        ...
