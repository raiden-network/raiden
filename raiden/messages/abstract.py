from dataclasses import dataclass

from raiden.exceptions import InvalidSignature
from raiden.messages.cmdid import CmdId
from raiden.utils.signer import Signer, recover
from raiden.utils.typing import Address, Any, Callable, ClassVar, MessageID, Optional, Signature


class cached_property:
    """Same as functools.cached_property in python 3.8

    See https://docs.python.org/3/library/functools.html#functools.cached_property.
    Remove after upgrading to python3.8
    """

    def __init__(self, func: Callable) -> None:
        self.func = func
        self.__doc__ = func.__doc__

    def __get__(self, instance: Any, cls: Any = None) -> Any:
        if instance is None:
            return self
        attrname = self.func.__name__
        try:
            cache = instance.__dict__
        except AttributeError:  # objects with __slots__ have no __dict__
            msg = (
                f"No '__dict__' attribute on {type(instance).__name__!r} "
                f"instance to cache {attrname!r} property."
            )
            raise TypeError(msg) from None
        if attrname not in cache:
            cache[attrname] = self.func(instance)
        return cache[attrname]


@dataclass(repr=False, eq=False)
class Message:
    # Needs to be set by a subclass
    cmdid: ClassVar[CmdId]


@dataclass(repr=False, eq=False)
class AuthenticatedMessage(Message):
    """Messages which the sender can be verified."""

    def sender(self) -> Optional[Address]:
        raise NotImplementedError("Property needs to be implemented in subclass.")


@dataclass(repr=False, eq=False)
class SignedMessage(AuthenticatedMessage):
    # signing is a bit problematic, we need to pack the data to sign, but the
    # current API assumes that signing is called before, this can be improved
    # by changing the order to packing then signing
    signature: Signature

    def __hash__(self) -> int:
        return hash((self._data_to_sign(), self.signature))

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and hash(self) == hash(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ...>"

    def _data_to_sign(self) -> bytes:
        """Return the binary data to be/which was signed

        Must be implemented by subclasses.
        """
        raise NotImplementedError

    def sign(self, signer: Signer) -> None:
        """Sign message using signer."""
        message_data = self._data_to_sign()
        self.signature = signer.sign(data=message_data)

    @cached_property
    def sender(self) -> Optional[Address]:  # type: ignore
        if not self.signature:
            return None
        data_that_was_signed = self._data_to_sign()
        message_signature = self.signature

        try:
            address: Optional[Address] = recover(
                data=data_that_was_signed, signature=message_signature
            )
        except InvalidSignature:
            address = None
        return address


@dataclass(repr=False, eq=False)
class RetrieableMessage(Message):
    """Message, that supports a retry-queue."""

    message_identifier: MessageID


@dataclass(repr=False, eq=False)
class SignedRetrieableMessage(SignedMessage, RetrieableMessage):
    """Mixin of SignedMessage and RetrieableMessage."""

    pass
