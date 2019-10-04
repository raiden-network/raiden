from dataclasses import dataclass

from eth_utils import to_hex

from raiden.exceptions import InvalidSignature
from raiden.messages.cmdid import CmdId
from raiden.utils.signer import Signer, recover
from raiden.utils.typing import Address, ClassVar, MessageID, Optional, Signature


@dataclass(repr=False, eq=False)
class Message:
    # Needs to be set by a subclass
    cmdid: ClassVar[CmdId]


@dataclass(repr=False, eq=False)
class AuthenticatedMessage(Message):
    """ Messages which the sender can be verified. """

    def sender(self) -> Optional[Address]:
        raise NotImplementedError("Property needs to be implemented in subclass.")


@dataclass(repr=False, eq=False)
class SignedMessage(AuthenticatedMessage):
    # signing is a bit problematic, we need to pack the data to sign, but the
    # current API assumes that signing is called before, this can be improved
    # by changing the order to packing then signing
    signature: Signature

    def __hash__(self):
        return hash((self._data_to_sign(), self.signature))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and hash(self) == hash(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "<{klass} [msghash={msghash}]>".format(
            klass=self.__class__.__name__, msghash=to_hex(hash(self))
        )

    def _data_to_sign(self) -> bytes:
        """ Return the binary data to be/which was signed

        Must be implemented by subclasses.
        """
        raise NotImplementedError

    def sign(self, signer: Signer):
        """ Sign message using signer. """
        message_data = self._data_to_sign()
        self.signature = signer.sign(data=message_data)

    @property
    def sender(self) -> Optional[Address]:
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
class RetrieableMessage:
    """ Message, that supports a retry-queue. """

    message_identifier: MessageID


@dataclass(repr=False, eq=False)
class SignedRetrieableMessage(SignedMessage, RetrieableMessage):
    """ Mixin of SignedMessage and RetrieableMessage. """

    pass
