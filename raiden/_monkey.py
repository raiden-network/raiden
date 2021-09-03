import asyncio.selector_events

import aioice.ice


def _patch_aioice() -> None:
    # local_candidate could be None so make sure we check for it before
    # invoking data_received
    def StunProtocol__connection_lost(self, exc: Exception) -> None:  # type: ignore
        self._StunProtocol__log_debug("connection_lost(%s)", exc)
        if self.local_candidate is not None:
            self.receiver.data_received(None, self.local_candidate.component)
        self._StunProtocol__closed.set_result(True)

    aioice.ice.StunProtocol.connection_lost = StunProtocol__connection_lost  # type: ignore


def _patch_asyncio() -> None:
    # don't do anything if the transport is closing/closed
    def wrap(orig):  # type: ignore
        def sendto(self, data, addr=None):  # type: ignore
            if not self._closing:
                orig(self, data, addr)

        return sendto

    orig = asyncio.selector_events._SelectorDatagramTransport.sendto  # type: ignore
    asyncio.selector_events._SelectorDatagramTransport.sendto = wrap(orig)  # type: ignore


def patch_all() -> None:
    _patch_aioice()
    _patch_asyncio()
