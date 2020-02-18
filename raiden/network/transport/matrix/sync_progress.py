from datetime import datetime
from uuid import UUID

from gevent.event import Event

from raiden.utils.notifying_queue import NotifyingQueue
from raiden.utils.typing import Any, Dict, List, Optional, Tuple

JSONResponse = Dict[str, Any]


class SyncEvent(Event):
    """
    Sync Event is a slightly modified version of gevent's Event.
    It is used to indicate a sync loop for the long polling sync to matrix servers.
    When setting the event a list of response_tokens are passed as arguments.
    When waiting for the event the token gets passed to the recipient.
    This is supposed to help the recipient to be able to wait for a specific sync to be processed.
    """

    def __init__(self) -> None:
        super(Event, self).__init__()
        self.tokens: List[UUID] = list()

    def set(self, tokens: List[UUID]) -> None:
        self.tokens = tokens
        super().set()

    def wait(self, timeout: Optional[float] = None) -> Optional[List[UUID]]:
        super().wait()
        return self.tokens


class SyncProgress:
    """
    SyncProgress tracks the current progress of matrix's long polling sync.
    Its main purpose is to help controlled synchronization / providing information
    when writing integration tests
    A SyncProgress instance provides an interface to easily wait for a sync to be processed.
    Currently a response of a sync response can be still in the response_queue
    and is not be processed. This can lead to flaky tests on CI.
    Every response has a unique response token.
    Every token will run through the synced_event and processed_event
    cycle (set->wait) exactly once.

    Args:
        response_queue: queue for responses passed to the response_handler
        by the sync_request worker
    """

    def __init__(
        self, response_queue: NotifyingQueue[Tuple[UUID, JSONResponse, datetime]]
    ) -> None:
        self.synced_event = SyncEvent()
        self.processed_event = SyncEvent()
        self.sync_iteration = 0
        self.processed_iteration = 0
        self.last_synced: Optional[UUID] = None
        self.last_processed: Optional[UUID] = None
        self.response_queue = response_queue

    def set_synced(self, token: UUID) -> None:
        self.sync_iteration += 1
        self.last_synced = token
        self.synced_event.set([token])
        self.synced_event.clear()

    def set_processed(self, tokens: List[UUID]) -> None:
        self.processed_iteration += len(tokens)
        self.last_processed = tokens[-1]
        self.processed_event.set(tokens)
        self.processed_event.clear()

    def is_processed(self, response_token: UUID) -> bool:
        response_list = list(self.response_queue.queue.queue)
        for response_data in response_list:
            token = response_data[0]
            if token == response_token:
                return False
        return True

    def wait_for_processed(self, token: UUID, offset: int = 0) -> Optional[UUID]:
        counter = 0

        while not self.is_processed(token):
            processed_token = self.processed_event.wait()
            if token == processed_token:
                break

        while counter < offset:
            self.processed_event.wait()
            counter += 1

        return self.last_processed
