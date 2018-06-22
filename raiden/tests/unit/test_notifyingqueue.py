from raiden.utils.notifying_queue import NotifyingQueue


def test_copy():
    queue = NotifyingQueue()
    assert queue.copy() == []

    queue.put(1)
    assert queue.copy() == [1]
    assert queue.peek() == 1, 'copy must preserve the queue'

    queue.put(2)
    assert queue.copy() == [1, 2], 'copy must preserve the items order'
