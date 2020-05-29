from raiden.utils.notifying_queue import NotifyingQueue


def add_element_to_queue(queue, element):
    queue.put(element)


def test_queue():
    queue = NotifyingQueue()
    assert queue.copy() == []

    queue.put(1)
    assert queue.copy() == [1]
    assert queue.peek() == 1, "copy must preserve the queue"

    queue.put(2)
    assert queue.copy() == [1, 2], "copy must preserve the items order"
    assert queue.peek() == 1, "copy must preserve the queue"

    assert queue.get() == 1, "get should return first item"
    assert queue.peek() == 2, "get must remove first item"


def test_not_empty():
    queue = NotifyingQueue()
    assert not queue.is_set()

    queue = NotifyingQueue(items=[1, 2])
    assert queue.is_set()
