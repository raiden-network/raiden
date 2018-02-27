class Lock(object):
    def __init__(self, amount_locked: int, lock_hash: str):
        self.amount_locked = amount_locked
        self.lock_hash = lock_hash
