# -*- coding: utf-8 -*-
import pickle


class PickleSerializer:
    @staticmethod
    def serialize(transaction):
        # Some of our StateChange classes have __slots__ without having a __getstate__
        # As seen in the SO question below:
        # http://stackoverflow.com/questions/2204155/why-am-i-getting-an-error-about-my-class-defining-slots-when-trying-to-pickl#2204702
        # We can either add a __getstate__ to all of them or use the `-1` protocol and be
        # incompatible with ancient python version. Here I opt for the latter.
        return pickle.dumps(transaction, -1)

    @staticmethod
    def deserialize(data):
        return pickle.loads(data)
