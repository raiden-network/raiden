import pickle


class PickleSerializer:
    @staticmethod
    def serialize(transaction):
        return pickle.dumps(transaction, 4)

    @staticmethod
    def deserialize(data):
        return pickle.loads(data)
