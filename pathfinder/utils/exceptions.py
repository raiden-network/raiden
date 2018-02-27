class InvalidSignatureError(ValueError):
    def __init__(self, *args) -> None:
        ValueError.__init__(self, *args)
