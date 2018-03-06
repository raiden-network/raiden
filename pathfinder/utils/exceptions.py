class InvalidAddressChecksumError(ValueError):
    def __init__(self, *args: object) -> None:
        ValueError.__init__(self, *args)
