class InvalidArg(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class IdaError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
