

class BER:

    """
    BER encoding consists of a TAG ID, Length and data
    """

    @staticmethod
    def encode(tag, data):
        assert isinstance(data, bytes)

        length = len(data)
        return bytes([tag, length]) + data


