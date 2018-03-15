

class BER:

    """
    BER encoding consists of a TAG ID, Length and data
    """

    @staticmethod
    def encode(tag, data):
        assert isinstance(data, bytes)

        length = len(data)
        if length == 0:
            return b''
        else:
            return bytes([tag, length]) + data


