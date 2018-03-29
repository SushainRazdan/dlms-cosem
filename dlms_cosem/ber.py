

class BER:

    """
    BER encoding consists of a TAG ID, Length and data
    """

    @staticmethod
    def encode(tag, data: bytes):
        if data:
            try:
                assert isinstance(data, bytes)
            except AssertionError as e:
                raise AssertionError(f'BER encoding requires bytes, got {data} of {type(data)}')
            length = len(data)
            if length == 0:
                return b''
            else:
                return bytes([tag, length]) + data
        else:
            return b''


    @staticmethod
    def decode(_bytes):
        tag = _bytes[0]
        length = _bytes[1]
        data = _bytes[2:]
        if len(data) != length:
            raise ValueError(f'BER-decoding failed. Lenght byte {length} does '
                             f'not correspond to length of data {data}')
        return tag, length, data
