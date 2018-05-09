from amr_crypto.dlms.security import SecuritySuiteFactory
from dlms_cosem.ber import BER

class SecurityHeader:

    def __init__(self, security_control_field, invocation_counter):
        self.security_control_field = security_control_field
        self.invocation_counter = invocation_counter



class SecurityControlField:

    """
    Bit 3...0: Security_Suite_Id;
    Bit 4: “A” subfield: indicates that authentication is applied;
    Bit 5: “E” subfield: indicates that encryption is applied;
    Bit 6: Key_Set subfield: 0 = Unicast, 1 = Broadcast;
    Bit 7: Indicates the use of compression.
    """

    def __init__(self, security_suite, authenticated=False, encrypted=False,
                 broadcast=False, compressed=False,):
        self.security_suite = security_suite
        self.authenticated = authenticated
        self.encrypted = encrypted
        self.broadcast = broadcast
        self.compressed = compressed

        if security_suite not in [0, 1, 2]:
            raise ValueError('Only security suite of 0-2 is valid.')

    @classmethod
    def from_bytes(cls, _byte):
        assert isinstance(_byte, int)  # just one byte.
        _security_suite = _byte & 0b00001111
        _authenticated = bool(_byte & 0b00010000)
        _encrypted = bool(_byte & 0b00100000)
        _key_set = bool(_byte & 0b01000000)
        _compressed = bool(_byte & 0b10000000)
        return cls(_security_suite, _authenticated, _encrypted, _key_set,
                   _compressed)

    def to_bytes(self):
        _byte = self.security_suite
        if self.authenticated:
            _byte += 0b00010000
        if self.encrypted:
            _byte += 0b00100000
        if self.broadcast:
            _byte += 0b01000000
        if self.compressed:
            _byte += 0b10000000

        return _byte.to_bytes(1, 'big')


class Conformance:
    def __init__(self, _bytes):

        # TODO: Parse the bytes to get prpposed conformance
        self._bytes = _bytes

    @classmethod
    def from_bytes(cls, _bytes):
        return cls(_bytes)

    def to_bytes(self):
        return self._bytes

    def __repr__(self):
        return f'Conformance: {self._bytes}'


class InitiateRequestAPDU:
    """
    InitiateRequest ::= SEQUENCE {
    dedicated-key: OCTET STRING OPTIONAL
    response-allowed: BOOLEAN DEFAULT TRUE
    proposed-quality-of-service: IMPLICIT Integer8 OPTIONAL
    proposed-dlms-version-number: Integer8  # Always 6?
    proposed-conformance: Conformance
    client-max-receive-pdu-size: Unsigned16
    }

    """

    tag = 0x01  # initiateRequest XDLMS-APDU Choice.
    name = 'initiate-request'

    object_map = [
        {'attr': 'dedicated_key', 'encoding': 'x-ads', 'optional': True,
         'default': None, 'class_ref': 'bytes', 'length': None},
        {'attr': 'response_allowed', 'encoding': 'x-ads', 'optional': False,
         'default': True, 'class_ref': 'bool', 'length': 1},
        {'attr': 'proposed_quality_of_service', 'encoding': 'x-ads', 'optional': False,
         'default': None, 'class_ref': 'int', 'length': 1},
        {'attr': 'proposed_dlms_version_number', 'encoding': 'x-ads', 'optional': False,
         'default': None, 'class_ref': 'int', 'length': 1},
        {'attr': 'proposed_conformance', 'encoding': 'ber', 'optional': False,
         'default': None, 'class_ref': Conformance, 'length': 7},  # Might be 6 over HDLC because of compbility with old version.
        {'attr': 'client_max_receive_pdu_size', 'encoding': 'x-ads', 'optional': False,
         'default': None, 'class_ref': 'int', 'length': 2},


    ]

    # TODO: Cannot be default and optional at the same time!

    def __init__(self,
                 proposed_conformance,
                 client_max_receive_pdu_size,
                 proposed_quality_of_service,
                 proposed_dlms_version_number=6,
                 response_allowed=True,
                 dedicated_key=None):

        self.proposed_conformance = proposed_conformance
        self.client_max_receive_pdu_size = client_max_receive_pdu_size
        self.proposed_quality_of_service = proposed_quality_of_service
        self.proposed_dlms_version_number = proposed_dlms_version_number
        self.response_allowed = response_allowed
        self.dedicated_key = dedicated_key

    @classmethod
    def from_bytes(cls, _bytes: bytes):
        # There is weird decoding here since it is mixed X-ADS and BER....
        data = bytearray(_bytes)
        apdu_tag = data.pop(0)
        if apdu_tag != 0x01:
            raise ValueError(f'Data is not a InitiateReques APDU, got apdu tag {apdu_tag}')
        object_dict = dict()

        for decoding_rule in InitiateRequestAPDU.object_map:
            is_used = True
            is_default = False
            if decoding_rule['optional']:
                tag = data.pop(0)  # get the first byte in the array
                if tag == 0x00:
                    # 0x00 indicates that the optinal element is not used.
                    is_used = False
                elif tag == 0x01:
                    # 0x01 indicates that the optional elemnt is used.
                    is_used =True
                else:
                    raise ValueError(
                        f'Not possible to byte: {tag} to be other than 0x00 or '
                        f'0x01 when optional is set.')
            if decoding_rule['default'] is not None:
                tag = data.pop(0)  # get the first byte in the array
                if tag == 0x00:
                    # 0x00 indicates that the default value is used.
                    is_default = True
                elif tag == 0x01:
                    # 0x01 indicates that the default value is not used and
                    # we need to look for the real value.
                    is_default = False
                else:
                    raise ValueError(
                        f'Not possible to byte: {tag} to be other than 0x00 or '
                        f'0x01 when default is set.')
            if is_default:
                object_dict[decoding_rule['attr']] = decoding_rule['default']
                continue
            if not is_used:
                object_dict[decoding_rule['attr']] = None
                continue

            object_data = data[:decoding_rule['length']]
            data = data[decoding_rule['length']:]

            # TODO: this is not nice
            if decoding_rule['class_ref'] == 'int':
                object_instance = int.from_bytes(object_data, 'big')
            elif decoding_rule['class_ref'] == 'bool':
                object_instance = bool(object_data)
            elif decoding_rule['class_ref'] == 'str':
                object_instance = str(object_data)
            elif decoding_rule['class_ref'] == 'bytes':
                object_instance = bytes(object_data)
            else:
                object_instance = decoding_rule['class_ref'].from_bytes(object_data)
            object_dict[decoding_rule['attr']] = object_instance

        print(object_dict)
        print(f'data: {data}')

        return cls(**object_dict)

    def to_bytes(self):
        _bytes = bytearray()
        for decoding_rule in self.object_map:
            object_value = self.__getattribute__(decoding_rule['attr'])
            # is the object used?
            if object_value is None and decoding_rule['optional'] is True:
                object_bytes = b'\x00'

            # is the object the default value?
            elif object_value == decoding_rule['default']:
                object_bytes = b'\x00'

            else:
                if isinstance(object_value, int):
                    object_bytes = object_value.to_bytes(decoding_rule['length'], 'big')
                elif isinstance(object_value, bytes):
                    object_bytes = object_value
                elif isinstance(object_value, bool):
                    if object_value:
                        object_bytes = b'\x01'
                    else:
                        object_bytes = b'\x00'
                elif isinstance(object_value, str):
                    object_bytes = object_value.encode()
                else:
                    object_bytes = object_value.to_bytes()

            if object_value is not None and decoding_rule['optional'] is True:
                # should add 0x01 infront of the data
                object_bytes = b'\x01' + object_bytes

            _bytes.extend(object_bytes)

        return b'\x01' + bytes(_bytes)

    def __repr__(self):
        return (f'\n\t\t\tdedicated key = {self.dedicated_key}, '
                f'\n\t\t\tresponse_allowed = {self.response_allowed}, '
                f'\n\t\t\tproposed_quality_of_service = {self.proposed_quality_of_service}, '
                f'\n\t\t\tproposed_dlms_version_number = {self.proposed_dlms_version_number}, '
                f'\n\t\t\tproposed_conformance = {self.proposed_conformance} '
                f'\n\t\t\tclient_max_recieve_pdu_size: {self.client_max_receive_pdu_size}')



class GeneralGlobalCipherAPDU:

    tag = 219
    name = 'general-glo-cipher'

    def __init__(self, system_title, security_header, ciphered_apdu):
        self.system_title = system_title
        self.security_header = security_header
        self.apdu = None
        self.ciphered_apdu = ciphered_apdu

    def decrypt(self, encryption_key, authentication_key):
        if not (isinstance(encryption_key,
                           bytes) or  # TODO: this could be moved to beginning
                isinstance(authentication_key, bytes)):
            raise ValueError('keys must be in bytes')

        security_suite_factory = SecuritySuiteFactory(encryption_key)
        security_suite = security_suite_factory.get_security_suite(
            self.security_header.security_control_field.security_suite
        )  #TODO: Move to SecurityHeader class

        initialization_vector = self.system_title + self.security_header.invocation_counter
        add_auth_data = self.security_header.security_control_field.to_bytes() + authentication_key  # TODO: Document

        apdu = security_suite.decrypt(
            initialization_vector, self.ciphered_apdu, add_auth_data)

        self.apdu = apdu

        return apdu


    @classmethod
    def from_bytes(cls, _bytes, use_system_title_length_byte=False,
                   encryption_key=None, authentication_key=None):

        # some meter send the length of the system title. But is is supposed to
        # be A-XDR encoded so no need of length.
        # TODO: Just check if the first byte is 8.
        if use_system_title_length_byte:
            _bytes = _bytes[1:]

        system_title = _bytes[:8]

        ciphered_content = _bytes[8:]

        length = ciphered_content[0]
        ciphered_content = ciphered_content[1:]

        if length != len(ciphered_content):
            raise ValueError('The length of the ciphered content does not '
                             'correspond to the length byte')
        s_c_f = SecurityControlField.from_bytes(
            ciphered_content[0])

        if not s_c_f.encrypted and not s_c_f.authenticated:
            # if there is no protection there is no need for the invocation
            # counter. I don't know if that is something that would acctually
            # be sent in a  general-glo-cipher. If it is we have to implement
            # that then
            raise NotImplementedError(
                'Handling an unprotected APDU in a general-glo-cipher is not '
                'implemented (and maybe not a valid operation)'
            )

        elif s_c_f.authenticated and not s_c_f.encrypted:
            raise NotImplementedError(
                'Decoding a APDU that is just authenticated is not yet '
                'implemented'
            )

        elif s_c_f.encrypted and not s_c_f.authenticated:
            raise NotImplementedError(
                'Decoding a APDU that is just encrypted is not yet implemented'
            )

        elif s_c_f.encrypted and s_c_f.authenticated:

            invocation_counter = ciphered_content[1:5]
            security_header = SecurityHeader(s_c_f, invocation_counter)
            ciphered_apdu = ciphered_content[5:]


        else:
            raise ValueError(
                'Security Control Field {} is not correctly interpreted since '
                'we have no way of handling its options'.format(s_c_f)
            )

        if s_c_f.compressed:
            raise NotImplementedError(
                'Handling Compressed APDUs is not implemented'
            )

        return cls(system_title, security_header, ciphered_apdu)


class XDLMSAPDUFactory:

    apdu_classes = {
        0x01: InitiateRequestAPDU,
        219: GeneralGlobalCipherAPDU
    }

    def __init__(self):
        pass

    def apdu_from_bytes(self, apdu_bytes):
        tag = apdu_bytes[0]

        apdu_class = self.apdu_classes.get(tag)

        return apdu_class.from_bytes(apdu_bytes[1:], True)


apdu_factory = XDLMSAPDUFactory()




