from dlms_cosem.ber import BER

class DLMSObjectIdentifier:
    """
    The DLMS Association has been assigned a prefix for all of its OBJECT
    IDENDIFIERS
    """
    tag = 6
    prefix = b'\x60\x85\x74\x05\x08'


class AppContextNameOId(DLMSObjectIdentifier):
    """
    This defines how to reference objects in the meter and if ciphered APDU:s
    are allowed.

    """
    # TODO: Can this be a bit more generalized??
    app_context = 1

    valid_context_ids = [1, 2, 3, 4]

    def __init__(self, logical_name_refs=True, ciphered_apdus=True):

        self.logical_name_refs = logical_name_refs
        self.ciphered_apdus = ciphered_apdus
        self.context_id = self.calculate_context_id()

    @classmethod
    def from_bytes(cls, _bytes):

        data = bytearray(_bytes)
        tag = data.pop(0)
        if tag != DLMSObjectIdentifier.tag:
            raise ValueError('Tag of {tag} is not a valid tag for '
                             'ObjectIdentifiers')

        length = data.pop(0)
        if length != len(data):
            raise ValueError('Length of data is not as length byte')

        context_id = data[-1]
        if context_id not in AppContextNameOId.valid_context_ids:
            raise ValueError(f'context_id of {context_id} is not valid')

        total_prefix = bytes(data[:-1])
        print(total_prefix)
        print((DLMSObjectIdentifier.prefix +
                            bytes([AppContextNameOId.app_context])))
        if total_prefix != (DLMSObjectIdentifier.prefix +
                            bytes([AppContextNameOId.app_context])):
            raise ValueError(f'Static part of object id it is not correct'
                             f' according to DLMS: {total_prefix}')
        settings_dict = AppContextNameOId.get_settings_by_context_id(context_id)
        return cls(**settings_dict)

    def to_bytes(self):
        total_data = self.prefix + bytes([self.app_context, self.context_id])
        return BER.encode(self.tag, total_data)

    def calculate_context_id(self):
        if self.logical_name_refs and not self.ciphered_apdus:
            return 1
        elif not self.logical_name_refs and not self.ciphered_apdus:
            return 2
        elif self.logical_name_refs and self.ciphered_apdus:
            return 3
        elif not self.logical_name_refs and self.ciphered_apdus:
            return 4

    @staticmethod
    def get_settings_by_context_id(context_id):
        settings_dict = {
            1: {'logical_name_refs': True, 'ciphered_apdus': False},
            2: {'logical_name_refs': False, 'ciphered_apdus': False},
            3: {'logical_name_refs': True, 'ciphered_apdus': True},
            4: {'logical_name_refs': False, 'ciphered_apdus': True},
        }
        return settings_dict.get(context_id)

    def __repr__(self):
        return (f'AppContextNameOId \n'
                f'\t\t logical_name_refs = {self.logical_name_refs} \n'
                f'\t\t ciphered_apdus = {self.ciphered_apdus}')



class AARQAPDU():
    """
      AARQ_apdu ::= [APPLICATION 0] IMPLICIT SEQUENCE {
      protocol_version [0] IMPLICIT BIT STRING OPTIONAL,
      application_context_name          [1]  EXPLICIT OBJECT IDENTIFIER,
      called_AP_title                   [2]  AP_title OPTIONAL,
      called_AE_qualifier               [3]  AE_qualifier OPTIONAL,
      called_AP_invocation_identifier   [4]  EXPLICIT AP_invocation_identifier OPTIONAL,
      called_AE_invocation_identifier   [5]  EXPLICIT AE_invocation_identifier OPTIONAL,
      calling_AP_title                  [6]  AP_title OPTIONAL,
      calling_AE_qualifier              [7]  AE_qualifier OPTIONAL,
      calling_AP_invocation_identifier  [8]  AP_invocation_identifier OPTIONAL,
      calling_AE_invocation_identifier  [9]  AE_invocation_identifier OPTIONAL,
      --  The following field shall not be present if only the Kernel is used.
      sender_acse_requirements          [10] IMPLICIT ACSE_requirements OPTIONAL,
      --  The following field shall only be present if the Authentication functional unit is selected.
      mechanism_name                    [11] IMPLICIT Mechanism_name OPTIONAL,
      --  The following field shall only be present if the Authentication functional unit is selected.
      calling_authentication_value      [12] EXPLICIT Authentication_value OPTIONAL,
      application_context_name_list
        [13] IMPLICIT Application_context_name_list OPTIONAL,
      --  The above field shall only be present if the Application Context Negotiation functional unit is selected
      implementation_information        [29] IMPLICIT Implementation_data OPTIONAL,
      user_information [30] EXPLICIT Association_information OPTIONAL
    }
    """
    tag = 96  # Application 0 = 60H = 96
    # TODO: Use NamedTuple
    tags = {
        160: ('protocol_version', None),  # Context specific, constructed? 0
        161: ('application_context_name', AppContextNameOId),  # Context specific, constructed 1
        162: ('called_ap_title', None),
        163: ('called_ae_qualifier', None),
        164: ('called_ap_invocation_identifier', None),
        165: ('called_ae_invocation_identifier', None),
        166: ('calling_ap_title', None),
        167: ('calling_ae_qualifier', None),
        168: ('calling_ap_invocation_identifier', None),
        169: ('calling_ae_invocation_identifier', None),
        170: ('sender_acse_requirements', None),
        171: ('mechanism_name', None),
        172: ('calling_authentication_value', None),
        189: ('implementation_information', None),
        190: ('user_information', None)  # Context specific, constructed 30
    }

    def __init__(self,
                 protocol_version=1,
                 application_context_name=None,
                 called_ap_title=None,
                 called_ae_qualifier=None,
                 called_ap_invocation_identifier=None,
                 called_ae_invocation_identifier=None,
                 calling_ap_title=None,
                 calling_ae_qualifier=None,
                 calling_ap_invocation_identifier=None,
                 calling_ae_invocation_identifier=None,
                 sender_acse_requirements=None,
                 mechanism_name=None,
                 calling_authentication_value=None,
                 implementation_information=None,
                 user_information=None,
                 raw_bytes=None):

        self.protocol_version = protocol_version
        self.application_context_name = application_context_name
        self.called_ap_title = called_ap_title
        self.called_ae_qualifier = called_ae_qualifier
        self.called_ap_invocation_identifier = called_ap_invocation_identifier
        self.called_ae_invocation_identifier = called_ae_invocation_identifier
        self.calling_ap_title = calling_ap_title
        self.calling_ae_qualifier = calling_ae_qualifier
        self.calling_ap_invocation_identifier = calling_ap_invocation_identifier
        self.calling_ae_invocation_identifier = calling_ae_invocation_identifier

        # if this is 1 authentication is used.
        self.sender_acse_requirements = sender_acse_requirements
        # these 2should not be present if authentication is not used.
        self.mechanism_name = mechanism_name
        self.calling_authentication_value = calling_authentication_value

        self.implementation_information = implementation_information
        self.user_information = user_information

        self._raw_bytes = raw_bytes

    @classmethod
    def from_bytes(cls, aarq_bytes):
        # put it in a bytearray to be able to pop.
        aarq_data = bytearray(aarq_bytes)

        aarq_tag = aarq_data.pop(0)
        if not aarq_tag == cls.tag:
            raise ValueError('Bytes are not an AARQ APDU. TAg is not int(96)')

        aarq_length = aarq_data.pop(0)

        if not len(aarq_data) == aarq_length:
            raise ValueError('The APDU Data lenght does not correspond '
                             'to length byte')

        # Assumes that the protocol-version is 1 and we don't need to decode it

        # Decode the AARQ  data
        object_dict = dict()
        object_dict['raw_bytes'] = aarq_bytes

        # use the data in tags to go through the bytes and create objects.
        while True:
            object_tag = aarq_data.pop(0)
            object_desc = AARQAPDU.tags.get(object_tag, None)
            if object_desc is None:
                raise ValueError(f'Could not find object with tag {object_tag} '
                                 f'in AARQ definition')

            object_length = aarq_data.pop(0)
            object_data = bytes(aarq_data[:object_length])
            aarq_data = aarq_data[object_length:]

            object_name = object_desc[0]
            object_class = object_desc[1]

            if object_class is not None:
                object_data = object_class.from_bytes(object_data)

            object_dict[object_name] = object_data

            if len(aarq_data) <= 0:
                break

        return cls(**object_dict)

    def to_bytes(self):
        # if we created the object from bytes we can just return the same bytes
        #if self._raw_bytes is not None:
        #    return self._raw_bytes
        aarq_data = bytearray()
        # default value of protocol_version is 1. Only decode if other than 1
        if self.protocol_version != 1:
            aarq_data.extend(
                BER.encode(160, bytes(self.protocol_version))
            )
        if self.application_context_name is not None:
            aarq_data.extend(
                BER.encode(161, self.application_context_name.to_bytes())
            )
        if self.called_ap_title is not None:
            aarq_data.extend(
                BER.encode(162, self.called_ap_title)
            )
        if self.called_ae_qualifier is not None:
            aarq_data.extend(
                BER.encode(163, self.called_ae_qualifier)
            )
        if self.called_ap_invocation_identifier is not None:
            aarq_data.extend(
                BER.encode(164, self.called_ap_invocation_identifier)
            )
        if self.called_ae_invocation_identifier is not None:
            aarq_data.extend(
                BER.encode(165, self.called_ae_invocation_identifier)
            )
        if self.calling_ap_title is not None:
            aarq_data.extend(
                BER.encode(166, self.calling_ap_title)
            )
        if self.calling_ae_qualifier is not None:
            aarq_data.extend(
                BER.encode(167, self.calling_ae_qualifier)
            )
        if self.calling_ap_invocation_identifier is not None:
            aarq_data.extend(
                BER.encode(168, self.calling_ap_invocation_identifier)
            )
        if self.calling_ae_invocation_identifier is not None:
            aarq_data.extend(
                BER.encode(169, self.calling_ae_invocation_identifier)
            )
        if self.sender_acse_requirements is not None:
            aarq_data.extend(
                BER.encode(170, self.sender_acse_requirements)
            )
        if self.mechanism_name is not None:
            aarq_data.extend(
                BER.encode(171, self.mechanism_name)
            )
        if self.calling_authentication_value is not None:
            aarq_data.extend(
                BER.encode(172, self.calling_authentication_value)
            )
        if self.implementation_information is not None:
            aarq_data.extend(
                BER.encode(189, self.implementation_information)
            )
        if self.user_information is not None:
            aarq_data.extend(
                BER.encode(190, self.user_information)
            )

        return BER.encode(self.tag, bytes(aarq_data))

        # TODO: make BER.encode handle bytes or bytearray to save code space.
        # TODO: CAn we use an orderedDict to loopt through all elemetns of the aarq to be transformed.


        # TODO: Add encoding of all values from ground up.

    def __repr__(self):
        return (
            f'AARQ APDU \n'
            f'\t protocol_version = {self.protocol_version} \n'
            f'\t application_context_name = {self.application_context_name} \n'
            f'\t called_ap_title = {self.called_ap_title} \n'
            f'\t called_ae_qualifier = {self.called_ae_qualifier} \n'
            f'\t called_ap_invocation_identifier = '
            f'{self.called_ap_invocation_identifier} \n'
            f'\t called_ae_invocation_identifier = '
            f'{self.called_ae_invocation_identifier} \n'
            f'\t calling_ap_title = {self.calling_ap_title} \n'
            f'\t calling_ae_qualifier = {self.calling_ae_qualifier} \n'
            f'\t calling_ap_invocation_identifier = '
            f'{self.calling_ap_invocation_identifier} \n'
            f'\t calling_ae_invocation_identifier = '
            f'{self.calling_ae_invocation_identifier} \n'
            f'\t sender_acse_requirements = {self.sender_acse_requirements} \n'
            f'\t calling_authentication_value = '
            f'{self.calling_authentication_value} \n'
            f'\t implementation_information = '
            f'{self.implementation_information}\n'
            f'\t user_information = {self.user_information}'
        )
