from typing import *

import attr

from dlms_cosem.protocol.ber import BER

from dlms_cosem.protocol.acse import base as acse_base
from dlms_cosem.protocol import xdlms


def user_information_holds_initiate_request(
    instance, attribute, value: acse_base.UserInformation
):
    if not isinstance(value.content, xdlms.InitiateRequestApdu):
        raise ValueError(
            f"ApplicationAssociationRequestApdu.user_information should "
            f"only hold a UserInformation where .content is a "
            f"InitiateRequestApdu. Got {value.content.__class__.__name__}"
        )


@attr.s(auto_attribs=True)
class ApplicationAssociationRequestApdu:
    """
    Application Association Request ( AARQ ) is used for starting an Application
    Association with a DLMS server (meter).

    It is encoded in BER. This is due to many of
    the field are variable in length and it is hard to know the length of each field in
    advance.

    The user information field holds an InitiateRequestApdu encoded in X-ADR wrapped
    in BER encoded OCTET_STRING.

    If sender_acse_requirements is present authentication is used.

    mechanism_name and calling_authentication_value should only be present if
    authentication is used.

    AP = Application Process
    AE = Application Entity
    ACSE = Association Control Service Element

    :parameter protocol_version: DLMS Protocol version. Always is the default
        (0) and is not used.

    # TODO: can we remove the protocol version since it is always the default and if
    # sent it should be the default?

    Kernel:
    :parameter application_context_name: Holds information about name
        referencing (long name refs are always used in this library) and use of
        ciphered APDUs

    :parameter calling_ap_title:  If the `application_context_name` uses ciphering
        `calling_ap_title` should contain the clients system title. Also if the
        proposed HLS (High Level Security) auth mechanism uses the system title it
        should be present.

    :parameter calling_ae_qualifier: If the `application_context_name` indicates the
        use of ciphered APDUs the `calling_ae_qualifier` may hold the public digital
        signature key certificate of the client.

    :parameter sender_acse_requirements: The use depends on the authentication
        mechanism used.
        * If Lowest Level Scurity (None) is used it shall not be present.
        * If Low Level Security (LLS) is used it should be present in request and may
            be present in response (AARE) and indicate authentication (bit0 = 1)
        * If High Level Security (HLS) is used it should be present in both request and
            response (AARE) and indicate authentication (bit0 = 1)

    :parameter mechanism_name: Shall only be present if `sender_acse_requirements`
        indicates authentication. The field in the request is the proposed method and
        the response holds the value to be used.

    :parameter calling_authentication_value: Shall only be present if
        `sender_acse_requirements` indicates authentication. It holds the client
        authentication value appropriat to the selected `mechanism_name`.

    :parameter user_information: Holds the proposed xDLMS context in the form of a
        `InitiateRequestApdu` encoded as a BER OctetString.
        If the `InitiateRequestApdu` contains a dedicated_key it should be
        authenticated and encrypted using the AES-GCM, global encryption key and the
        authentication key (if in use).
        Even if there is no dedicated key the `InitiateRequestApdu` should be protected
        as above if there is need to protect the RLRQ


    :parameter called_ap_title: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter called_ae_qualifier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter called_ap_invocation_identfier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter called_ae_invocation_indentifier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter calling_ap_invocation_identifier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter calling_ae_invocation_identifier: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    :parameter implementation_information: Usage not defined in DLMS green book.
        Usage could be defined by meter manufacturer

    }

    # TODO: sender_asce_requirement is compleaty dependant on the meshanism name.
    # No need to have it as input.
    # TODO: Mechanism name as INT Enum.

    """

    TAG: ClassVar[int] = 0x60  # Application 0 = 60H = 96
    PARSE_TAGS = {
        0x80: ("protocol_version", None),  # Context specific, constructed? 0
        0xA1: ("application_context_name", acse_base.AppContextName),
        # Context specific, constructed 1
        162: ("called_ap_title", None),
        163: ("called_ae_qualifier", None),
        164: ("called_ap_invocation_identifier", None),
        165: ("called_ae_invocation_identifier", None),
        166: ("calling_ap_title", None),
        167: ("calling_ae_qualifier", None),
        168: ("calling_ap_invocation_identifier", None),
        169: ("calling_ae_invocation_identifier", None),
        0x8A: ("sender_acse_requirements", acse_base.AuthFunctionalUnit),
        0x8B: ("mechanism_name", acse_base.MechanismName),
        0xAC: ("calling_authentication_value", acse_base.AuthenticationValue),
        0xBD: ("implementation_information", None),
        0xBE: (
            "user_information",
            acse_base.UserInformation,
        ),  # Context specific, constructed 30
    }

    application_context_name: acse_base.AppContextName
    protocol_version: Optional[int] = attr.ib(default=1)
    calling_ap_title: Optional[bytes] = attr.ib(default=None)
    calling_ae_qualifier: Optional[bytes] = attr.ib(default=None)

    sender_acse_requirements: Optional[acse_base.AuthFunctionalUnit] = attr.ib(
        default=None
    )
    mechanism_name: Optional[acse_base.MechanismName] = attr.ib(default=None)
    calling_authentication_value: Optional[acse_base.AuthenticationValue] = attr.ib(
        default=None
    )
    user_information: Optional[acse_base.UserInformation] = attr.ib(
        default=None, validator=[user_information_holds_initiate_request]
    )

    # Not really used
    called_ap_title: Optional[bytes] = attr.ib(default=None)
    called_ae_qualifier: Optional[bytes] = attr.ib(default=None)
    called_ap_invocation_identifier: Optional[bytes] = attr.ib(default=None)
    called_ae_invocation_identifier: Optional[bytes] = attr.ib(default=None)
    calling_ap_invocation_identifier: Optional[bytes] = attr.ib(default=None)
    calling_ae_invocation_identifier: Optional[bytes] = attr.ib(default=None)
    implementation_information: Optional[bytes] = attr.ib(default=None)

    @classmethod
    def from_bytes(cls, aarq_bytes):
        # put it in a bytearray to be able to pop.
        aarq_data = bytearray(aarq_bytes)

        aarq_tag = aarq_data.pop(0)
        if not aarq_tag == cls.TAG:
            raise ValueError("Bytes are not an AARQ APDU. TAg is not int(96)")

        aarq_length = aarq_data.pop(0)

        if not len(aarq_data) == aarq_length:
            raise ValueError(
                "The APDU Data lenght does not correspond " "to length byte"
            )

        # Assumes that the protocol-version is 1 and we don't need to decode it

        # Decode the AARQ  data
        object_dict = dict()
        # use the data in tags to go through the bytes and create objects.
        while True:
            # TODO: this does not take into account when defining objects in dict and not using them.
            object_tag = aarq_data.pop(0)
            object_desc = ApplicationAssociationRequestApdu.PARSE_TAGS.get(
                object_tag, None
            )
            if object_desc is None:
                raise ValueError(
                    f"Could not find object with tag {object_tag} "
                    f"in AARQ definition"
                )

            object_length = aarq_data.pop(0)
            object_data = bytes(aarq_data[:object_length])
            aarq_data = aarq_data[object_length:]

            object_name = object_desc[0]
            object_class: Any = object_desc[1]

            if object_class is not None:
                object_data = object_class.from_bytes(object_data)

            object_dict[object_name] = object_data

            if len(aarq_data) <= 0:
                break

        return cls(**object_dict)

    def to_bytes(self):
        # if we created the object from bytes we can just return the same bytes
        # if self._raw_bytes is not None:
        #    return self._raw_bytes
        aarq_data = bytearray()
        # default value of protocol_version is 1. Only decode if other than 1
        if self.protocol_version != 1:
            aarq_data.extend(BER.encode(160, bytes(self.protocol_version)))
        if self.application_context_name is not None:
            aarq_data.extend(BER.encode(161, self.application_context_name.to_bytes()))
        if self.called_ap_title is not None:
            aarq_data.extend(BER.encode(162, self.called_ap_title))
        if self.called_ae_qualifier is not None:
            aarq_data.extend(BER.encode(163, self.called_ae_qualifier))
        if self.called_ap_invocation_identifier is not None:
            aarq_data.extend(BER.encode(164, self.called_ap_invocation_identifier))
        if self.called_ae_invocation_identifier is not None:
            aarq_data.extend(BER.encode(165, self.called_ae_invocation_identifier))
        if self.calling_ap_title is not None:
            aarq_data.extend(BER.encode(166, self.calling_ap_title))
        if self.calling_ae_qualifier is not None:
            aarq_data.extend(BER.encode(167, self.calling_ae_qualifier))
        if self.calling_ap_invocation_identifier is not None:
            aarq_data.extend(BER.encode(168, self.calling_ap_invocation_identifier))
        if self.calling_ae_invocation_identifier is not None:
            aarq_data.extend(BER.encode(169, self.calling_ae_invocation_identifier))
        if self.sender_acse_requirements is not None:
            aarq_data.extend(BER.encode(0x8A, self.sender_acse_requirements.to_bytes()))
        if self.mechanism_name is not None:
            aarq_data.extend(BER.encode(0x8B, self.mechanism_name.to_bytes()))
        if self.calling_authentication_value is not None:
            aarq_data.extend(
                BER.encode(0xAC, self.calling_authentication_value.to_bytes())
            )
        if self.implementation_information is not None:
            aarq_data.extend(BER.encode(0xBD, self.implementation_information))
        if self.user_information is not None:
            aarq_data.extend(BER.encode(0xBE, self.user_information.to_bytes()))
        # TODO: UPDATE THE ENCODING TAGS!

        return BER.encode(self.TAG, aarq_data)

        # TODO: make BER.encode handle bytes or bytearray to save code space.
        # TODO: CAn we use an orderedDict to loopt through all elemetns of the aarq to be transformed.

        # TODO: Add encoding of all values from ground up.