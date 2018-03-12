from dlms_cosem.association import AARQAPDU

__bytes = b'`\x1d\xa1\t\x06\x07`\x85t\x05\x08\x01\x01\xbe\x10\x04\x0e\x01\x00\x00\x00\x06_\x1f\x04\x00\x000\x1d\xff\xff'
aarq = AARQAPDU.from_bytes(__bytes)
print('DECODED AARQ')
print(aarq)

print('Decoding AARQ')
print(aarq.to_bytes())

if (__bytes != aarq.to_bytes()):
    print('Decoding and encoding is not correct!')
    print(__bytes)
    print(aarq.to_bytes())#

else:
    print('Decoding and encoding CORRECT!')
    print(__bytes)
    print(aarq.to_bytes())

#print(aarq.user_information.association_information.initiate_request)