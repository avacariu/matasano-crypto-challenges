from lib.crypto import validate_pkcs7_padding

test_data = [
    (b"ICE ICE BABY\x04\x04\x04\x04", (True, b"ICE ICE BABY")),
    (b"ICE ICE BABY\x05\x05\x05\x05", False),
    (b"ICE ICE BABY\x01\x02\x03\x04", False),
]

for data, expect in test_data:
    try:
        print(data)
        print(validate_pkcs7_padding(data))
    except:
        print("Exception thrown")
