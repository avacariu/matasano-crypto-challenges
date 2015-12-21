import lib.crypto
from functools import partial

# this file just test the detection code in lib.crypto

ecb = partial(lib.crypto.encryption_oracle, method='ecb')
cbc = partial(lib.crypto.encryption_oracle, method='cbc')

ecb_detection_count = 0
count = 10000
for x in range(count):
    ecb_detection_count += lib.crypto.detect_ecb_cbc(ecb) == 'ecb'

print("ecb detection success rate: %f" % (ecb_detection_count / count))

cbc_detection_count = 0
count = 10000
for x in range(count):
    cbc_detection_count += lib.crypto.detect_ecb_cbc(cbc) == 'cbc'

print("cbc detection success rate: %f" % (cbc_detection_count / count))
