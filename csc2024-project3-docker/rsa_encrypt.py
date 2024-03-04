import sys
import pickle

e = 65535
n = 22291846172619859445381409012451
d = 14499309299673345844676003563183
filename = "Pictures/simple_pic.jpg"

plain_bytes = b''
with open(filename, 'rb') as f:
    plain_bytes = f.read()
cipher_int = [pow(i, e, n) for i in plain_bytes]
with open(filename, 'wb') as f:
    pickle.dump(cipher_int, f)
