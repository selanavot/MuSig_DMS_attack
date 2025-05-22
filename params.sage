'''
A toy setup of the secp256k elliptic curve and the hash functions used in the toy MuSig signature scheme, and SHA256 hashing wrapper.

There are likely implementation based vulnerabilities, but this is besides the point. Our attack does not abuse them, and would work even if the implementation was perfect.
'''

# Setup the secp256k curve 
p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
F = GF(p)
secp256k = EllipticCurve(F, [0, 7])
G = secp256k(55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)
identity = 0 * G
q = G.order()

# set-up the hash functions.
# Not done: Correct codomain for hashing, but this is not relevant for the attack. 
import hashlib
def h_com(R):
    h = hashlib.new('sha256')
    h.update(b"com")
    h.update(ec_point_to_bytes(R))
    return h.hexdigest()


def h_agg(index, PKs): # remark: index is 1-indexed.
    assert 1 <= index and index <= len(PKs)
    h = hashlib.new('sha256')
    h.update(b"agg")
    h.update(index.to_bytes(32, 'big'))
    for PK in PKs:
        h.update(ec_point_to_bytes(PK))
    return int(h.hexdigest(), base = 16)

def h_sign(agg_nonce, agg_key, message):
    h = hashlib.new('sha256')
    h.update(b"sign")
    h.update(ec_point_to_bytes(agg_nonce))
    h.update(ec_point_to_bytes(agg_key))
    h.update(message.encode())
    return int(h.hexdigest(), base = 16)

# utility functions
def ec_point_to_bytes(point):
    x, y = point.xy()
    x_int = int(x)
    y_int = int(y) 
    return x_int.to_bytes(32, 'big') + y_int.to_bytes(32, 'big')
