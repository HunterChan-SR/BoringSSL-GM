# Computing SM2 curve sqrt constants (user-visible)
# We'll define SM2 prime and compute square roots of 10 and 12 (mod p) similarly to your examples.
from caas_jupyter_tools import display_dataframe_to_user
import binascii

p = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
n  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
h  = 1

def to_bytes_be(x, length=32):
    return x.to_bytes(length, 'big')

def hex_bytes_array(x, length=32):
    b = to_bytes_be(x, length)
    return ", ".join("0x%02x" % bb for bb in b)

# compute sqrt(10) and sqrt(12) mod p using (p+1)//4 (works when p % 4 == 3)
assert p % 4 == 3  # SM2 prime is congruent 3 mod 4
sqrt10 = pow(10, (p+1)//4, p)
sqrt12 = pow(12, (p+1)//4, p)
# verify
assert pow(sqrt10, 2, p) == 10 % p
assert pow(sqrt12, 2, p) == 12 % p

results = {
    "p": hex(p),
    "a": hex(a),
    "b": hex(b),
    "Gx": hex(gx),
    "Gy": hex(gy),
    "n": hex(n),
    "h": h,
    "kSM2Sqrt10_bytes": hex_bytes_array(sqrt10),
    "kSM2Sqrt12_bytes": hex_bytes_array(sqrt12),
    "kSM2Sqrt10_int": sqrt10,
    "kSM2Sqrt12_int": sqrt12
}

# present results in a small table for easy copy
import pandas as pd
df = pd.DataFrame([{
    "name":"p", "value":results["p"]
},
{"name":"a","value":results["a"]},
{"name":"b","value":results["b"]},
{"name":"Gx","value":results["Gx"]},
{"name":"Gy","value":results["Gy"]},
{"name":"n","value":results["n"]},
{"name":"h","value":str(results["h"])},
{"name":"kSM2Sqrt10 (hex bytes array)","value":results["kSM2Sqrt10_bytes"]},
{"name":"kSM2Sqrt12 (hex bytes array)","value":results["kSM2Sqrt12_bytes"]}
])
display_dataframe_to_user("SM2 parameters and sqrt constants", df)

# Also print C-style static arrays like in your examples
print("// kSM2Sqrt10 is sqrt(10) in SM2P256V1's field (32 bytes, big-endian).")
print("// Computed as: pow(10, (p+1)//4, p)")
print("static const uint8_t kSM2Sqrt10[] = {")
print("    " + results["kSM2Sqrt10_bytes"])
print("};\n")
print("// kSM2Sqrt12 is sqrt(12) in SM2P256V1's field (32 bytes, big-endian).")
print("// Computed as: pow(12, (p+1)//4, p)")
print("static const uint8_t kSM2Sqrt12[] = {")
print("    " + results["kSM2Sqrt12_bytes"])
print("};")