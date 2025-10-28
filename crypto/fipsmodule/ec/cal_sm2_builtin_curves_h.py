
def hex_to_int(h):
    return int(h.replace(" ", "").replace("\n", ""), 16)

def to_words(x, bits=64, num_words=None):
    mask = (1 << bits) - 1
    words = []
    while x:
        words.append(x & mask)
        x >>= bits
    if num_words:
        while len(words) < num_words:
            words.append(0)
    return words

def print_words(name, value, bits):
    print(f"OPENSSL_UNUSED static const uint{bits}_t {name}[] = {{")
    per_line = 2 if bits == 64 else 4
    for i, w in enumerate(value):
        end = "," if i != len(value) - 1 else ""
        print(f"    0x{w:0{bits//4}x}{end}")
        if (i + 1) % per_line == 0 and i + 1 < len(value):
            print("    //")
    print("};\n")

def inv64(x):
    return pow(x, -1, 1 << 64)

# ===============================================================
# SM2 curve parameters (GM/T 0003-2012)
# ===============================================================
p  = hex_to_int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")
a  = hex_to_int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
b  = hex_to_int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")
gx = hex_to_int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
gy = hex_to_int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
n  = hex_to_int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")

# ===============================================================
# Montgomery setup
# ===============================================================
R = 1 << 256
Rmodp = R % p
RRmodp = (R * R) % p
RRmodn = (R * R) % n

n0_p = (-pow(p, -1, 1 << 64)) & ((1 << 64) - 1)
n0_n = (-pow(n, -1, 1 << 64)) & ((1 << 64) - 1)

mont_b  = (b  * R) % p
mont_gx = (gx * R) % p
mont_gy = (gy * R) % p

# ===============================================================
# Print Results (64-bit + 32-bit)
# ===============================================================
print("// ===============================================================")
print("// SM2P256V1 curve constants for BoringSSL (auto-generated)")
print("// ===============================================================\n")

print(f"OPENSSL_UNUSED static const uint64_t kSM2FieldN0 = 0x{n0_p:016x};")
print(f"OPENSSL_UNUSED static const uint64_t kSM2OrderN0 = 0x{n0_n:016x};\n")

# ---- 64-bit ----
print("// ---------------- 64-bit constants ----------------")
print_words("kSM2Field",    to_words(p, 64, 4), 64)
print_words("kSM2Order",    to_words(n, 64, 4), 64)
print_words("kSM2FieldR",   to_words(Rmodp, 64, 4), 64)
print_words("kSM2FieldRR",  to_words(RRmodp, 64, 4), 64)
print_words("kSM2OrderRR",  to_words(RRmodn, 64, 4), 64)
print_words("kSM2MontB",    to_words(mont_b, 64, 4), 64)
print_words("kSM2MontGX",   to_words(mont_gx, 64, 4), 64)
print_words("kSM2MontGY",   to_words(mont_gy, 64, 4), 64)

# ---- 32-bit ----
print("// ---------------- 32-bit constants ----------------")
print_words("kSM2Field32",   to_words(p, 32, 8), 32)
print_words("kSM2Order32",   to_words(n, 32, 8), 32)
print_words("kSM2FieldR32",  to_words(Rmodp, 32, 8), 32)
print_words("kSM2FieldRR32", to_words(RRmodp, 32, 8), 32)
print_words("kSM2OrderRR32", to_words(RRmodn, 32, 8), 32)
print_words("kSM2MontB32",   to_words(mont_b, 32, 8), 32)
print_words("kSM2MontGX32",  to_words(mont_gx, 32, 8), 32)
print_words("kSM2MontGY32",  to_words(mont_gy, 32, 8), 32)