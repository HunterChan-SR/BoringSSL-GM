import binascii

# SM2曲线参数定义
p_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
a_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
b_hex = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
n_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
Gx_hex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
Gy_hex = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

# 将十六进制字符串转换为整数
p = int(p_hex, 16)
a = int(a_hex, 16)
b = int(b_hex, 16)
n = int(n_hex, 16)
Gx = int(Gx_hex, 16)
Gy = int(Gy_hex, 16)

# 计算Montgomery参数N0 (满足 N0 * N ≡ -1 mod 2^w)
def calc_n0(N, w):
    mask = (1 << w) - 1
    N_low = N & mask
    inv = pow(N_low, -1, 1 << w)
    return (1 << w) - inv  # 因为需要满足 N0 * N ≡ -1 mod 2^w

# 计算Montgomery参数RR (R^2 mod N)
def calc_rr(N, w):
    k = (N.bit_length() + w - 1) // w * w  # R = 2^k
    R = 1 << k
    RR = (R * R) % N
    return RR

# 将大整数分解为w位数组 (小端序)
def int_to_words(value, w, num_words):
    mask = (1 << w) - 1
    words = []
    for _ in range(num_words):
        words.append(value & mask)
        value >>= w
    return words

# 计算Montgomery域表示
def to_montgomery(x, N, w):
    k = (N.bit_length() + w - 1) // w * w
    R = 1 << k
    return (x * R) % N

# 计算64位参数
w64 = 64
num_words64 = 4  # 256位 / 64位 = 4个字

kSM2FieldN0_64 = calc_n0(p, w64)
kSM2OrderN0_64 = calc_n0(n, w64)

kSM2Field_64 = int_to_words(p, w64, num_words64)
kSM2Order_64 = int_to_words(n, w64, num_words64)
kSM2B_64 = int_to_words(b, w64, num_words64)
kSM2GX_64 = int_to_words(Gx, w64, num_words64)
kSM2GY_64 = int_to_words(Gy, w64, num_words64)

# 64位Montgomery参数
kSM2FieldR_64 = to_montgomery(1, p, w64)  # R mod p
kSM2FieldRR_64 = calc_rr(p, w64)          # R^2 mod p
kSM2OrderRR_64 = calc_rr(n, w64)          # R^2 mod n
kSM2MontB_64 = to_montgomery(b, p, w64)
kSM2MontGX_64 = to_montgomery(Gx, p, w64)
kSM2MontGY_64 = to_montgomery(Gy, p, w64)

# 计算32位参数
w32 = 32
num_words32 = 8  # 256位 / 32位 = 8个字

kSM2FieldN0_32 = calc_n0(p, w32)
kSM2OrderN0_32 = calc_n0(n, w32)

kSM2Field_32 = int_to_words(p, w32, num_words32)
kSM2Order_32 = int_to_words(n, w32, num_words32)
kSM2B_32 = int_to_words(b, w32, num_words32)
kSM2GX_32 = int_to_words(Gx, w32, num_words32)
kSM2GY_32 = int_to_words(Gy, w32, num_words32)

# 32位Montgomery参数
kSM2FieldR_32 = to_montgomery(1, p, w32)  # R mod p
kSM2FieldRR_32 = calc_rr(p, w32)          # R^2 mod p
kSM2OrderRR_32 = calc_rr(n, w32)          # R^2 mod n
kSM2MontB_32 = to_montgomery(b, p, w32)
kSM2MontGX_32 = to_montgomery(Gx, p, w32)
kSM2MontGY_32 = to_montgomery(Gy, p, w32)

# 打印结果
print("// SM2曲线常量定义")
print(f"OPENSSL_UNUSED static const uint64_t kSM2FieldN0 = 0x{kSM2FieldN0_64:016x};")
print(f"OPENSSL_UNUSED static const uint64_t kSM2OrderN0 = 0x{kSM2OrderN0_64:016x};")
print("")
print("#if defined(OPENSSL_64_BIT)")
print("OPENSSL_UNUSED static const uint64_t kSM2Field[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in kSM2Field_64))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2Order[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in kSM2Order_64))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2B[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in kSM2B_64))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2GX[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in kSM2GX_64))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2GY[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in kSM2GY_64))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2FieldR[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in int_to_words(kSM2FieldR_64, w64, num_words64)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2FieldRR[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in int_to_words(kSM2FieldRR_64, w64, num_words64)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2OrderRR[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in int_to_words(kSM2OrderRR_64, w64, num_words64)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2MontB[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in int_to_words(kSM2MontB_64, w64, num_words64)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2MontGX[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in int_to_words(kSM2MontGX_64, w64, num_words64)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint64_t kSM2MontGY[] = {")
print("    " + ", ".join(f"0x{x:016x}" for x in int_to_words(kSM2MontGY_64, w64, num_words64)))
print("};")
print("\n#elif defined(OPENSSL_32_BIT)")
print(f"OPENSSL_UNUSED static const uint32_t kSM2FieldN0 = 0x{kSM2FieldN0_32:08x};")
print(f"OPENSSL_UNUSED static const uint32_t kSM2OrderN0 = 0x{kSM2OrderN0_32:08x};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2Field[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in kSM2Field_32))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2Order[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in kSM2Order_32))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2B[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in kSM2B_32))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2GX[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in kSM2GX_32))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2GY[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in kSM2GY_32))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2FieldR[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in int_to_words(kSM2FieldR_32, w32, num_words32)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2FieldRR[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in int_to_words(kSM2FieldRR_32, w32, num_words32)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2OrderRR[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in int_to_words(kSM2OrderRR_32, w32, num_words32)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2MontB[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in int_to_words(kSM2MontB_32, w32, num_words32)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2MontGX[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in int_to_words(kSM2MontGX_32, w32, num_words32)))
print("};")
print("")
print("OPENSSL_UNUSED static const uint32_t kSM2MontGY[] = {")
print("    " + ", ".join(f"0x{x:08x}" for x in int_to_words(kSM2MontGY_32, w32, num_words32)))
print("};")
print("\n#else")
print("#error \"unknown word size\"")
print("#endif")