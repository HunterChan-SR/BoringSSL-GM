def main():
    import sys
    sys.setrecursionlimit(10000)

    # --------------------------
    # 1. SM2 曲线参数（用户提供）
    # --------------------------
    p_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
    a_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
    b_hex = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
    n_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
    Gx_hex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
    Gy_hex = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

    # 转换为大整数（注意：hex字符串是大端序）
    p = int(p_hex, 16)
    a = int(a_hex, 16)
    b = int(b_hex, 16)
    n = int(n_hex, 16)
    Gx = int(Gx_hex, 16)
    Gy = int(Gy_hex, 16)

    # --------------------------
    # 2. 辅助工具函数
    # --------------------------
    def modinv(x, m):
        """费马小定理求逆元（m为质数）"""
        return pow(x, m - 2, m)

    def int_to_le_uint64_arr(x):
        """256位整数转换为小端序uint64_t数组（4个元素，对应SM2_LIMBS=4）"""
        arr = []
        for _ in range(4):
            arr.append(x & 0xFFFFFFFFFFFFFFFF)
            x >>= 64
        return arr

    def int_to_le_uint32_arr(x):
        """256位整数转换为小端序uint32_t数组（8个元素，对应SM2_LIMBS=8）"""
        arr = []
        for _ in range(8):
            arr.append(x & 0xFFFFFFFF)
            x >>= 32
        return arr

    def uint64_to_tobn(val):
        """uint64_t值转换为TOBN(high, low)宏（32位分拆）"""
        low = val & 0xFFFFFFFF
        high = (val >> 32) & 0xFFFFFFFF
        return f"TOBN(0x{high:08x}, 0x{low:08x})"

    def compute_mont_r(m):
        """计算Montgomery域的R值 = 2^256 mod m"""
        return pow(2, 256, m)

    def to_mont(x, R, m):
        """转换值到Montgomery域：x_mont = (x * R) mod m"""
        return (x * R) % m

    # --------------------------
    # 3. SM2 点运算类（用于预计算表）
    # --------------------------
    class SM2Point:
        def __init__(self, x, y):
            self.x = x % p if x is not None else None
            self.y = y % p if y is not None else None
            self.validate()

        def validate(self):
            """验证点是否在SM2曲线上"""
            if self.x is None:
                return  # 无穷远点
            lhs = (self.y ** 2) % p
            rhs = (self.x ** 3 + a * self.x + b) % p
            if lhs != rhs:
                raise ValueError(f"Point ({hex(self.x)}, {hex(self.y)}) not on SM2 curve")

        def __add__(self, other):
            """点加法：self + other"""
            # 处理无穷远点
            if self.x is None:
                return other
            if other.x is None:
                return self
            # 处理P = -Q（y1 + y2 ≡ 0 mod p）
            if self.x == other.x and (self.y + other.y) % p == 0:
                return SM2Point(None, None)
            # 计算斜率lambda
            if self.x != other.x:
                dx = (other.x - self.x) % p
                lam = ((other.y - self.y) * modinv(dx, p)) % p
            else:
                dy = (2 * self.y) % p
                lam = ((3 * self.x ** 2 + a) * modinv(dy, p)) % p
            # 计算结果点
            x3 = (lam ** 2 - self.x - other.x) % p
            y3 = (lam * (self.x - x3) - self.y) % p
            return SM2Point(x3, y3)

        def __mul__(self, scalar):
            """点乘法：scalar * self（二进制快速幂）"""
            result = SM2Point(None, None)  # 无穷远点
            current = self
            while scalar > 0:
                if scalar % 2 == 1:
                    result = result + current
                current = current + current  # 点加倍
                scalar = scalar // 2
            return result

        def __rmul__(self, scalar):
            """支持 scalar * point 语法"""
            return self * scalar

        def double_k_times(self, k):
            """将点加倍k次（等价于 * 2^k）"""
            result = self
            for _ in range(k):
                result = result + result
            return result

        def to_mont(self, R):
            """转换为Montgomery域坐标"""
            if self.x is None:
                return (None, None)
            x_mont = (self.x * R) % p
            y_mont = (self.y * R) % p
            return (x_mont, y_mont)

    # --------------------------
    # 第一步：生成 SM2 常量（对齐P256格式）
    # --------------------------
    print("// --------------------------")
    print("// SM2 Core Constants")
    print("// --------------------------")

    # 计算Montgomery基础参数
    R = compute_mont_r(p)  # 2^256 mod p（n也是256位，R值相同）
    RR_p = (R * R) % p     # R² mod p（域参数用）
    RR_n = (R * R) % n     # R² mod n（阶参数用）

    # 1. 最低64位常量（Montgomery乘法需要）
    kSM2FieldN0 = p & 0xFFFFFFFFFFFFFFFF
    kSM2OrderN0 = n & 0xFFFFFFFFFFFFFFFF
    print(f"OPENSSL_UNUSED static const uint64_t kSM2FieldN0 = 0x{kSM2FieldN0:016x};")
    print(f"OPENSSL_UNUSED static const uint64_t kSM2OrderN0 = 0x{kSM2OrderN0:016x};")

    # 2. 64位环境常量（SM2_LIMBS=4）
    print("#if defined(OPENSSL_64_BIT)")
    # 域参数 p（小端序uint64_t[4]，匹配SM2_LIMBS=4）
    kSM2Field_64 = int_to_le_uint64_arr(p)
    print("OPENSSL_UNUSED static const uint64_t kSM2Field[] = {")
    print(f"    0x{kSM2Field_64[0]:016x}, 0x{kSM2Field_64[1]:016x}, 0x{kSM2Field_64[2]:016x}, 0x{kSM2Field_64[3]:016x}");
    print("};")

    # 阶参数 n（小端序uint64_t[4]）
    kSM2Order_64 = int_to_le_uint64_arr(n)
    print("OPENSSL_UNUSED static const uint64_t kSM2Order[] = {")
    print(f"    0x{kSM2Order_64[0]:016x}, 0x{kSM2Order_64[1]:016x}, 0x{kSM2Order_64[2]:016x}, 0x{kSM2Order_64[3]:016x}");
    print("};")

    # Montgomery R/RR（域参数）
    kSM2FieldR_64 = int_to_le_uint64_arr(R)
    kSM2FieldRR_64 = int_to_le_uint64_arr(RR_p)
    print("OPENSSL_UNUSED static const uint64_t kSM2FieldR[] = {")
    print(f"    0x{kSM2FieldR_64[0]:016x}, 0x{kSM2FieldR_64[1]:016x}, 0x{kSM2FieldR_64[2]:016x}, 0x{kSM2FieldR_64[3]:016x}");
    print("};")
    print("OPENSSL_UNUSED static const uint64_t kSM2FieldRR[] = {")
    print(f"    0x{kSM2FieldRR_64[0]:016x}, 0x{kSM2FieldRR_64[1]:016x}, 0x{kSM2FieldRR_64[2]:016x}, 0x{kSM2FieldRR_64[3]:016x}");
    print("};")

    # Montgomery RR（阶参数）
    kSM2OrderRR_64 = int_to_le_uint64_arr(RR_n)
    print("OPENSSL_UNUSED static const uint64_t kSM2OrderRR[] = {")
    print(f"    0x{kSM2OrderRR_64[0]:016x}, 0x{kSM2OrderRR_64[1]:016x}, 0x{kSM2OrderRR_64[2]:016x}, 0x{kSM2OrderRR_64[3]:016x}");
    print("};")

    # Montgomery形式的曲线参数（B、Gx、Gy）
    b_mont = to_mont(b, R, p)
    Gx_mont = to_mont(Gx, R, p)
    Gy_mont = to_mont(Gy, R, p)
    kSM2MontB_64 = int_to_le_uint64_arr(b_mont)
    kSM2MontGX_64 = int_to_le_uint64_arr(Gx_mont)
    kSM2MontGY_64 = int_to_le_uint64_arr(Gy_mont)

    print("OPENSSL_UNUSED static const uint64_t kSM2MontB[] = {")
    print(f"    0x{kSM2MontB_64[0]:016x}, 0x{kSM2MontB_64[1]:016x}, 0x{kSM2MontB_64[2]:016x}, 0x{kSM2MontB_64[3]:016x}");
    print("};")
    print("OPENSSL_UNUSED static const uint64_t kSM2MontGX[] = {")
    print(f"    0x{kSM2MontGX_64[0]:016x}, 0x{kSM2MontGX_64[1]:016x}, 0x{kSM2MontGX_64[2]:016x}, 0x{kSM2MontGX_64[3]:016x}");
    print("};")
    print("OPENSSL_UNUSED static const uint64_t kSM2MontGY[] = {")
    print(f"    0x{kSM2MontGY_64[0]:016x}, 0x{kSM2MontGY_64[1]:016x}, 0x{kSM2MontGY_64[2]:016x}, 0x{kSM2MontGY_64[3]:016x}");
    print("};")

    # 3. 32位环境常量（SM2_LIMBS=8）
    print("#elif defined(OPENSSL_32_BIT)")
    # 域参数 p（小端序uint32_t[8]，匹配SM2_LIMBS=8）
    kSM2Field_32 = int_to_le_uint32_arr(p)
    print("OPENSSL_UNUSED static const uint32_t kSM2Field[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2Field_32])}");
    print("};")

    # 阶参数 n（小端序uint32_t[8]）
    kSM2Order_32 = int_to_le_uint32_arr(n)
    print("OPENSSL_UNUSED static const uint32_t kSM2Order[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2Order_32])}");
    print("};")

    # Montgomery R/RR（域参数）
    kSM2FieldR_32 = int_to_le_uint32_arr(R)
    kSM2FieldRR_32 = int_to_le_uint32_arr(RR_p)
    print("OPENSSL_UNUSED static const uint32_t kSM2FieldR[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2FieldR_32])}");
    print("};")
    print("OPENSSL_UNUSED static const uint32_t kSM2FieldRR[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2FieldRR_32])}");
    print("};")

    # Montgomery RR（阶参数）
    kSM2OrderRR_32 = int_to_le_uint32_arr(RR_n)
    print("OPENSSL_UNUSED static const uint32_t kSM2OrderRR[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2OrderRR_32])}");
    print("};")

    # Montgomery形式的曲线参数（B、Gx、Gy）
    kSM2MontB_32 = int_to_le_uint32_arr(b_mont)
    kSM2MontGX_32 = int_to_le_uint32_arr(Gx_mont)
    kSM2MontGY_32 = int_to_le_uint32_arr(Gy_mont)
    print("OPENSSL_UNUSED static const uint32_t kSM2MontB[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2MontB_32])}");
    print("};")
    print("OPENSSL_UNUSED static const uint32_t kSM2MontGX[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2MontGX_32])}");
    print("};")
    print("OPENSSL_UNUSED static const uint32_t kSM2MontGY[] = {")
    print(f"    {', '.join([f'0x{x:08x}' for x in kSM2MontGY_32])}");
    print("};")

    print("#else")
    print("#error \"unknown word size (requires 64-bit or 32-bit OpenSSL)\"")
    print("#endif\n")

    # --------------------------
    # 第二步：生成 SM2 预计算表（window-7）
    # 注意：依赖已定义的 SM2_POINT_AFFINE 和 PRECOMP_SM2_ROW
    # --------------------------
    print("// --------------------------")
    print("// SM2 Precomputed Table (window-7 for fast scalar multiplication)")
    print("// --------------------------")

    # 预计算参数（window-7：37行×127列，支持256位标量）
    WINDOW_SIZE = 7
    NUM_ROWS = (256 + WINDOW_SIZE - 1) // WINDOW_SIZE  # 正确计算：ceil(256/7) = 37
    # 修正S_VALUES范围：window-7应包含-64~63（不含0），共127个非零点（2^7-1）
    S_VALUES = list(range(-64, 64))
    S_VALUES.remove(0)  # 移除0，保留127个值

    # 初始化生成元G
    G = SM2Point(Gx, Gy)
    precomputed = []

    # 生成每一行的预计算点
    for row_idx in range(NUM_ROWS):
        shift = WINDOW_SIZE * row_idx  # 该行点需要加倍的次数（左移窗口）
        row_points = []
        for s in S_VALUES:
            # 1. 计算 s*G（处理负系数：取反y坐标）
            abs_s = abs(s)
            G_s = abs_s * G
            # 2. 加倍shift次：G_s * 2^shift（对应窗口位置）
            G_s_shift = G_s.double_k_times(shift)
            # 3. 转换为Montgomery域
            x_mont, y_mont = G_s_shift.to_mont(R)
            if s < 0:
                y_mont = (-y_mont) % p  # 负系数取反y坐标
            # 4. 转换为TOBN格式（小端序，匹配SM2_LIMBS）
            if SM2_LIMBS == 4:  # 64位环境：每个坐标4个uint64元素
                x_arr = int_to_le_uint64_arr(x_mont)
                y_arr = int_to_le_uint64_arr(y_mont)
            else:  # 32位环境：每个坐标8个uint32元素
                x_arr = int_to_le_uint32_arr(x_mont)
                y_arr = int_to_le_uint32_arr(y_mont)
            x_tobn = [uint64_to_tobn(val) for val in x_arr]
            y_tobn = [uint64_to_tobn(val) for val in y_arr]
            # 5. 组合成SM2_POINT_AFFINE结构
            point_str = f"{{{{{', '.join(x_tobn)}}}, {{ {', '.join(y_tobn)} }}}}"
            row_points.append(point_str)
        precomputed.append(row_points)

    # 输出预计算表（37行×127列，数量匹配window-7要求）
    print("static const alignas(4096) PRECOMP_SM2_ROW ecp_sm2_precomputed[37] = {")
    for i, row in enumerate(precomputed):
        row_str = ",\n     ".join(row)
        if i == NUM_ROWS - 1:
            print(f"    {{\n     {row_str}\n    }}")
        else:
            print(f"    {{\n     {row_str}\n    }},")
    print("};")

if __name__ == "__main__":
    # 从环境变量获取SM2_LIMBS值（64位：4，32位：8），确保生成匹配的数组长度
    import os
    sm2_limbs = int(os.getenv("SM2_LIMBS", 4))  # 默认64位环境
    globals()["SM2_LIMBS"] = sm2_limbs
    main()