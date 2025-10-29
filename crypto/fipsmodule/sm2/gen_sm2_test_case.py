#!/usr/bin/env python3
import subprocess
import tempfile
import os
import textwrap
import re

NUM_CASES = 10  # 生成10组

def run_cmd(cmd: str) -> str:
    """执行shell命令并返回输出（字符串）"""
    return subprocess.check_output(cmd, shell=True, text=True)

def extract_hex(field: str, text: str) -> str:
    """从openssl输出中提取priv/pub部分的十六进制串"""
    pattern = rf"{field}:\s*((?:[0-9A-Fa-f:]|\s)+)"
    m = re.search(pattern, text)
    if not m:
        raise ValueError(f"Failed to find {field} field")
    hex_data = m.group(1).replace(":", "").replace(" ", "").replace("\n", "")
    return hex_data.upper()

def generate_one_case(i: int):
    """生成一组SM2密钥对，返回字典"""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, f"sm2key{i}.pem")

        # 1️⃣ 生成SM2密钥
        run_cmd(f"openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:SM2 -out {key_path}")

        # 2️⃣ 查看密钥详情（提取priv/pub）
        text = run_cmd(f"openssl pkey -in {key_path} -text -noout")

        priv_hex = extract_hex("priv", text)
        pub_hex  = extract_hex("pub", text)

        # 确保公钥以04开头（非压缩格式）
        if not pub_hex.startswith("04"):
            pub_hex = "04" + pub_hex

        return {
            "secret": priv_hex,
            "priv": priv_hex,
            "pub": pub_hex,
        }

def main():
    print("// Auto-generated SM2P256V1 derive test cases using system OpenSSL")
    print("const DeriveTest kDeriveTests[] = {")

    for i in range(1, NUM_CASES + 1):
        case = generate_one_case(i)
        print("  {")
        print("      EC_group_sm2p256v1(),")
        print(f"      HexToBytes(\"{case['secret']}\"),")
        print(f"      HexToBytes(\"{case['priv']}\"),")
        wrapped_pub = textwrap.fill(
            f"\"{case['pub']}\"",
            width=70,
            subsequent_indent="          ",
        )
        print("      HexToBytes(")
        print(f"          {wrapped_pub}),")
        print("  },")
    print("};")

if __name__ == "__main__":
    main()
