
# BoringSSL-GM

**BoringSSL-GM** 是基于 [Google BoringSSL](https://github.com/google/boringssl) **0.20240913.0** 版本的扩展实现，增加了对中国国家密码算法（SM 系列）的支持，包括：

* **SM2**（椭圆曲线公钥加密与签名算法）
* **SM3**（哈希算法）

该项目旨在为需要国密支持的安全通信协议（如 SSL/TLS、PSI、SCQL 等）提供与 BoringSSL 保持兼容的替代实现。

---

## 🔧 特性

* ✅ 保持与原版 **BoringSSL** API 和构建系统兼容
* ✅ 新增 **SM2/SM3** 算法支持
* ✅ 可选启用或禁用国密算法模块
* ✅ 支持通过 **CMake** 或 **Bazel** 构建
* ✅ 测试通过基础加解密与签名验签示例

---


## 📜 版本信息

* **基线版本**：BoringSSL 0.20240913.0
* **国密扩展作者**：CHENHE

---

## 🧩 兼容性与限制

* 当前国密实现主要面向 **实验与研究用途**；
* 不建议直接用于生产级别 TLS 服务器；

---

## 🧠 参考项目

* [Google BoringSSL](https://github.com/google/boringssl)
* [GMSSL](https://github.com/guanzhi/GmSSL)

---

## 📄 License

本项目沿用原 BoringSSL 的许可协议（Apache License 2.0）。
国密部分代码基于开源实现重新整理并在许可范围内使用。

---
# 原README：

# BoringSSL

BoringSSL is a fork of OpenSSL that is designed to meet Google's needs.

Although BoringSSL is an open source project, it is not intended for general
use, as OpenSSL is. We don't recommend that third parties depend upon it. Doing
so is likely to be frustrating because there are no guarantees of API or ABI
stability.

Programs ship their own copies of BoringSSL when they use it and we update
everything as needed when deciding to make API changes. This allows us to
mostly avoid compromises in the name of compatibility. It works for us, but it
may not work for you.

BoringSSL arose because Google used OpenSSL for many years in various ways and,
over time, built up a large number of patches that were maintained while
tracking upstream OpenSSL. As Google's product portfolio became more complex,
more copies of OpenSSL sprung up and the effort involved in maintaining all
these patches in multiple places was growing steadily.

Currently BoringSSL is the SSL library in Chrome/Chromium, Android (but it's
not part of the NDK) and a number of other apps/programs.

Project links:

  * [API documentation](https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html)
  * [Issue tracker](https://crbug.com/boringssl)
    * [Filing new (public) issues](https://crbug.com/boringssl/new)
  * [CI](https://ci.chromium.org/p/boringssl/g/main/console)
  * [Code review](https://boringssl-review.googlesource.com)

To file a security issue, use the [Chromium process](https://www.chromium.org/Home/chromium-security/reporting-security-bugs/) and mention in the report this is for BoringSSL. You can ignore the parts of the process that are specific to Chromium/Chrome.

There are other files in this directory which might be helpful:

  * [PORTING.md](./PORTING.md): how to port OpenSSL-using code to BoringSSL.
  * [BUILDING.md](./BUILDING.md): how to build BoringSSL
  * [INCORPORATING.md](./INCORPORATING.md): how to incorporate BoringSSL into a project.
  * [API-CONVENTIONS.md](./API-CONVENTIONS.md): general API conventions for BoringSSL consumers and developers.
  * [STYLE.md](./STYLE.md): rules and guidelines for coding style.
  * include/openssl: public headers with API documentation in comments. Also [available online](https://commondatastorage.googleapis.com/chromium-boringssl-docs/headers.html).
  * [FUZZING.md](./FUZZING.md): information about fuzzing BoringSSL.
  * [CONTRIBUTING.md](./CONTRIBUTING.md): how to contribute to BoringSSL.
  * [BREAKING-CHANGES.md](./BREAKING-CHANGES.md): notes on potentially-breaking changes.
  * [SANDBOXING.md](./SANDBOXING.md): notes on using BoringSSL in a sandboxed environment.
