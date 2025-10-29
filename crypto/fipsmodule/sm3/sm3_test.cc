#include <gtest/gtest.h>

#include <openssl/mem.h>
#include <openssl/sm3.h>
#include <openssl/digest.h>
#include <iomanip>
#include <string>
#include "../../test/abi_test.h"
#include "../../test/test_util.h"
namespace {
static void RunSM3(const uint8_t *input, const uint8_t *expected,
                   size_t length) {
  uint8_t digest[SM3_DIGEST_LENGTH];
  SM3(input, length, digest);
  EXPECT_EQ(0, CRYPTO_memcmp(digest, expected, SM3_DIGEST_LENGTH));

  uint8_t digest2[SM3_DIGEST_LENGTH];
  SM3_CTX sm3_test_ctx;
  EXPECT_EQ(1, SM3_Init(&sm3_test_ctx));
  EXPECT_EQ(1, SM3_Update(&sm3_test_ctx, input, length));
  EXPECT_EQ(1, SM3_Final(digest2, &sm3_test_ctx));
  EXPECT_EQ(0, CRYPTO_memcmp(digest2, expected, SM3_DIGEST_LENGTH));
}

TEST(SM3Test, basic) {
  static const uint8_t input1[] = {0x61, 0x62, 0x63};

  /*
   * This test vector comes from Example 1 (A.1) of GM/T 0004-2012
   */
  static const uint8_t expected1[SM3_DIGEST_LENGTH] = {
      0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4,
      0x6b, 0xdc, 0x10, 0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2,
      0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0};

  static const uint8_t input2[] = {
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
      0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62,
      0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61,
      0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63,
      0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};

  /*
   * This test vector comes from Example 2 (A.2) from GM/T 0004-2012
   */
  static const uint8_t expected2[SM3_DIGEST_LENGTH] = {
      0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48,
      0x89, 0xc1, 0x8e, 0x5a, 0x4d, 0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e,
      0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};

  RunSM3(input1, expected1, sizeof(input1));
  RunSM3(input2, expected2, sizeof(input2));
}

static std::string Sm3String(const std::string &bytes) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;

  EVP_MD_CTX *evp_md_ctx_ = EVP_MD_CTX_new();  
  EXPECT_NE(evp_md_ctx_, nullptr);

  EXPECT_EQ(1, EVP_DigestInit_ex(evp_md_ctx_, EVP_sm3(), nullptr));
  EXPECT_EQ(1, EVP_DigestUpdate(evp_md_ctx_, bytes.data(), bytes.length()));
  EXPECT_EQ(1, EVP_DigestFinal_ex(evp_md_ctx_, hash, &md_len));

  EVP_MD_CTX_free(evp_md_ctx_);  

  return std::string(reinterpret_cast<char *>(hash), md_len);
}


std::string BytesToHexString(const std::string &bytes) {
  std::stringstream ss;
  ss << std::hex << std::uppercase << std::setfill('0');
  for (unsigned char c : bytes) {
    ss << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
  }
  return ss.str();
}

TEST(SM3Test, BasicStrings) {
  // Test "hello"
  EXPECT_EQ(BytesToHexString(Sm3String("hello")),
            "BECBBFAAE6548B8BF0CFCAD5A27183CD1BE6093B1CCECCC303D9C61D0A645268");

  // Test "ABCDE"
  EXPECT_EQ(BytesToHexString(Sm3String("ABCDE")),
            "3D3C180892E9F4B1F0A311F30AEDDA636B3C1D8EACA4EB76A158117A729898AC");
}

TEST(SM3Test, UTF8String) {
  // Test UTF8 string "你好"
  EXPECT_EQ(BytesToHexString(Sm3String("你好")),
            "78E5C78C5322CA174089E58DC7790ACF8CE9D542BEE6AE4A5A0797D5E356BE61");
}

TEST(SM3Test, EmptyString) {
  EXPECT_NO_THROW(Sm3String(""));
  // Note: Add specific hash value for empty string if known
}

TEST(SM3Test, LongString) {
  std::string long_text =
      "This small book contains a fairy tale,a story about many things."
      "First of all,Innocence of Childhood and love.The prince loves his roses,"
      "but felt disappointed by something the rose said.As doubt grows, he "
      "decides "
      "to explore other planet.The little prince discovers that his rose is "
      "not "
      "the only one of its kind,there are thousands of them in a garden,but "
      "then "
      "he realizes that his rose is special \"because it is she that I have "
      "watered; "
      "because it is she that I have put under the glass globe; because it is "
      "she "
      "that I have sheltered behind the screen\".The fox teaches the prince "
      "\"It "
      "is only with the heart that one can see rightly;what is essential is "
      "invisible "
      "to the eye \"";

  EXPECT_EQ(BytesToHexString(Sm3String(long_text)),
            "FC17B7051C7274AF272F6D2C8D1F674E9387C78614891074B938CDDDBF4440CC");
}

TEST(SM3Test, SpecialCharacters) {
  EXPECT_NO_THROW(Sm3String("!@#$%^&*()_+"));
  EXPECT_NO_THROW(Sm3String("\n\t\r"));
}

TEST(SM3Test, ConsistentResults) {
  // Same input should produce same hash
  std::string input = "test string";
  std::string hash1 = Sm3String(input);
  std::string hash2 = Sm3String(input);
  EXPECT_EQ(hash1, hash2);
}


}  // namespace
