#include <gtest/gtest.h>

#include <openssl/sm2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>


#include "../../internal.h"
#include "../../test/test_util.h"
namespace {


// static EC_GROUP *sm2_create_EC_group(const char *p_hex, const char *a_hex,
//                                      const char *b_hex, const char *x_hex,
//                                      const char *y_hex, const char
//                                      *order_hex, const char *cof_hex) {
//   BIGNUM *p = NULL;
//   BIGNUM *a = NULL;
//   BIGNUM *b = NULL;
//   BIGNUM *g_x = NULL;
//   BIGNUM *g_y = NULL;
//   BIGNUM *order = NULL;
//   BIGNUM *cof = NULL;
//   EC_POINT *generator = NULL;
//   EC_GROUP *group = NULL;
//   //   int ok = 0;

//   EXPECT_TRUE(BN_hex2bn(&p, p_hex));
//   EXPECT_TRUE(BN_hex2bn(&a, a_hex));
//   EXPECT_TRUE(BN_hex2bn(&b, b_hex));

//   group = EC_GROUP_new_curve_GFp(p, a, b, NULL);
//   EXPECT_NE(group, nullptr);

//   generator = EC_POINT_new(group);
//   EXPECT_NE(generator, nullptr);

//   EXPECT_TRUE(BN_hex2bn(&g_x, x_hex));
//   EXPECT_TRUE(BN_hex2bn(&g_y, y_hex));
//   EXPECT_TRUE(
//       EC_POINT_set_affine_coordinates(group, generator, g_x, g_y, NULL));

//   EXPECT_TRUE(BN_hex2bn(&order, order_hex));
//   EXPECT_TRUE(BN_hex2bn(&cof, cof_hex));
//   EXPECT_TRUE(EC_GROUP_set_generator(group, generator, order, cof));

//   BN_free(p);
//   BN_free(a);
//   BN_free(b);
//   BN_free(g_x);
//   BN_free(g_y);
//   EC_POINT_free(generator);
//   BN_free(order);
//   BN_free(cof);

//   return group;
// }


// static int test_sm2_crypt(const EC_GROUP *group, const EVP_MD *digest,
//                           const char *privkey_hex, const char *message,
//                           const char *k_hex, const char *ctext_hex) {
//   const size_t msg_len = strlen(message);
//   BIGNUM *priv = NULL;
//   EC_KEY *key = NULL;
//   EC_POINT *pt = NULL;
//   std::vector<uint8_t> expected;
//   size_t ctext_len = 0;
//   size_t ptext_len = 0;
//   uint8_t *ctext = NULL;
//   uint8_t *recovered = NULL;
//   size_t recovered_len = msg_len;
//   int rc = 0;

//   DecodeHex(&expected, ctext_hex);

//   EXPECT_TRUE(BN_hex2bn(&priv, privkey_hex));

//   key = EC_KEY_new();
//   EXPECT_NE(nullptr, key);

//   EXPECT_TRUE(EC_KEY_set_group(key, group));
//   EXPECT_TRUE(EC_KEY_set_private_key(key, priv));

//   pt = EC_POINT_new(group);
//   EXPECT_NE(nullptr, pt);
//   EXPECT_TRUE(EC_POINT_mul(group, pt, priv, NULL, NULL, NULL));
//   EXPECT_TRUE(EC_KEY_set_public_key(key, pt));
//   EXPECT_TRUE(SM2_ciphertext_size(key, digest, msg_len, &ctext_len));


//   ctext = (uint8_t *)OPENSSL_zalloc(ctext_len);
//   EXPECT_NE(nullptr, ctext);

//   // start_fake_rand(k_hex);
//   EXPECT_TRUE(SM2_encrypt(key, digest, (const uint8_t *)message, msg_len,
//   ctext,
//                           &ctext_len));
//   // restore_rand();

//   EXPECT_EQ(0, OPENSSL_memcmp(ctext, expected.data(), ctext_len));

//   EXPECT_TRUE(SM2_plaintext_size(ctext, ctext_len, &ptext_len));
//   EXPECT_EQ(ptext_len, msg_len);

//   recovered = (uint8_t *)OPENSSL_zalloc(ptext_len);
//   EXPECT_NE(nullptr, recovered);
//   EXPECT_TRUE(
//       SM2_decrypt(key, digest, ctext, ctext_len, recovered, &recovered_len));
//   EXPECT_EQ(recovered_len, msg_len);

//   EXPECT_EQ(0, OPENSSL_memcmp(recovered, message, msg_len));

//   BN_free(priv);
//   EC_POINT_free(pt);
//   OPENSSL_free(ctext);
//   OPENSSL_free(recovered);
//   EC_KEY_free(key);
//   return rc;
// }

// TEST(SM2Test, Crypt) {
//   EC_GROUP *sm2p256_group = (EC_GROUP *)EC_group_sm2p256v1();

// //   EC_GROUP *sm2p256_group_by_nid = EC_GROUP_new_by_curve_name(NID_sm2);

//   EXPECT_NE(sm2p256_group, nullptr);
// //   EXPECT_NE(sm2p256_group_by_nid, nullptr);

//   test_sm2_crypt(
//       sm2p256_group, EVP_sm3(),
//       /* privkey (from which the encrypting public key is derived) */
//       "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
//       /* plaintext message */
//       "encryption standard",
//       /* ephemeral nonce k */
//       "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21",
//       /*
//        * expected ciphertext, the field values are from GM/T 0003.5-2012
//        * (Annex C), but serialized following the ASN.1 format specified
//        * in GM/T 0009-2012 (Sec. 7.2).
//        */
//       "307C" /* SEQUENCE, 0x7c bytes */
//       "0220" /* INTEGER, 0x20 bytes */
//       "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73"
//       "0221" /* INTEGER, 0x21 bytes */
//       "00"   /* leading 00 due to DER for pos. int with topmost bit set */
//       "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0"
//       "0420" /* OCTET STRING, 0x20 bytes */
//       "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766"
//       "0413" /* OCTET STRING, 0x13 bytes */
//       "21886CA989CA9C7D58087307CA93092D651EFA");
//     EC_GROUP_free(sm2p256_group);

//   test_sm2_crypt(
//       sm2p256_group_by_nid, EVP_sm3(),
//       /* privkey (from which the encrypting public key is derived) */
//       "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
//       /* plaintext message */
//       "encryption standard",
//       /* ephemeral nonce k */
//       "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21",
//       /*
//        * expected ciphertext, the field values are from GM/T 0003.5-2012
//        * (Annex C), but serialized following the ASN.1 format specified
//        * in GM/T 0009-2012 (Sec. 7.2).
//        */
//       "307C" /* SEQUENCE, 0x7c bytes */
//       "0220" /* INTEGER, 0x20 bytes */
//       "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73"
//       "0221" /* INTEGER, 0x21 bytes */
//       "00"   /* leading 00 due to DER for pos. int with topmost bit set */
//       "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0"
//       "0420" /* OCTET STRING, 0x20 bytes */
//       "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766"
//       "0413" /* OCTET STRING, 0x13 bytes */
//       "21886CA989CA9C7D58087307CA93092D651EFA");

//   EC_GROUP *gm_group = NULL;
//   std::cout<<"sm2_create_EC_group\n";
//   EC_GROUP *test_group = sm2_create_EC_group(
//       "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
//       "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
//       "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
//       "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
//       "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
//       "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
//       "1");

//   EXPECT_NE(nullptr, test_group);

//   test_sm2_crypt(
//       test_group, EVP_sm3(),
//       "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
//       "encryption standard",
//       "004C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"
//       "0092e8ff62146873c258557548500ab2df2a365e0609ab67640a1f6d57d7b17820"
//       "008349312695a3e1d2f46905f39a766487f2432e95d6be0cb009fe8c69fd8825a7",
//       "307B0220245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF1"
//       "7F6252E7022076CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A2"
//       "4B84400F01B804209C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A"
//       "285E07480653426D0413650053A89B41C418B0C3AAD00D886C00286467");

/* Same test as above except using SHA-256 instead of SM3 */
//   test_sm2_crypt(
//       test_group, EVP_sha256(),
//       "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0",
//       "encryption standard",
//       "004C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"
//       "003da18008784352192d70f22c26c243174a447ba272fec64163dd4742bae8bc98"
//       "00df17605cf304e9dd1dfeb90c015e93b393a6f046792f790a6fa4228af67d9588",
//       "307B0220245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F"
//       "6252E7022076CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84"
//       "400F01B80420BE89139D07853100EFA763F60CBE30099EA3DF7F8F364F9D10A5E9"
//       "88E3C5AAFC0413229E6C9AEE2BB92CAD649FE2C035689785DA33");

/* From Annex C in both GM/T0003.5-2012 and GB/T 32918.5-2016.*/
//   gm_group = sm2_create_EC_group(
//       "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
//       "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
//       "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
//       "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
//       "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
//       "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
//       "1");

//   EXPECT_NE(nullptr, gm_group);

//   test_sm2_crypt(
//       gm_group, EVP_sm3(),
//       /* privkey (from which the encrypting public key is derived) */
//       "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
//       /* plaintext message */
//       "encryption standard",
//       /* ephemeral nonce k */
//       "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21",
//       /*
//        * expected ciphertext, the field values are from GM/T 0003.5-2012
//        * (Annex C), but serialized following the ASN.1 format specified
//        * in GM/T 0009-2012 (Sec. 7.2).
//        */
//       "307C" /* SEQUENCE, 0x7c bytes */
//       "0220" /* INTEGER, 0x20 bytes */
//       "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73"
//       "0221" /* INTEGER, 0x21 bytes */
//       "00"   /* leading 00 due to DER for pos. int with topmost bit set */
//       "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0"
//       "0420" /* OCTET STRING, 0x20 bytes */
//       "59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766"
//       "0413" /* OCTET STRING, 0x13 bytes */
//       "21886CA989CA9C7D58087307CA93092D651EFA");


//   testresult = 1;
//   EC_GROUP_free(test_group);
//   EC_GROUP_free(gm_group);
// }

// sign
// static int test_sm2_sign(const EC_GROUP *group, const char *userid,
//                          const char *privkey_hex, const char *message,
//                          const char *k_hex, const char *r_hex,
//                          const char *s_hex) {
//   const size_t msg_len = strlen(message);
//   int ok = 0;
//   BIGNUM *priv = NULL;
//   EC_POINT *pt = NULL;
//   EC_KEY *key = NULL;
//   ECDSA_SIG *sig = NULL;
//   const BIGNUM *sig_r = NULL;
//   const BIGNUM *sig_s = NULL;
//   BIGNUM *r = NULL;
//   BIGNUM *s = NULL;

//   EXPECT_TRUE(BN_hex2bn(&priv, privkey_hex));
//   key = EC_KEY_new();
//   EXPECT_NE(nullptr, key);
//   EXPECT_TRUE(EC_KEY_set_group(key, group));
//   EXPECT_TRUE(EC_KEY_set_private_key(key, priv));

//   pt = EC_POINT_new(group);
//   EXPECT_NE(nullptr, pt);

//   EXPECT_TRUE(EC_POINT_mul(group, pt, priv, NULL, NULL, NULL));
//   EXPECT_TRUE(EC_KEY_set_public_key(key, pt));

//   sig = SM2_do_sign(key, EVP_sm3(), (const uint8_t *)userid,
//   strlen(userid),
//                     (const uint8_t *)message, msg_len);
//   EXPECT_NE(nullptr, sig);

//   ECDSA_SIG_get0(sig, &sig_r, &sig_s);

//   EXPECT_TRUE(BN_hex2bn(&r, r_hex));
//   EXPECT_TRUE(BN_hex2bn(&s, s_hex));
//   EXPECT_EQ(0, BN_cmp(sig_r, r));
//   EXPECT_EQ(0, BN_cmp(sig_s, s));

//   EXPECT_TRUE(SM2_do_verify(key, EVP_sm3(), sig, (const uint8_t *)userid,
//                             strlen(userid), (const uint8_t *)message,
//                             msg_len));

//   ECDSA_SIG_free(sig);
//   EC_POINT_free(pt);
//   EC_KEY_free(key);
//   BN_free(priv);
//   BN_free(r);
//   BN_free(s);

//   return ok;
// }

// TEST(SM2Test, Sign) {
//   //   int testresult = 0;
//   EC_GROUP *gm_group = NULL;
//   /* From draft-shen-sm2-ecdsa-02 */
//   EC_GROUP *test_group = sm2_create_EC_group(
//       "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3",
//       "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
//       "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
//       "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
//       "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
//       "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7",
//       "1");

//   EXPECT_NE(nullptr, test_group);

//   EXPECT_TRUE(test_sm2_sign(
//       test_group, "ALICE123@YAHOO.COM",
//       "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
//       "message digest",
//       "006CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F"
//       "007c47811054c6f99613a578eb8453706ccb96384fe7df5c171671e760bfa8be3a",
//       "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
//       "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7"));

//   /* From Annex A in both GM/T0003.5-2012 and GB/T 32918.5-2016.*/
//   gm_group = sm2_create_EC_group(
//       "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
//       "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
//       "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
//       "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
//       "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
//       "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
//       "1");

//   EXPECT_NE(nullptr, gm_group);

//   EXPECT_TRUE(test_sm2_sign(
//       gm_group,
//       /* the default ID specified in GM/T 0009-2012 (Sec. 10).*/
//       SM2_DEFAULT_USERID,
//       /* privkey */
//       "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
//       /* plaintext message */
//       "message digest",
//       /* ephemeral nonce k */
//       "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21",
//       /* expected signature, the field values are from GM/T 0003.5-2012,
//          Annex A. */
//       /* signature R, 0x20 bytes */
//       "F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3",
//       /* signature S, 0x20 bytes */
//       "B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"));

//   EC_GROUP_free(test_group);
//   EC_GROUP_free(gm_group);
// }


// static std::vector<uint8_t> HexToBytes(const char *str) {
//   std::vector<uint8_t> ret;
//   if (!DecodeHex(&ret, str)) {
//     abort();
//   }
//   return ret;
// }
// struct DeriveTest {
//   const EC_GROUP *group;
//   std::vector<uint8_t> secret;
//   std::vector<uint8_t> expected_priv;
//   std::vector<uint8_t> expected_pub;
// };
// TEST(SM2Test, EC_GROUP_SM2P256V1) {
//   const DeriveTest kDeriveTests[] = {
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("E69D4C5066EC2FC3F2C690682190EAF9E1DB3D5C0992B22B7689BED"
//                      "7FC9DA82D"),
//           HexToBytes("E69D4C5066EC2FC3F2C690682190EAF9E1DB3D5C0992B22B7689BED"
//                      "7FC9DA82D"),
//           HexToBytes("04A3E944F521624DDF4C1AF8446F258CFB7EE70E1B1826322345747"
//                      "F377448272D813AFAC22C991CA0663EEB310D78D3FC4494199DFEEE"
//                      "30054E363CDA4A5E0B6AA"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("0A16661946FED9036B41195761140FAE227760742D11808286B656E"
//                      "1820F3B60"),
//           HexToBytes("0A16661946FED9036B41195761140FAE227760742D11808286B656E"
//                      "1820F3B60"),
//           HexToBytes("04ADE2A466A75C1AD120B94E645A5D00DBFCFDE84BFB5A8405694C3"
//                      "ECB2105CEF04E1167BF484F7D49AA7677B543DA2B5F04C1C5FF7E67"
//                      "DE85B6AACB3676B753C1A"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("504E53C8EA3506519FBC765DDE41D5C4B09CDB6C127B2177F5D2F94"
//                      "1E2162C69"),
//           HexToBytes("504E53C8EA3506519FBC765DDE41D5C4B09CDB6C127B2177F5D2F94"
//                      "1E2162C69"),
//           HexToBytes("04C946E3359E8CE177E0D3994DB149AC0E16CB909373CEF657FBA99"
//                      "777D903E7E56E5D70D86134465BA89A051A1D2A4F266EF85DCA5AB4"
//                      "54BADAA7258F46310458A"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("442BDD3149506345A479923BCC9D12FB4F112E98545721B31A40C56"
//                      "D67C5740E"),
//           HexToBytes("442BDD3149506345A479923BCC9D12FB4F112E98545721B31A40C56"
//                      "D67C5740E"),
//           HexToBytes("04C85DB0ADFDD0E30721BFD4E4BD38239075477577178D1CF726868"
//                      "21E258F29E70C73731E4248DF211EE3FD2BAF09824869143812170A"
//                      "3AE9F6C4E9F4C3CD9EF9A"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("032561AD5670C99982D9704E647F476AC96E63AA67EDDA31A268257"
//                      "AB013067E"),
//           HexToBytes("032561AD5670C99982D9704E647F476AC96E63AA67EDDA31A268257"
//                      "AB013067E"),
//           HexToBytes("04A50CB8CB279266A20E7569D2F7904B14731771EC702AFDE8C13CB"
//                      "F8E3434F86430545C2DF446F456A627FCA7D3210FDC3F487E4F0544"
//                      "873900F032B955F21C06A"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("3A58D9CB6732DFC227FD464CE328C34BD073C2AB5A0A53FA872882E"
//                      "1A8768903"),
//           HexToBytes("3A58D9CB6732DFC227FD464CE328C34BD073C2AB5A0A53FA872882E"
//                      "1A8768903"),
//           HexToBytes("04A9F54D2123755B53E84823BA347106D1DAF4919DF27053281B2B6"
//                      "E2B815BBE8C7E72A89400A60DACD94645E629FB246DD01D42C40ECD"
//                      "36737FF3BA1CAE9C4463A"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("D14931A94EDEA52924B66D84DDACD38B99967F81BDD1339F7AEC120"
//                      "96EB14C20"),
//           HexToBytes("D14931A94EDEA52924B66D84DDACD38B99967F81BDD1339F7AEC120"
//                      "96EB14C20"),
//           HexToBytes("048EEBC294E368B37ADBA20C7A87390B3F137CC6CAC2D2009A056DB"
//                      "59EF8182CD321CD3F2616F79CE78B3470716D17840998F9BE410337"
//                      "0C5D38E66195B12F848FA"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("6D0312DDFF6750721FA8EDEF3709DBCE45D7EF06262BA60D37FE074"
//                      "5804E495E"),
//           HexToBytes("6D0312DDFF6750721FA8EDEF3709DBCE45D7EF06262BA60D37FE074"
//                      "5804E495E"),
//           HexToBytes("04A332CED3B53D44BC16FDB2409D11D5BA81536AA4CFB20F872EDDC"
//                      "76DE11CED496F90CFA9A383074D90FE6607AC8403E3D4BA60E84DF3"
//                      "83061000CD19E90BEF36A"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("926DD82B1A554802D6E2C73703A039498ECAA66E349416F951948A7"
//                      "94A0934C0"),
//           HexToBytes("926DD82B1A554802D6E2C73703A039498ECAA66E349416F951948A7"
//                      "94A0934C0"),
//           HexToBytes("0458FD969DCB24590D75FEA7F5EC4AB0EDB7FFD51C3EB90AAA54211"
//                      "A910AB810F67DA0F0C1D5074D16CD441B3F0F8F114171000D07E206"
//                      "BA6CBD9F78B75B6DAED6A"),
//       },
//       {
//           EC_group_sm2p256v1(),
//           HexToBytes("A067B2D814E9A2184E305C2CF282F897966617191D97E40371DA6D1"
//                      "E6B03C85C"),
//           HexToBytes("A067B2D814E9A2184E305C2CF282F897966617191D97E40371DA6D1"
//                      "E6B03C85C"),
//           HexToBytes("04BE331CABCF4D8347E37DC09DE07798010452D3DF591D61043C581"
//                      "8B2F340FE37295B76F5344F7662110DD8C123AE450A617533C4111B"
//                      "78D6E4D2BD60C6737236A"),
//       }
//       //   {
//       //       // FAILED
//       //       EC_group_sm2p256v1(),
//       //       HexToBytes("A067B2D814E9A2184E305C2CF282F897966617191D97E40371DA6D1"
//       //                  "E6B03C85C"),
//       //       HexToBytes("A067B2D814E9A2184E305C2CF282F897966617191D97E40371DA6D1"
//       //                  "E6B03C85C"),
//       //       HexToBytes("04BE331000004D8347E37DC09DE07798010452D3DF591D61043C581"
//       //                  "8B2F340FE37295B76F5344F7662110DD8C123AE450A617533C4111B"
//       //                  "78D6E4D2BD60C6737236A"),
//       //   },
//   };
//   for (const auto &test : kDeriveTests) {
//     SCOPED_TRACE(Bytes(test.secret));

//     bssl::UniquePtr<EC_KEY> key(EC_KEY_derive_from_secret(
//         test.group, test.secret.data(), test.secret.size()));
//     ASSERT_TRUE(key);

//     std::vector<uint8_t> priv(BN_num_bytes(EC_GROUP_get0_order(test.group)));
//     ASSERT_TRUE(BN_bn2bin_padded(priv.data(), priv.size(),
//                                  EC_KEY_get0_private_key(key.get())));
//     EXPECT_EQ(Bytes(priv), Bytes(test.expected_priv));

//     uint8_t *pub = nullptr;
//     size_t pub_len =
//         EC_KEY_key2buf(key.get(), POINT_CONVERSION_UNCOMPRESSED, &pub, nullptr);
//     bssl::UniquePtr<uint8_t> free_pub(pub);
//     EXPECT_NE(pub_len, 0u);
//     EXPECT_EQ(Bytes(pub, pub_len), Bytes(test.expected_pub));
//   }
// }

// TEST(SM2Test, HashToCurve)
}  // namespace