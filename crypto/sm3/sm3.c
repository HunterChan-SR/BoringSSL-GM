/**
 * 添加文件 sm3.c
 * 2025.10.27 陈贺
 */
#include <openssl/sm3.h>

#include <openssl/mem.h>

#include "../fipsmodule/bcm_interface.h"


int SM3_Init(SM3_CTX *c) {
  BCM_sm3_init(c);
  return 1;
}

int SM3_Update(SM3_CTX *c, const void *data, size_t len) {
  BCM_sm3_update(c, data, len);
  return 1;
}
int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *c) {
  BCM_sm3_final(out, c);
  return 1;
}



uint8_t *SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]) {
  SM3_CTX ctx;
  BCM_sm3_init(&ctx);
  BCM_sm3_update(&ctx, data, len);
  BCM_sm3_final(out, &ctx);
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return out;
}

void SM3_Transform(SM3_CTX *md5, const uint8_t block[SM3_BLOCK_SIZE]) {
  BCM_sm3_transform(md5, block);
}