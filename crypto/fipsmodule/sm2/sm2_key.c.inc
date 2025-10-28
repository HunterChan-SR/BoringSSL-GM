#include<openssl/sm2.h>
#include<openssl/bn.h>
#include<openssl/ec.h>
#include<openssl/err.h>
#include<openssl/base.h>

/*
 * ================================================================
 *  函数名称: SM2_key_private_check
 *  功能描述: 检查给定的 SM2 私钥是否合法（范围正确且曲线匹配）
 *  
 *  参数说明:
 *    - eckey : 待验证的 EC_KEY 对象，需包含私钥与曲线信息
 *  
 *  返回值:
 *    - 1 : 私钥合法
 *    - 0 : 私钥非法（空指针、曲线不匹配或超出范围）
 *  
 *  合法条件（参考 GM/T 0003.2-2012 第 6.2.1 条）:
 *    私钥 d 满足: 1 ≤ d ≤ n - 1
 *    其中 n 为椭圆曲线的阶 (EC_GROUP_get0_order)
 * ================================================================
 */
int SM2_key_private_check(const EC_KEY *eckey)
{
    int ret = 0;
    BIGNUM *max = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_key = NULL,*order = NULL;
    if(eckey==NULL 
        || (group = EC_KEY_get0_group(eckey))==NULL
        || (priv_key = EC_KEY_get0_private_key(eckey))==NULL
        || (order = EC_GROUP_get0_order(group))==NULL){
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PRIVATE_KEY);
        return 0;
    }
    
    max = BN_dup(order);
    if(max == NULL || !BN_sub_word(max,1))
        goto end;
    if(BN_cmp(priv_key,BN_value_one())<0
        || BN_cmp(priv_key,max)>=0 ){
        OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PRIVATE_KEY);
        goto end;
    }
    ret = 1;

end:
    BN_free(max);
    return ret;
}