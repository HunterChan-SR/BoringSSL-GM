#include <openssl/base.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <string.h>

#include "internal.h"
#include "../delocate.h"
#include "../../internal.h"

//TODO 实现

// 导出方法表
DEFINE_METHOD_FUNCTION(EC_METHOD, EC_GFp_sm2_method) {
    out->point_get_affine_coordinates = ;
    out->add = ;
    out->dbl = ;
    out->mul = ;
    out->mul_base = ;
    out->mul_public = ;
    out->felem_mul = ;
    out->felem_sqr = ;
    out->felem_to_bytes = ;
    out->felem_from_bytes = ;
    out->scalar_inv0_montgomery = ;
    out->scalar_to_montgomery_inv_vartime =    ;
    out->cmp_x_coordinate = ;
}