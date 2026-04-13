//
// Created by pythagodzilla on 2026/4/11.
//

#include "Auth.h"
#include "InternalHex.h"
#include "mbedtls/md.h"

namespace {
    // 计算登录参数 password = "{MD5}" + HMAC_MD5(challenge, plainPassword)
}

namespace Auth {
    String buildPasswordParam(const String &plainPassword, const String &challenge) {
        uint8_t hmacOut[16]; // MD5 输出 16 字节

        const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        if (!mdInfo) return "";

        int ret = mbedtls_md_hmac(
            mdInfo,
            (const unsigned char *) challenge.c_str(), challenge.length(),
            (const unsigned char *) plainPassword.c_str(), plainPassword.length(),
            hmacOut
        );
        if (ret != 0) return "";

        return "{MD5}" + AuthInternal::toHexLower(hmacOut, 16);
    }
}
