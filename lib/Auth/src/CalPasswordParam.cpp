//
// Created by pythagodzilla on 2026/4/11.
//

#include "Auth.h"
#include "mbedtls/md.h"

namespace {
    String toHexLower(const uint8_t *data, size_t len) {
        static const char *hex = "0123456789abcdef";
        String out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; i++) {
            out += hex[(data[i] >> 4) & 0x0F];
            out += hex[data[i] & 0x0F];
        }
        return out;
    }

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

        return "{MD5}" + toHexLower(hmacOut, 16);
    }
}
