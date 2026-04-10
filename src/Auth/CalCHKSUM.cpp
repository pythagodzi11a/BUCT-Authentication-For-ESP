//
// Created by pythagodzilla on 2026/4/11.
//
#include "Auth.h"
#include <Arduino.h>
#include "mbedtls/sha1.h"

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
}


namespace Auth {
    String buildChksum(const String &challenge,
                       const String &username,
                       const String &hmd5, // 不带 {MD5} 前缀，只要32位hex
                       const String &acId, // "20"
                       const String &ip,
                       const String &n, // "200"
                       const String &type, // "1"
                       const String &info) {
        // 带 {SRBX1} 前缀

        String chkstr;
        chkstr.reserve(challenge.length() * 7 + username.length() + hmd5.length() +
                       acId.length() + ip.length() + n.length() + type.length() + info.length());

        chkstr += challenge;
        chkstr += username;
        chkstr += challenge;
        chkstr += hmd5;
        chkstr += challenge;
        chkstr += acId;
        chkstr += challenge;
        chkstr += ip;
        chkstr += challenge;
        chkstr += n;
        chkstr += challenge;
        chkstr += type;
        chkstr += challenge;
        chkstr += info;

        uint8_t shaOut[20];
        mbedtls_sha1((const unsigned char *) chkstr.c_str(), chkstr.length(), shaOut);

        return toHexLower(shaOut, 20);
    }
}

