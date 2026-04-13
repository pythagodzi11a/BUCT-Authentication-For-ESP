//
// Created by pythagodzilla on 2026/4/11.
//

#include "Auth.h"
#include "mbedtls/md.h"
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

    String srunB64Alphabet = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

    String customBase64(const uint8_t *data, const size_t len) {
        if (!data || len == 0) return "";

        String out;
        out.reserve(((len + 2) / 3) * 4);

        size_t i = 0;
        while (i + 2 < len) {
            const uint32_t b10 = (static_cast<uint32_t>(data[i]) << 16) |
                                 (static_cast<uint32_t>(data[i + 1]) << 8) |
                                 static_cast<uint32_t>(data[i + 2]);
            out += srunB64Alphabet[(b10 >> 18) & 0x3F];
            out += srunB64Alphabet[(b10 >> 12) & 0x3F];
            out += srunB64Alphabet[(b10 >> 6) & 0x3F];
            out += srunB64Alphabet[b10 & 0x3F];
            i += 3;
        }

        const size_t rem = len - i;
        if (rem == 1) {
            const uint32_t b10 = (static_cast<uint32_t>(data[i]) << 16);
            out += srunB64Alphabet[(b10 >> 18) & 0x3F];
            out += srunB64Alphabet[(b10 >> 12) & 0x3F];
            out += '=';
            out += '=';
        } else if (rem == 2) {
            const uint32_t b10 = (static_cast<uint32_t>(data[i]) << 16) |
                                 (static_cast<uint32_t>(data[i + 1]) << 8);
            out += srunB64Alphabet[(b10 >> 18) & 0x3F];
            out += srunB64Alphabet[(b10 >> 12) & 0x3F];
            out += srunB64Alphabet[(b10 >> 6) & 0x3F];
            out += '=';
        }

        return out;
    }

    inline uint32_t charAtSafe(const uint8_t *msg, const size_t msgLen, const size_t idx) {
        return (idx < msgLen) ? static_cast<uint32_t>(msg[idx]) : 0u;
    }

    uint8_t *xencodeBytes(const char *plain, const char *key, size_t &outLen) {
        outLen = 0;
        if (!plain || !key) return nullptr;

        const uint8_t *p = reinterpret_cast<const uint8_t *>(plain);
        const uint8_t *ksrc = reinterpret_cast<const uint8_t *>(key);
        const size_t pLen = strlen(plain);
        const size_t keyLen = strlen(key);

        if (pLen == 0) return nullptr;

        const size_t vCoreLen = (pLen + 3) / 4;
        const size_t vLen = vCoreLen + 1;
        uint32_t *v = static_cast<uint32_t *>(calloc(vLen, sizeof(uint32_t)));
        if (!v) return nullptr;

        for (size_t i = 0, j = 0; j < vCoreLen; i += 4, ++j) {
            v[j] = (charAtSafe(p, pLen, i)) |
                   (charAtSafe(p, pLen, i + 1) << 8) |
                   (charAtSafe(p, pLen, i + 2) << 16) |
                   (charAtSafe(p, pLen, i + 3) << 24);
        }
        v[vLen - 1] = static_cast<uint32_t>(pLen);

        const size_t kCoreLen = (keyLen + 3) / 4;
        const size_t kLen = (kCoreLen < 4) ? 4 : kCoreLen;
        uint32_t *kk = static_cast<uint32_t *>(calloc(kLen, sizeof(uint32_t)));
        if (!kk) {
            free(v);
            return nullptr;
        }

        for (size_t i = 0, j = 0; j < kCoreLen; i += 4, ++j) {
            kk[j] = (charAtSafe(ksrc, keyLen, i)) |
                    (charAtSafe(ksrc, keyLen, i + 1) << 8) |
                    (charAtSafe(ksrc, keyLen, i + 2) << 16) |
                    (charAtSafe(ksrc, keyLen, i + 3) << 24);
        }

        uint32_t n = (uint32_t) (vLen - 1);
        uint32_t z = v[n], y = v[0];
        uint32_t c = 0x9E3779B9u;
        uint32_t d = 0, e, m, pidx;
        int q = (int) (6 + 52 / (n + 1));

        while (q-- > 0) {
            d = d + c;
            e = (d >> 2) & 3u;

            for (pidx = 0; pidx < n; ++pidx) {
                y = v[pidx + 1];
                m = (z >> 5) ^ (y << 2);
                m += ((y >> 3) ^ (z << 4)) ^ (d ^ y);
                m += (kk[(pidx & 3u) ^ e] ^ z);
                v[pidx] = v[pidx] + m;
                z = v[pidx];
            }

            y = v[0];
            m = (z >> 5) ^ (y << 2);
            m += ((y >> 3) ^ (z << 4)) ^ (d ^ y);
            m += (kk[(pidx & 3u) ^ e] ^ z);
            v[n] = v[n] + m;
            z = v[n];
        }

        outLen = vLen * 4;
        uint8_t *out = static_cast<uint8_t *>(malloc(outLen));
        if (!out) {
            free(v);
            free(kk);
            outLen = 0;
            return nullptr;
        }

        for (size_t i = 0; i < vLen; ++i) {
            out[i * 4 + 0] = static_cast<uint8_t>(v[i] & 0xFFu);
            out[i * 4 + 1] = static_cast<uint8_t>((v[i] >> 8) & 0xFFu);
            out[i * 4 + 2] = static_cast<uint8_t>((v[i] >> 16) & 0xFFu);
            out[i * 4 + 3] = static_cast<uint8_t>((v[i] >> 24) & 0xFFu);
        }

        free(v);
        free(kk);
        return out;
    }
}

namespace Auth {
    String buildPasswordParam(const String &plainPassword, const String &challenge) {
        uint8_t hmacOut[16];

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

    String buildInfo(const char *username, const char *password, const char *ip, const char *challenge) {
        String plain = String("{\"username\":\"") + username +
                       "\",\"password\":\"" + password +
                       "\",\"ip\":\"" + ip +
                       "\",\"acid\":\"20\",\"enc_ver\":\"srun_bx1\"}";

        size_t encLen = 0;
        uint8_t *enc = xencodeBytes(plain.c_str(), challenge, encLen);
        if (!enc || encLen == 0) return "";

        String b64 = customBase64(enc, encLen);
        free(enc);

        return "{SRBX1}" + b64;
    }

    String buildChksum(const String &challenge,
                       const String &username,
                       const String &hmd5,
                       const String &acId,
                       const String &ip,
                       const String &n,
                       const String &type,
                       const String &info) {
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

