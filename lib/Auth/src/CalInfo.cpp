//
// Created by pythagodzilla on 2026/4/11.
#include "Auth.h"


/**
 * 此处大量vibe coding,我自己也懒得管了，如果能用就不要管这个了。
 */
namespace {
    String SRUN_B64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

    String customBase64(const uint8_t *data, const size_t len) {
        if (!data || len == 0) return "";

        String out;
        out.reserve(((len + 2) / 3) * 4);

        size_t i = 0;
        while (i + 2 < len) {
            const uint32_t b10 = (static_cast<uint32_t>(data[i]) << 16) |
                                 (static_cast<uint32_t>(data[i + 1]) << 8) |
                                 static_cast<uint32_t>(data[i + 2]);
            out += SRUN_B64_ALPHABET[(b10 >> 18) & 0x3F];
            out += SRUN_B64_ALPHABET[(b10 >> 12) & 0x3F];
            out += SRUN_B64_ALPHABET[(b10 >> 6) & 0x3F];
            out += SRUN_B64_ALPHABET[b10 & 0x3F];
            i += 3;
        }

        const size_t rem = len - i;
        if (rem == 1) {
            const uint32_t b10 = (static_cast<uint32_t>(data[i]) << 16);
            out += SRUN_B64_ALPHABET[(b10 >> 18) & 0x3F];
            out += SRUN_B64_ALPHABET[(b10 >> 12) & 0x3F];
            out += '=';
            out += '=';
        } else if (rem == 2) {
            const uint32_t b10 = (static_cast<uint32_t>(data[i]) << 16) |
                                 (static_cast<uint32_t>(data[i + 1]) << 8);
            out += SRUN_B64_ALPHABET[(b10 >> 18) & 0x3F];
            out += SRUN_B64_ALPHABET[(b10 >> 12) & 0x3F];
            out += SRUN_B64_ALPHABET[(b10 >> 6) & 0x3F];
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

        // s(plain, true)
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

        // s(key, false), 至少 4 个 uint32
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
            m += (kk[(pidx & 3u) ^ e] ^ z); // 此时 pidx == n
            v[n] = v[n] + m;
            z = v[n];
        }

        // l(v, false): 每个 uint32 转 4 字节（小端）
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
}
