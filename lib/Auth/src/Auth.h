//
// Created by pythagodzilla on 2026/4/10.
//

#pragma once
#include <ArduinoHttpClient.h>
#include <WiFi.h>

#define BASE_URL "tree.buct.edu.cn"
#define BASE_URL_IP "202.4.130.95"

namespace Auth {
    extern WiFiClient tcpClient;
    extern HttpClient client;

    std::pair<bool, String> isOnline();

    std::pair<bool, String> loginWithPlainPassword(const String &username, const String &password);

    std::pair<bool, String> login(const String &username, const String &password_param,
                                  const String &ip, const String &CHKSUM, const String &info);

    String getChallenge(const String &username, const String &ip);

    String genInfo(const String &username, const String &password, const String &ip);

    String buildPasswordParam(const String &plainPassword, const String &challenge);

    String buildInfo(const char *username, const char *password, const char *ip, const char *challenge);

    String buildChksum(const String &challenge,
                       const String &username,
                       const String &hmd5, // 不带 {MD5} 前缀，只要32位hex
                       const String &acId, // "20"
                       const String &ip,
                       const String &n, // "200"
                       const String &type, // "1"
                       const String &info);
}

namespace CalInfo {
    extern String SRUN_B64_ALPHABET;

    String customBase64(const uint8_t *data, size_t len);

    String buildInfo(const char *username, const char *password, const char *ip, const char *challenge);
}

namespace CalPasswordParam {
    String toHexLower(const uint8_t *data, size_t len);

    String buildPasswordParam(const String &plainPassword, const String &challenge);
}
