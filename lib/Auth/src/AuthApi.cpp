//
// Created by pythagodzilla on 2026/4/10.
//

#include "Auth.h"
#include <ArduinoJson.h>
#include <URLEncoder.h>

namespace Auth {
    String buildPasswordParam(const String &plainPassword, const String &challenge);
    String buildInfo(const char *username, const char *password, const char *ip, const char *challenge);
    String buildChksum(const String &challenge,
                       const String &username,
                       const String &hmd5,
                       const String &acId,
                       const String &ip,
                       const String &n,
                       const String &type,
                       const String &info);
}

namespace {
    WiFiClient tcpClient;
    HttpClient client(tcpClient, BASE_URL, 80);

    bool extractJson(String &target_url) {
        const int startIndex = target_url.indexOf("{");
        const int endIndex = target_url.lastIndexOf("}");

        if (startIndex != -1 && endIndex != -1) {
            target_url = target_url.substring(startIndex, endIndex + 1);
            return true;
        }

        return false;
    }

    String getChallenge(const String &username, const String &ip) {
        const String usernameEnc = URLEncoder.encode(username);
        const String ts = String(millis());
        char target_url[128];
        const int n = snprintf(target_url, sizeof(target_url),
                               "/cgi-bin/get_challenge?username=%s&ip=%s&callback=%s&_=%s",
                               usernameEnc.c_str(), ip.c_str(), ts.c_str(), ts.c_str());
        if (n < 0 || n >= (int) sizeof(target_url)) return "";
        client.get(target_url);

        String response = client.responseBody();
        if (!extractJson(response)) return "";

        JsonDocument json;
        const DeserializationError error = deserializeJson(json, response);
        if (error) {
            Serial.print("Failed to parse JSON: ");
            Serial.println(error.c_str());
            return "";
        }

        return json["challenge"];
    }

    std::pair<bool, String> performPortalLogin(const String &username,
                                                const String &passwordParam,
                                                const String &ip,
                                                const String &chksum,
                                                const String &info,
                                                const String &system) {
        const String usernameEnc = URLEncoderClass::encode(username);
        const String passwordEnc = URLEncoderClass::encode(passwordParam);
        const String infoEnc = URLEncoderClass::encode(info);
        const String osEnc = URLEncoderClass::encode(system);
        const String nameEnc = URLEncoderClass::encode("Windows");
        const String ts = String(millis());
        const char *loginPathFormat =
                "/cgi-bin/srun_portal?"
                "callback=%s"
                "&action=login"
                "&username=%s"
                "&password=%s"
                "&ac_id=20"
                "&ip=%s"
                "&chksum=%s"
                "&info=%s"
                "&n=200"
                "&type=1"
                "&os=%s"
                "&name=%s"
                "&double_stack=0"
                "&_=%s";
        char target_url[1024];
        const int n = snprintf(target_url, sizeof(target_url),
                               loginPathFormat,
                               "callback", usernameEnc.c_str(), passwordEnc.c_str(), ip.c_str(), chksum.c_str(),
                               infoEnc.c_str(), osEnc.c_str(), nameEnc.c_str(), ts.c_str());
        if (n < 0 || n >= (int) sizeof(target_url)) {
            return std::make_pair(false, "URL too long");
        }

        client.get(target_url);
        String response = client.responseBody();
        if (extractJson(response)) {
            JsonDocument json;
            const DeserializationError error = deserializeJson(json, response);
            if (error) {
                Serial.print("Failed to parse JSON: ");
                Serial.println(error.c_str());
                return std::make_pair(false, "Failed to parse JSON");
            }

            const String res = json["res"];
            const String ecode = json["ecode"];

            if (res == "ok") {
                return std::make_pair(true, res.c_str());
            }

            if (ecode == "E2901") {
                return std::make_pair(false, "Incorrect password");
            }
        }
        return std::make_pair(false, response.c_str());
    }
}

namespace Auth {
    std::pair<bool, String> login(const String &username,
                                  const String &password,
                                  const String &system) {
        if (username.isEmpty() || password.isEmpty()) {
            return std::make_pair(false, "Empty username or password");
        }

        const std::pair<bool, String> onlineState = isOnline();
        const String ip = onlineState.second;
        if (ip.isEmpty() || ip.startsWith("Failed")) {
            return std::make_pair(false, "Failed to get client IP");
        }

        const String challenge = getChallenge(username, ip);
        if (challenge.isEmpty()) {
            return std::make_pair(false, "Failed to get challenge");
        }

        const String passwordParam = buildPasswordParam(password, challenge);
        if (!passwordParam.startsWith("{MD5}") || passwordParam.length() <= 5) {
            return std::make_pair(false, "Failed to build password param");
        }

        const String hmd5 = passwordParam.substring(5);
        const String info = buildInfo(username.c_str(), password.c_str(), ip.c_str(), challenge.c_str());
        if (info.isEmpty()) {
            return std::make_pair(false, "Failed to build info");
        }

        const String chksum = buildChksum(challenge, username, hmd5, "20", ip, "200", "1", info);
        if (chksum.isEmpty()) {
            return std::make_pair(false, "Failed to build chksum");
        }

        return performPortalLogin(username, passwordParam, ip, chksum, info, system);
    }

    std::pair<bool, String> isOnline() {
        char target_url[128];
        sprintf(target_url, "/cgi-bin/rad_user_info?callback=callback&_=%s", String(millis()).c_str());
        client.get(target_url);

        const int statusCode = client.responseStatusCode();
        String response = client.responseBody();

        Serial.println();
        Serial.print("Status code: ");
        Serial.println(statusCode);
        Serial.print("Response: ");
        Serial.println(response);

        if (extractJson(response)) {
            JsonDocument json;
            const DeserializationError error = deserializeJson(json, response);
            if (error) {
                Serial.print("Failed to parse JSON: ");
                Serial.println(error.c_str());
                return std::make_pair(false, "Failed to parse JSON");
            }

            const String isOnline = json["error"];
            const String clientIP = json["client_ip"];
            if (isOnline == "ok") {
                return std::make_pair(true, clientIP);
            }

            return std::make_pair(false, clientIP);
        }

        Serial.println("Failed to extract JSON from response");
        return std::make_pair(false, "Failed to extract JSON");
    }
}

