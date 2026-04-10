//
// Created by pythagodzilla on 2026/4/10.
//

#include "Auth.h"
#include <ArduinoJson.h>
#include <URLEncoder.h>

namespace {
    /**
     *
     * @param target_url 传入要解JSONP的字符串，解出JSON后会覆盖原字符串。
     * @return bool 是否成功解出JSON
     */
    bool extractJson(String &target_url) {
        const int startIndex = target_url.indexOf("{");
        const int endIndex = target_url.lastIndexOf("}");

        if (startIndex != -1 && endIndex != -1) {
            target_url = target_url.substring(startIndex, endIndex + 1);
            return true;
        }

        return false;
    }
}

namespace Auth {
    WiFiClient tcpClient;
    HttpClient client(tcpClient, BASE_URL, 80);

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

        // const int startIndex = response.indexOf("{");
        // const int endIndex = response.indexOf("}");

        if (extractJson(response)) {
            // const String jsonString = response.substring(startIndex, endIndex + 1);
            // Serial.print("Extracted JSON: ");
            // Serial.println(jsonString);

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


    String getChallenge(const String &username, const String &ip) {
        const String usernameEnc = URLEncoder.encode(username);
        const String ts = String(millis());
        char target_url[128];
        const int n = snprintf(target_url, sizeof(target_url),
                               "/cgi-bin/get_challenge?username=%s&ip=%s&callback=%s&_=%s",
                               usernameEnc.c_str(), ip.c_str(), ts.c_str(), ts.c_str());
        if (n < 0 || n >= (int)sizeof(target_url)) return "";
        client.get(target_url);

        String response = client.responseBody();
        if (extractJson(response)) {
            JsonDocument json;
            const DeserializationError error = deserializeJson(json, response);

            if (error) {
                Serial.print("Failed to parse JSON: ");
                Serial.println(error.c_str());
                return "";
            }

            const String challenge = json["challenge"];
            return challenge;
        }

        return "";
    }


    std::pair<bool, String> login(const String &username, const String &password_param,
                                  const String &ip, const String &CHKSUM, const String &info) {
        const String usernameEnc = URLEncoder.encode(username);
        const String passwordEnc = URLEncoder.encode(password_param);
        const String infoEnc = URLEncoder.encode(info);
        const String osEnc = URLEncoder.encode("Windows 95");
        const String nameEnc = URLEncoder.encode("Windows");
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
                               "callback", usernameEnc.c_str(), passwordEnc.c_str(), ip.c_str(), CHKSUM.c_str(),
                               infoEnc.c_str(), osEnc.c_str(), nameEnc.c_str(), ts.c_str());
        if (n < 0 || n >= (int)sizeof(target_url)) {
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
