#include <Arduino.h>

#include "Auth/Auth.h"

const char *ssid = "";
const char *password = "";
const char *portalUser = "";
const char *portalPass = "";


unsigned long lastCheckMs = 0;
const unsigned long checkIntervalMs = 30000; // 30s

void ensureWiFi() {
    if (WiFi.status() == WL_CONNECTED) return;
    WiFi.begin(ssid, password);
    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 10000) {
        delay(300);
    }
}


void ensurePortal() {
    const std::pair<bool, String> onlineResult = Auth::isOnline();
    const bool online = onlineResult.first;
    if (online) return;

    const std::pair<bool, String> loginResult = Auth::loginWithPlainPassword(portalUser, portalPass);
    const bool ok = loginResult.first;
    const String msg = loginResult.second;
    Serial.print("Portal relogin: ");
    Serial.println(ok ? "OK" : msg);
}

void setup() {
    Serial.begin(115200);
    ensureWiFi();
    ensurePortal();
}

void loop() {
    if (millis() - lastCheckMs >= checkIntervalMs) {
        lastCheckMs = millis();
        ensureWiFi();
        ensurePortal();
    }
}
