#include <Arduino.h>

#include "Auth/Auth.h"

const char* ssid = "抽刀断牛刀两段";
const char* password = "cddndldadnnsgz";

void setup() {
// write your initialization code here
    Serial.begin(115200);
    pinMode(LED_BUILTIN, OUTPUT);
    WiFi.begin(ssid,password);
    while (WiFiClass::status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    delay(5000);
    Auth::isOnline();
}

void loop() {
// write your code here
    Serial.println("");
    delay(5000);
}