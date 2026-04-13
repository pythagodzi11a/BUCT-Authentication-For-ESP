//
// Created by pythagodzilla on 2026/4/10.
//

#pragma once
#include <ArduinoHttpClient.h>
#include <WiFi.h>

#define BASE_URL "tree.buct.edu.cn"
#define BASE_URL_IP "202.4.130.95"

namespace Auth {

    std::pair<bool, String> isOnline();

    std::pair<bool, String> login(const String &username,
                                  const String &password,
                                  const String &system = "Windows 95");
}
