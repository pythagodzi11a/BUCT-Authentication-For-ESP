//
// Created by pythagodzilla on 2026/4/10.
//

#pragma once
#include <ArduinoHttpClient.h>
#include <WiFi.h>

#define BASE_URL "http://tree.buct.edu.cn"
#define BASE_URL_IP "http://202.4.130.95"

namespace Auth {
    /**
     *
     */
    WiFiClient tcpClient;
    auto client = HttpClient(tcpClient, BASE_URL,80); 
}