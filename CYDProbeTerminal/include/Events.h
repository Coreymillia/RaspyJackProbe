// Events.h — Poll Pi /events and /status endpoints, buffer new lines for terminal
#pragma once
#include <Arduino.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

#define EV_MAX     80        // ring buffer size
#define EV_MSG_LEN 80        // max chars per line
#define EV_TS_LEN  10

struct ProbeEvent {
    char ts[EV_TS_LEN];
    char level[8];   // INFO | ALERT | BC | MODE
    char msg[EV_MSG_LEN];
};

static ProbeEvent ev_buf[EV_MAX];
static int  ev_head      = 0;   // next write position
static int  ev_count     = 0;   // total lines ever received (detect new)
static int  ev_last_seen = 0;
static bool ev_new_lines = false;

// Current status fields
static char  ev_mode[24]     = "idle";
static int   ev_device_count = 0;
static bool  ev_bettercap    = false;

static bool evFetchStatus(const char* host, uint16_t port) {
    char url[128];
    snprintf(url, sizeof(url), "http://%s:%u/status", host, port);
    HTTPClient http;
    http.begin(url); http.setTimeout(3000);
    int code = http.GET();
    if (code != 200) { http.end(); return false; }
    String body = http.getString(); http.end();
    JsonDocument doc;
    if (deserializeJson(doc, body)) return false;
    strlcpy(ev_mode, doc["mode"] | "idle", sizeof(ev_mode));
    ev_device_count = doc["device_count"] | 0;
    ev_bettercap    = doc["bettercap"] | false;
    return true;
}

static bool evFetchEvents(const char* host, uint16_t port) {
    char url[128];
    snprintf(url, sizeof(url), "http://%s:%u/events", host, port);
    HTTPClient http;
    http.begin(url); http.setTimeout(3000);
    int code = http.GET();
    if (code != 200) { http.end(); return false; }
    String body = http.getString(); http.end();
    JsonDocument doc;
    if (deserializeJson(doc, body)) return false;
    JsonArray arr = doc["events"].as<JsonArray>();
    if (arr.isNull()) return false;

    int total = arr.size();
    if (total == ev_last_seen) { ev_new_lines = false; return true; }

    // Only process lines we haven't seen
    int start = (ev_last_seen < total) ? ev_last_seen : 0;
    ev_new_lines = true;
    int i = 0;
    for (JsonObject obj : arr) {
        if (i++ < start) continue;
        ProbeEvent& e = ev_buf[ev_head % EV_MAX];
        strlcpy(e.ts,    obj["ts"]    | "",      EV_TS_LEN);
        strlcpy(e.level, obj["level"] | "INFO",  8);
        strlcpy(e.msg,   obj["msg"]   | "",      EV_MSG_LEN);
        ev_head++;
        ev_count++;
    }
    ev_last_seen = total;
    return true;
}

static bool evPostCmd(const char* host, uint16_t port, const char* cmd) {
    char url[128];
    snprintf(url, sizeof(url), "http://%s:%u/cmd", host, port);
    HTTPClient http;
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    char body[64];
    snprintf(body, sizeof(body), "{\"cmd\":\"%s\"}", cmd);
    int code = http.POST(body);
    http.end();
    return code == 200;
}
