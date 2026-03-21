// Events.h — Poll Pi /events and /status endpoints, buffer new lines for terminal
#pragma once
#include <Arduino.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

#define EV_MAX     80        // ring buffer size
#define EV_MSG_LEN 80        // max chars per line
#define EV_TS_LEN  10
#define BC_HOST_MAX   32
#define BC_AP_MAX     32
#define BC_MODULE_MAX 8

struct BettercapHost {
    char ipv4[16];
    char mac[18];
    char hostname[32];
    char vendor[32];
};

struct BettercapAp {
    char essid[40];
    char bssid[18];
    char security[24];
    int  channel;
    int  rssi;
};

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
static int   ev_wifi_ap_count = 0;
static bool  ev_bettercap    = false;
static char  ev_bc_iface[16] = "?";
static char  ev_bc_wifi_iface[16] = "";
static char  ev_bc_modules[BC_MODULE_MAX][16];
static int   ev_bc_module_count = 0;
static BettercapHost ev_bc_hosts[BC_HOST_MAX];
static int   ev_bc_host_count = 0;
static BettercapAp ev_bc_aps[BC_AP_MAX];
static int   ev_bc_ap_count = 0;

static void evClearBettercap() {
    strlcpy(ev_bc_iface, "?", sizeof(ev_bc_iface));
    ev_bc_wifi_iface[0] = '\0';
    ev_bc_module_count = 0;
    ev_bc_host_count = 0;
    ev_bc_ap_count = 0;
}

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
    ev_wifi_ap_count = doc["wifi_ap_count"] | 0;
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

static bool evFetchBettercap(const char* host, uint16_t port) {
    char url[128];
    snprintf(url, sizeof(url), "http://%s:%u/bettercap", host, port);
    HTTPClient http;
    http.begin(url); http.setTimeout(4000);
    int code = http.GET();
    if (code != 200) { http.end(); return false; }
    String body = http.getString(); http.end();
    JsonDocument doc;
    if (deserializeJson(doc, body)) return false;

    strlcpy(ev_bc_iface, doc["interface"] | "?", sizeof(ev_bc_iface));
    strlcpy(ev_bc_wifi_iface, doc["wifi_interface"] | "", sizeof(ev_bc_wifi_iface));

    ev_bc_module_count = 0;
    JsonArray modules = doc["modules"].as<JsonArray>();
    if (!modules.isNull()) {
        for (JsonVariant mod : modules) {
            if (ev_bc_module_count >= BC_MODULE_MAX) break;
            strlcpy(ev_bc_modules[ev_bc_module_count], mod.as<const char*>() ? mod.as<const char*>() : "", sizeof(ev_bc_modules[0]));
            ev_bc_module_count++;
        }
    }

    ev_bc_host_count = 0;
    JsonArray hosts_arr = doc["hosts"].as<JsonArray>();
    if (!hosts_arr.isNull()) {
        for (JsonObject obj : hosts_arr) {
            if (ev_bc_host_count >= BC_HOST_MAX) break;
            BettercapHost& h = ev_bc_hosts[ev_bc_host_count++];
            strlcpy(h.ipv4, obj["ipv4"] | "", sizeof(h.ipv4));
            strlcpy(h.mac, obj["mac"] | "", sizeof(h.mac));
            strlcpy(h.hostname, obj["hostname"] | "", sizeof(h.hostname));
            strlcpy(h.vendor, obj["vendor"] | "", sizeof(h.vendor));
        }
    }

    ev_bc_ap_count = 0;
    JsonArray aps_arr = doc["wifi_aps"].as<JsonArray>();
    if (!aps_arr.isNull()) {
        for (JsonObject obj : aps_arr) {
            if (ev_bc_ap_count >= BC_AP_MAX) break;
            BettercapAp& ap = ev_bc_aps[ev_bc_ap_count++];
            strlcpy(ap.essid, obj["essid"] | "", sizeof(ap.essid));
            strlcpy(ap.bssid, obj["bssid"] | "", sizeof(ap.bssid));
            strlcpy(ap.security, obj["security"] | "", sizeof(ap.security));
            ap.channel = obj["channel"] | 0;
            ap.rssi = obj["rssi"] | 0;
        }
    }
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
