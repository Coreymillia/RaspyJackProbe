// Portal.h — WiFi captive portal + NVS settings for CYDProbeTerminal
// Stores: WiFi SSID/pass, Pi IP, Pi event-server port (default 8765)

#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

static char     pt_wifi_ssid[64] = "";
static char     pt_wifi_pass[64] = "";
static char     pt_pi_ip[64]     = "192.168.0.121";
static uint16_t pt_pi_port       = 9090;
static bool     pt_has_settings  = false;

static Preferences _pt_prefs;

static void ptLoadSettings() {
    _pt_prefs.begin("cydprobe", true);
    pt_has_settings = _pt_prefs.getBool("configured", false);
    strlcpy(pt_wifi_ssid, _pt_prefs.getString("ssid",  "").c_str(),             sizeof(pt_wifi_ssid));
    strlcpy(pt_wifi_pass, _pt_prefs.getString("wpass", "").c_str(),             sizeof(pt_wifi_pass));
    strlcpy(pt_pi_ip,     _pt_prefs.getString("piip",  "192.168.0.121").c_str(), sizeof(pt_pi_ip));
    pt_pi_port = (uint16_t)_pt_prefs.getUInt("piport", 9090);
    _pt_prefs.end();
}

static void ptSaveSettings(const char* ssid, const char* wpass,
                            const char* piip, uint16_t piport) {
    _pt_prefs.begin("cydprobe", false);
    _pt_prefs.putBool("configured", true);
    _pt_prefs.putString("ssid",   ssid);
    _pt_prefs.putString("wpass",  wpass);
    _pt_prefs.putString("piip",   piip);
    _pt_prefs.putUInt("piport",   piport);
    _pt_prefs.end();
    strlcpy(pt_wifi_ssid, ssid,  sizeof(pt_wifi_ssid));
    strlcpy(pt_wifi_pass, wpass, sizeof(pt_wifi_pass));
    strlcpy(pt_pi_ip,     piip,  sizeof(pt_pi_ip));
    pt_pi_port     = piport;
    pt_has_settings = true;
}

static WebServer _pt_server(80);
static DNSServer _pt_dns;

static const char PT_HTML[] PROGMEM = R"html(
<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:monospace;background:#0d0d0d;color:#00ff88;padding:20px}
h2{color:#00ff88;border-bottom:1px solid #333;padding-bottom:8px}
label{display:block;margin-top:14px;color:#aaa;font-size:13px}
input{width:100%;padding:8px;margin:4px 0;box-sizing:border-box;
      background:#1a1a1a;color:#00ff88;border:1px solid #333;
      border-radius:4px;font-family:monospace;font-size:14px}
button{margin-top:20px;width:100%;padding:12px;background:#003322;
       color:#00ff88;border:1px solid #00aa55;border-radius:6px;
       font-size:16px;cursor:pointer;font-family:monospace}
</style></head><body>
<h2>&#x25A3; PROBE TERMINAL Setup</h2>
<form method="POST" action="/save">
<label>WiFi SSID</label>
<input name="ssid"   value="{SSID}">
<label>WiFi Password</label>
<input name="wpass"  type="password">
<label>Pi IP Address</label>
<input name="piip"   value="{PIIP}">
<label>Pi Event Port (default 9090)</label>
<input name="piport" type="number" value="{PIPORT}">
<button type="submit">&#x25B6; Save &amp; Connect</button>
</form></body></html>
)html";

static void _ptHandleRoot() {
    String page = PT_HTML;
    page.replace("{SSID}",   pt_wifi_ssid);
    page.replace("{PIIP}",   pt_pi_ip);
    char pb[8]; snprintf(pb, sizeof(pb), "%u", pt_pi_port);
    page.replace("{PIPORT}", pb);
    _pt_server.send(200, "text/html", page);
}

static void _ptHandleSave() {
    String ssid   = _pt_server.arg("ssid");
    String wpass  = _pt_server.arg("wpass");
    String piip   = _pt_server.arg("piip");
    String piport = _pt_server.arg("piport");
    ptSaveSettings(ssid.c_str(), wpass.c_str(), piip.c_str(),
                   (uint16_t)piport.toInt());
    _pt_server.send(200, "text/html",
        "<html><body style='background:#0d0d0d;color:#00ff88;font-family:monospace;padding:20px'>"
        "<h2>&#10003; Saved! Rebooting...</h2></body></html>");
    delay(1500);
    ESP.restart();
}

static void ptRunPortal() {
    WiFi.mode(WIFI_AP);
    WiFi.softAP("ProbeTerminal-Setup");
    _pt_dns.start(53, "*", WiFi.softAPIP());
    _pt_server.on("/",      _ptHandleRoot);
    _pt_server.on("/save",  HTTP_POST, _ptHandleSave);
    _pt_server.onNotFound(  _ptHandleRoot);
    _pt_server.begin();
    while (true) {
        _pt_dns.processNextRequest();
        _pt_server.handleClient();
        delay(2);
    }
}

// Returns true when connected, runs portal forever if it can't connect.
static bool ptConnect() {
    ptLoadSettings();
    if (!pt_has_settings || strlen(pt_wifi_ssid) == 0) {
        ptRunPortal();
    }
    WiFi.mode(WIFI_STA);
    WiFi.begin(pt_wifi_ssid, pt_wifi_pass);
    unsigned long t = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t < 15000) {
        delay(250);
    }
    if (WiFi.status() != WL_CONNECTED) {
        ptRunPortal();
    }
    return true;
}
