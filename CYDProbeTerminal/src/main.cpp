/**
 * CYDProbeTerminal — Matrix-style terminal display + touch control overlay
 * for RaspyJackProbe Pi.
 *
 * Hardware: ESP32 "Cheap Yellow Display" (ESP32-2432S028)
 *   - ILI9341 320x240 TFT (landscape)
 *   - XPT2046 resistive touch
 *
 * Default view: scrolling green-on-black terminal log of Pi events.
 *   - Green  = INFO   (mode started, device count)
 *   - Red    = ALERT  (new device, MAC change, spike)
 *   - Yellow = BC     (bettercap updates)
 *   - Cyan   = MODE   (mode changes)
 *
 * Tap anywhere → control overlay, or Bettercap detail tabs while in Bettercap mode.
 * Buttons POST /cmd to Pi event server on port 8765.
 */

#include <Arduino.h>
#include <SPI.h>
#include <WiFi.h>
#include <Arduino_GFX_Library.h>
#include <XPT2046_Touchscreen.h>
#include "Portal.h"
#include "Events.h"

// ── Display (CYD non-inverted hardware SPI) ──────────────────────────────────
#define GFX_BL 21
Arduino_DataBus *bus = new Arduino_HWSPI(2 /*DC*/, 15 /*CS*/, 14 /*SCK*/, 13 /*MOSI*/, 12 /*MISO*/);
Arduino_GFX    *gfx = new Arduino_ILI9341(bus, GFX_NOT_DEFINED, 1 /*landscape*/);

// ── Touch (CYD VSPI) ─────────────────────────────────────────────────────────
#define XPT2046_IRQ  36
#define XPT2046_CS   33
#define XPT2046_CLK  25
#define XPT2046_MOSI 32
#define XPT2046_MISO 39
SPIClass touchSPI(VSPI);
XPT2046_Touchscreen ts(XPT2046_CS, XPT2046_IRQ);

// ── Layout ───────────────────────────────────────────────────────────────────
#define W         320
#define H         240
#define HDR_H     18    // top status bar
#define TERM_Y    HDR_H
#define TERM_H    (H - HDR_H)
#define LINE_H    12
#define CHAR_W    6
#define COLS      (W / CHAR_W)           // 53 chars
#define TERM_ROWS (TERM_H / LINE_H)      // 18 rows

// ── Colors (RGB565) ──────────────────────────────────────────────────────────
#define C_BG       0x0000
#define C_HDR      0x0210   // dark green
#define C_HDR_TXT  0x07E0   // bright green
#define C_INFO     0x07E0   // green
#define C_ALERT    0xF800   // red
#define C_BC       0xFFE0   // yellow
#define C_MODE     0x07FF   // cyan
#define C_SCAN     0xFD20   // orange
#define C_RJ       0xFDA0   // amber  — RaspyJack live output
#define C_LOOT     0xF81F   // magenta — loot file updates
#define C_DIM      0x2945   // dark grey
#define C_WHITE    0xFFFF
#define C_OVERLAY  0x0841   // near-black overlay tint

// ── Terminal ring buffer (rendered lines) ────────────────────────────────────
struct TermLine {
    char    text[COLS + 1];
    uint16_t color;
};
static TermLine term[TERM_ROWS * 2];   // double height for smooth scroll
static int      term_write = 0;        // next write row (absolute)
static int      term_scroll_row = 0;   // topmost visible row (absolute)
static bool     term_dirty = true;

static uint16_t levelColor(const char* level) {
    if (strncmp(level, "ALERT", 5) == 0) return C_ALERT;
    if (strncmp(level, "BC",    2) == 0) return C_BC;
    if (strncmp(level, "MODE",  4) == 0) return C_MODE;
    if (strncmp(level, "SCAN",  4) == 0) return C_SCAN;
    if (strncmp(level, "RJ",    2) == 0) return C_RJ;
    if (strncmp(level, "LOOT",  4) == 0) return C_LOOT;
    return C_INFO;
}

// Push one event line into the terminal buffer (wraps long lines).
static void termPush(const char* ts, const char* level, const char* msg) {
    uint16_t col = levelColor(level);

    // Format: "HH:MM:SS [LVL] message..."
    char full[160];
    snprintf(full, sizeof(full), "%s [%s] %s", ts, level, msg);

    int len = strlen(full);
    int pos = 0;
    do {
        TermLine& tl = term[term_write % (TERM_ROWS * 2)];
        int take = min(len - pos, COLS);
        strncpy(tl.text, full + pos, take);
        tl.text[take] = '\0';
        tl.color = col;
        term_write++;
        pos += take;
    } while (pos < len);

    // Keep scroll pinned to bottom
    if (term_write > TERM_ROWS) {
        term_scroll_row = term_write - TERM_ROWS;
    } else {
        term_scroll_row = 0;
    }
    term_dirty = true;
}

static void termRedraw() {
    if (!term_dirty) return;
    gfx->fillRect(0, TERM_Y, W, TERM_H, C_BG);
    gfx->setTextSize(1);
    for (int r = 0; r < TERM_ROWS; r++) {
        int abs_r = term_scroll_row + r;
        if (abs_r >= term_write) break;
        TermLine& tl = term[abs_r % (TERM_ROWS * 2)];
        gfx->setTextColor(tl.color, C_BG);
        gfx->setCursor(0, TERM_Y + r * LINE_H);
        gfx->print(tl.text);
    }
    term_dirty = false;
}

// ── Status header ─────────────────────────────────────────────────────────────
static void drawHeader() {
    gfx->fillRect(0, 0, W, HDR_H, C_HDR);
    gfx->setTextColor(C_HDR_TXT, C_HDR);
    gfx->setTextSize(1);

    // Left: mode
    char left[40];
    snprintf(left, sizeof(left), "%-12s", ev_mode);
    gfx->setCursor(4, 5);
    gfx->print(left);

    // Right: device count + wifi
    char right[32];
    snprintf(right, sizeof(right), "h:%d ap:%d %s",
             ev_device_count,
             ev_wifi_ap_count,
             (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString().c_str() : "no wifi");
    gfx->setCursor(W - strlen(right) * CHAR_W - 4, 5);
    gfx->print(right);
}

// ── Control overlay ───────────────────────────────────────────────────────────
static bool overlay_visible = false;
enum BettercapView { BC_VIEW_SUMMARY, BC_VIEW_HOSTS, BC_VIEW_WIFI };
static BettercapView bc_view = BC_VIEW_SUMMARY;
static int bc_host_page = 0;
static int bc_wifi_page = 0;
#define BC_HOSTS_PER_PAGE 5
#define BC_APS_PER_PAGE   5

struct OvButton {
    const char* label;
    const char* cmd;
    uint16_t    bg;
    int16_t     x, y, w, h;
};

static OvButton ov_buttons[] = {
    { "ANOMALY",      "anomaly_detector", 0x0320,  10,  40,  96, 34 },
    { "RASPYJACK",    "raspyjack",        0x620C, 112,  40,  96, 34 },
    { "BETTERCAP",    "bettercap",        0x0059, 214,  40,  96, 34 },
    { "WIFI SCAN",    "wifi_scan",        0x0410,  10,  80,  96, 34 },
    { "QUICK SCAN",   "quick_scan",       0x4200, 112,  80,  96, 34 },
    { "PORT SCAN",    "port_scan",        0x3008, 214,  80,  96, 34 },
    { "STOP MODE",    "stop",             0x6000,  10, 124, 300, 36 },
};
#define N_OV_BUTTONS 7

// RaspyJack submenu — shown when Pi mode == "raspyjack"
static OvButton rj_buttons[] = {
    { "NET SCAN",     "rj_net_scan",  0x0320,  10,  40, 140, 36 },
    { "ARP SCAN",     "rj_arp_scan",  0x0059, 165,  40, 145, 36 },
    { "PORT SCAN",    "rj_port_scan", 0x3008,  10,  82, 140, 36 },
    { "SHOW LOOT",    "rj_loot",      0x620C, 165,  82, 145, 36 },
    { "STOP RJ",      "rj_stop",      0x6000,  10, 124, 300, 36 },
};
#define N_RJ_BUTTONS 5

static bool isBettercapMode() {
    return (strncmp(ev_mode, "bettercap", 9) == 0) || (strncmp(ev_mode, "mitm", 4) == 0);
}

static int pageCount(int total, int per_page) {
    return (total <= 0) ? 1 : ((total + per_page - 1) / per_page);
}

static void drawBcTab(const char* label, int16_t x, int16_t y, int16_t w, bool active) {
    uint16_t bg = active ? 0x0059 : 0x1082;
    uint16_t fg = active ? C_WHITE : C_DIM;
    gfx->fillRoundRect(x, y, w, 24, 5, bg);
    gfx->drawRoundRect(x, y, w, 24, 5, C_HDR_TXT);
    gfx->setTextColor(fg, bg);
    gfx->setTextSize(1);
    int tx = x + (w - strlen(label) * CHAR_W) / 2;
    gfx->setCursor(tx, y + 8);
    gfx->print(label);
}

static void drawBettercapSummary(int16_t y0) {
    gfx->setTextSize(1);
    gfx->setTextColor(C_HDR_TXT, C_BG);
    gfx->setCursor(12, y0);
    gfx->print("SUMMARY");

    char line[96];
    gfx->setTextColor(C_WHITE, C_BG);
    snprintf(line, sizeof(line), "LAN IF: %s", ev_bc_iface);
    gfx->setCursor(12, y0 + 16); gfx->print(line);
    snprintf(line, sizeof(line), "WIFI IF: %s", strlen(ev_bc_wifi_iface) ? ev_bc_wifi_iface : "off");
    gfx->setCursor(12, y0 + 30); gfx->print(line);
    snprintf(line, sizeof(line), "HOSTS: %d   APS: %d", ev_device_count, ev_wifi_ap_count);
    gfx->setCursor(12, y0 + 44); gfx->print(line);

    gfx->setTextColor(C_BC, C_BG);
    gfx->setCursor(12, y0 + 62); gfx->print("MODULES");
    gfx->setTextColor(C_WHITE, C_BG);
    int mx = 12, my = y0 + 76;
    for (int i = 0; i < ev_bc_module_count; i++) {
        int len = strlen(ev_bc_modules[i]) * CHAR_W + 14;
        if (mx + len > W - 12) {
            mx = 12;
            my += 14;
        }
        gfx->fillRoundRect(mx, my - 2, len, 12, 4, 0x1082);
        gfx->setCursor(mx + 6, my);
        gfx->print(ev_bc_modules[i]);
        mx += len + 6;
    }

    gfx->setTextColor(C_INFO, C_BG);
    gfx->setCursor(12, y0 + 104);
    if (ev_bc_host_count > 0) {
        snprintf(line, sizeof(line), "HOST SAMPLE: %s  %s", ev_bc_hosts[0].ipv4, ev_bc_hosts[0].mac);
        gfx->print(line);
    } else {
        gfx->print("HOST SAMPLE: waiting...");
    }

    gfx->setTextColor(C_BC, C_BG);
    gfx->setCursor(12, y0 + 118);
    if (ev_bc_ap_count > 0) {
        const char* name = strlen(ev_bc_aps[0].essid) ? ev_bc_aps[0].essid : ev_bc_aps[0].bssid;
        snprintf(line, sizeof(line), "WIFI SAMPLE: %.20s ch%d %ddBm", name, ev_bc_aps[0].channel, ev_bc_aps[0].rssi);
        gfx->print(line);
    } else {
        gfx->print("WIFI SAMPLE: waiting...");
    }
}

static void drawBettercapHosts(int16_t y0) {
    gfx->setTextSize(1);
    gfx->setTextColor(C_HDR_TXT, C_BG);
    gfx->setCursor(12, y0);
    char hdr[48];
    int total_pages = pageCount(max(ev_bc_host_count, 1), BC_HOSTS_PER_PAGE);
    snprintf(hdr, sizeof(hdr), "HOSTS  %d/%d", bc_host_page + 1, total_pages);
    gfx->print(hdr);

    if (ev_bc_host_count == 0) {
        gfx->setTextColor(C_DIM, C_BG);
        gfx->setCursor(12, y0 + 24);
        gfx->print("No host details yet.");
        return;
    }

    int start = bc_host_page * BC_HOSTS_PER_PAGE;
    int end = min(start + BC_HOSTS_PER_PAGE, ev_bc_host_count);
    int y = y0 + 18;
    for (int i = start; i < end; i++) {
        BettercapHost& h = ev_bc_hosts[i];
        char line[96];
        gfx->setTextColor(C_WHITE, C_BG);
        snprintf(line, sizeof(line), "%s  %s", h.ipv4, h.mac);
        gfx->setCursor(12, y); gfx->print(line);
        gfx->setTextColor(C_DIM, C_BG);
        const char* extra = strlen(h.hostname) ? h.hostname : h.vendor;
        snprintf(line, sizeof(line), "%s", strlen(extra) ? extra : "(no hostname)");
        gfx->setCursor(18, y + 10); gfx->print(line);
        y += 24;
    }
}

static void drawBettercapWifi(int16_t y0) {
    gfx->setTextSize(1);
    gfx->setTextColor(C_HDR_TXT, C_BG);
    gfx->setCursor(12, y0);
    char hdr[48];
    int total_pages = pageCount(max(ev_bc_ap_count, 1), BC_APS_PER_PAGE);
    snprintf(hdr, sizeof(hdr), "WIFI  %d/%d", bc_wifi_page + 1, total_pages);
    gfx->print(hdr);

    if (ev_bc_ap_count == 0) {
        gfx->setTextColor(C_DIM, C_BG);
        gfx->setCursor(12, y0 + 24);
        gfx->print("No AP details yet.");
        return;
    }

    int start = bc_wifi_page * BC_APS_PER_PAGE;
    int end = min(start + BC_APS_PER_PAGE, ev_bc_ap_count);
    int y = y0 + 18;
    for (int i = start; i < end; i++) {
        BettercapAp& ap = ev_bc_aps[i];
        char line[96];
        const char* name = strlen(ap.essid) ? ap.essid : ap.bssid;
        gfx->setTextColor(C_WHITE, C_BG);
        snprintf(line, sizeof(line), "%.24s", name);
        gfx->setCursor(12, y); gfx->print(line);
        gfx->setTextColor(C_DIM, C_BG);
        snprintf(line, sizeof(line), "ch:%d  rssi:%d  %.16s", ap.channel, ap.rssi, ap.security);
        gfx->setCursor(18, y + 10); gfx->print(line);
        y += 24;
    }
}

static void drawBettercapOverlay() {
    gfx->fillRect(0, 0, W, H, C_OVERLAY);
    gfx->fillRect(0, 0, W, 34, 0x0030);
    gfx->setTextColor(C_WHITE, 0x0030);
    gfx->setTextSize(2);
    gfx->setCursor(8, 8);
    gfx->print("BETTERCAP");

    gfx->fillRoundRect(270, 5, 40, 24, 4, 0x2000);
    gfx->drawRoundRect(270, 5, 40, 24, 4, 0x6000);
    gfx->setTextColor(0xF800, 0x2000);
    gfx->setTextSize(2);
    gfx->setCursor(283, 10);
    gfx->print("X");

    drawBcTab("SUMMARY", 10, 42, 92, bc_view == BC_VIEW_SUMMARY);
    drawBcTab("HOSTS",   114, 42, 92, bc_view == BC_VIEW_HOSTS);
    drawBcTab("WIFI",    218, 42, 92, bc_view == BC_VIEW_WIFI);

    gfx->fillRoundRect(8, 74, 304, 112, 6, C_BG);
    gfx->drawRoundRect(8, 74, 304, 112, 6, C_DIM);
    if (bc_view == BC_VIEW_SUMMARY) drawBettercapSummary(84);
    else if (bc_view == BC_VIEW_HOSTS) drawBettercapHosts(84);
    else drawBettercapWifi(84);

    bool can_prev = false, can_next = false;
    if (bc_view == BC_VIEW_HOSTS) {
        can_prev = bc_host_page > 0;
        can_next = (bc_host_page + 1) < pageCount(ev_bc_host_count, BC_HOSTS_PER_PAGE);
    } else if (bc_view == BC_VIEW_WIFI) {
        can_prev = bc_wifi_page > 0;
        can_next = (bc_wifi_page + 1) < pageCount(ev_bc_ap_count, BC_APS_PER_PAGE);
    }

    uint16_t prev_bg = can_prev ? 0x1082 : 0x0841;
    uint16_t next_bg = can_next ? 0x1082 : 0x0841;
    gfx->fillRoundRect(10, 198, 80, 32, 6, prev_bg);
    gfx->drawRoundRect(10, 198, 80, 32, 6, C_HDR_TXT);
    gfx->setTextColor(can_prev ? C_WHITE : C_DIM, prev_bg);
    gfx->setTextSize(2);
    gfx->setCursor(35, 206);
    gfx->print("<");

    gfx->fillRoundRect(104, 198, 112, 32, 6, 0x6000);
    gfx->drawRoundRect(104, 198, 112, 32, 6, C_WHITE);
    gfx->setTextColor(C_WHITE, 0x6000);
    gfx->setTextSize(1);
    gfx->setCursor(134, 210);
    gfx->print("STOP MODE");

    gfx->fillRoundRect(230, 198, 80, 32, 6, next_bg);
    gfx->drawRoundRect(230, 198, 80, 32, 6, C_HDR_TXT);
    gfx->setTextColor(can_next ? C_WHITE : C_DIM, next_bg);
    gfx->setTextSize(2);
    gfx->setCursor(259, 206);
    gfx->print(">");
}

static void drawOverlay() {
    if (isBettercapMode()) {
        drawBettercapOverlay();
        return;
    }
    bool is_rj = (strncmp(ev_mode, "raspyjack", 9) == 0);
    OvButton* btns = is_rj ? rj_buttons : ov_buttons;
    int       n    = is_rj ? N_RJ_BUTTONS : N_OV_BUTTONS;

    gfx->fillRect(0, 0, W, H, C_OVERLAY);

    // Title bar
    gfx->fillRect(0, 0, W, 34, is_rj ? 0x3000 : 0x0210);
    gfx->setTextColor(is_rj ? C_RJ : C_HDR_TXT, is_rj ? 0x3000 : 0x0210);
    gfx->setTextSize(2);
    gfx->setCursor(8, 8);
    gfx->print(is_rj ? "RASPYJACK CTL" : "PROBE CONTROL");

    // Buttons
    gfx->setTextSize(1);
    for (int i = 0; i < n; i++) {
        OvButton& b = btns[i];
        gfx->fillRoundRect(b.x, b.y, b.w, b.h, 6, b.bg);
        gfx->drawRoundRect(b.x, b.y, b.w, b.h, 6, C_HDR_TXT);
        int tx = b.x + (b.w - strlen(b.label) * CHAR_W) / 2;
        int ty = b.y + (b.h - 8) / 2;
        gfx->setTextColor(C_WHITE, b.bg);
        gfx->setCursor(tx, ty);
        gfx->print(b.label);
    }

    // Status strip
    gfx->fillRect(0, 170, W, 24, 0x1082);
    gfx->setTextColor(C_DIM, 0x1082);
    gfx->setTextSize(1);
    char status[64];
    snprintf(status, sizeof(status), "mode:%-10s h:%d ap:%d",
             ev_mode, ev_device_count, ev_wifi_ap_count);
    gfx->setCursor(8, 178);
    gfx->print(status);

    // X / dismiss button
    gfx->fillRoundRect(10, 200, 300, 32, 6, 0x2000);
    gfx->drawRoundRect(10, 200, 300, 32, 6, 0x6000);
    gfx->setTextColor(0xF800, 0x2000);
    gfx->setTextSize(2);
    int tx = 10 + (300 - 3 * CHAR_W * 2) / 2;
    gfx->setCursor(tx, 210);
    gfx->print("X  BACK");
}

// Returns true if overlay should close (X tapped or command sent)
static bool handleOverlayTouch(int tx, int ty) {
    if (isBettercapMode()) {
        if (tx >= 270 && tx <= 310 && ty >= 5 && ty <= 29) {
            return true;
        }
        if (ty >= 42 && ty <= 66) {
            if (tx >= 10 && tx <= 102) {
                bc_view = BC_VIEW_SUMMARY;
                drawOverlay();
                return false;
            }
            if (tx >= 114 && tx <= 206) {
                bc_view = BC_VIEW_HOSTS;
                drawOverlay();
                return false;
            }
            if (tx >= 218 && tx <= 310) {
                bc_view = BC_VIEW_WIFI;
                drawOverlay();
                return false;
            }
        }
        if (tx >= 104 && tx <= 216 && ty >= 198 && ty <= 230) {
            evPostCmd(pt_pi_ip, pt_pi_port, "stop");
            return true;
        }
        if (tx >= 10 && tx <= 90 && ty >= 198 && ty <= 230) {
            if (bc_view == BC_VIEW_HOSTS && bc_host_page > 0) bc_host_page--;
            if (bc_view == BC_VIEW_WIFI && bc_wifi_page > 0) bc_wifi_page--;
            drawOverlay();
            return false;
        }
        if (tx >= 230 && tx <= 310 && ty >= 198 && ty <= 230) {
            int max_host_page = pageCount(ev_bc_host_count, BC_HOSTS_PER_PAGE) - 1;
            int max_wifi_page = pageCount(ev_bc_ap_count, BC_APS_PER_PAGE) - 1;
            if (bc_view == BC_VIEW_HOSTS && bc_host_page < max_host_page) bc_host_page++;
            if (bc_view == BC_VIEW_WIFI && bc_wifi_page < max_wifi_page) bc_wifi_page++;
            drawOverlay();
            return false;
        }
        return false;
    }
    // X / Back button
    if (tx >= 10 && tx <= 310 && ty >= 200 && ty <= 232) {
        return true;
    }
    bool is_rj = (strncmp(ev_mode, "raspyjack", 9) == 0);
    OvButton* btns = is_rj ? rj_buttons : ov_buttons;
    int       n    = is_rj ? N_RJ_BUTTONS : N_OV_BUTTONS;
    for (int i = 0; i < n; i++) {
        OvButton& b = btns[i];
        if (tx >= b.x && tx <= b.x + b.w && ty >= b.y && ty <= b.y + b.h) {
            // Flash button
            gfx->fillRoundRect(b.x, b.y, b.w, b.h, 6, C_HDR_TXT);
            gfx->setTextColor(C_BG, C_HDR_TXT);
            gfx->setTextSize(1);
            int ltx = b.x + (b.w - strlen(b.label) * CHAR_W) / 2;
            int lty = b.y + (b.h - 8) / 2;
            gfx->setCursor(ltx, lty);
            gfx->print(b.label);
            delay(150);
            evPostCmd(pt_pi_ip, pt_pi_port, b.cmd);
            return true;
        }
    }
    return false;
}

// ── Touch calibration (CYD typical values) ───────────────────────────────────
// Raw XPT2046 → screen coords (landscape, non-inverted)
static void mapTouch(uint16_t rx, uint16_t ry, int& sx, int& sy) {
    // Typical CYD calibration — adjust if your unit differs
    sx = map(rx, 200, 3800, 0, W);
    sy = map(ry, 200, 3800, 0, H);
    sx = constrain(sx, 0, W - 1);
    sy = constrain(sy, 0, H - 1);
}

// ── Arduino entrypoints ───────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);

    // Display
    pinMode(GFX_BL, OUTPUT);
    digitalWrite(GFX_BL, HIGH);
    gfx->begin();
    gfx->fillScreen(C_BG);

    // Splash
    gfx->setTextColor(C_HDR_TXT, C_BG);
    gfx->setTextSize(2);
    gfx->setCursor(20, 80);
    gfx->print("PROBE TERMINAL");
    gfx->setTextSize(1);
    gfx->setTextColor(C_DIM, C_BG);
    gfx->setCursor(20, 110);
    gfx->print("Connecting to WiFi...");

    // Touch
    touchSPI.begin(XPT2046_CLK, XPT2046_MISO, XPT2046_MOSI, XPT2046_CS);
    ts.begin(touchSPI);
    ts.setRotation(1);

    // WiFi / portal
    ptConnect();

    gfx->fillScreen(C_BG);
    drawHeader();

    // Seed the terminal with a connect message
    termPush("--:--:--", "INFO", "Connected to Pi probe");
    termRedraw();
}

static unsigned long last_fetch_ms  = 0;
static unsigned long last_hdr_ms    = 0;
static bool          touch_was_down = false;
#define FETCH_INTERVAL_MS  3000
#define HDR_INTERVAL_MS    5000

void loop() {
    unsigned long now = millis();

    // ── Poll Pi events + status ─────────────────────────────────────────────
    if (now - last_fetch_ms >= FETCH_INTERVAL_MS) {
        last_fetch_ms = now;
        evFetchStatus(pt_pi_ip, pt_pi_port);
        evFetchEvents(pt_pi_ip, pt_pi_port);
        if (ev_bettercap) evFetchBettercap(pt_pi_ip, pt_pi_port);
        else evClearBettercap();

        if (ev_new_lines && !overlay_visible) {
            // Push new lines into terminal
            // ev_buf is a ring — iterate from ev_last_seen-N to ev_last_seen
            // We track writes via ev_count; just redraw all new ones.
            // Simple: re-render whole terminal from buffer each time.
            // (buffer is small enough)
            term_write      = 0;
            term_scroll_row = 0;
            int total = ev_head;   // total events ever written to buf
            int start = max(0, total - (TERM_ROWS * 2 - 1));
            for (int i = start; i < total; i++) {
                ProbeEvent& e = ev_buf[i % EV_MAX];
                termPush(e.ts, e.level, e.msg);
            }
            term_dirty = true;
        }
        if (overlay_visible && isBettercapMode()) {
            drawOverlay();
        }
    }

    // ── Redraw terminal ─────────────────────────────────────────────────────
    if (!overlay_visible) {
        termRedraw();
    }

    // ── Update header periodically ──────────────────────────────────────────
    if (now - last_hdr_ms >= HDR_INTERVAL_MS && !overlay_visible) {
        last_hdr_ms = now;
        drawHeader();
    }

    // ── Touch ───────────────────────────────────────────────────────────────
    bool touched = ts.tirqTouched() && ts.touched();
    if (touched && !touch_was_down) {
        TS_Point p = ts.getPoint();
        int sx, sy;
        mapTouch(p.x, p.y, sx, sy);

        if (!overlay_visible) {
            // Any tap opens overlay
            overlay_visible = true;
            if (isBettercapMode()) {
                bc_view = BC_VIEW_SUMMARY;
                bc_host_page = 0;
                bc_wifi_page = 0;
            }
            drawOverlay();
        } else {
            if (handleOverlayTouch(sx, sy)) {
                overlay_visible = false;
                // Redraw terminal underneath
                gfx->fillScreen(C_BG);
                drawHeader();
                term_dirty = true;
                termRedraw();
            }
        }
    }
    touch_was_down = touched;

    delay(20);
}
