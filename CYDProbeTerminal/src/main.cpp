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
 * Tap anywhere → control overlay (4 command buttons + status + X to dismiss).
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
    snprintf(right, sizeof(right), "hosts:%d  %s",
             ev_device_count,
             (WiFi.status() == WL_CONNECTED) ? WiFi.localIP().toString().c_str() : "no wifi");
    gfx->setCursor(W - strlen(right) * CHAR_W - 4, 5);
    gfx->print(right);
}

// ── Control overlay ───────────────────────────────────────────────────────────
static bool overlay_visible = false;

struct OvButton {
    const char* label;
    const char* cmd;
    uint16_t    bg;
    int16_t     x, y, w, h;
};

static OvButton ov_buttons[] = {
    { "ANOMALY DET",  "anomaly_detector", 0x0320, 10,  40,  140, 42 },
    { "BETTERCAP",    "bettercap",        0x0059, 165, 40,  145, 42 },
    { "QUICK SCAN",   "quick_scan",       0x4200, 10,  92,  140, 42 },
    { "STOP MODE",    "stop",             0x6000, 165, 92,  145, 42 },
};
#define N_OV_BUTTONS 4

static void drawOverlay() {
    // Semi-transparent tint by filling with a dark color
    gfx->fillRect(0, 0, W, H, C_OVERLAY);

    // Title bar
    gfx->fillRect(0, 0, W, 34, 0x0210);
    gfx->setTextColor(C_HDR_TXT, 0x0210);
    gfx->setTextSize(2);
    gfx->setCursor(8, 8);
    gfx->print("PROBE CONTROL");

    // Buttons
    gfx->setTextSize(1);
    for (int i = 0; i < N_OV_BUTTONS; i++) {
        OvButton& b = ov_buttons[i];
        gfx->fillRoundRect(b.x, b.y, b.w, b.h, 6, b.bg);
        gfx->drawRoundRect(b.x, b.y, b.w, b.h, 6, C_HDR_TXT);
        // Center text
        int tx = b.x + (b.w - strlen(b.label) * CHAR_W) / 2;
        int ty = b.y + (b.h - 8) / 2;
        gfx->setTextColor(C_WHITE, b.bg);
        gfx->setCursor(tx, ty);
        gfx->print(b.label);
    }

    // Status strip
    gfx->fillRect(0, 144, W, 28, 0x1082);
    gfx->setTextColor(C_DIM, 0x1082);
    gfx->setTextSize(1);
    char status[64];
    snprintf(status, sizeof(status), "mode: %-12s  hosts: %d",
             ev_mode, ev_device_count);
    gfx->setCursor(8, 152);
    gfx->print(status);

    // X / dismiss button
    gfx->fillRoundRect(10, 182, 300, 42, 6, 0x2000);
    gfx->drawRoundRect(10, 182, 300, 42, 6, 0x6000);
    gfx->setTextColor(0xF800, 0x2000);
    gfx->setTextSize(2);
    int tx = 10 + (300 - 3 * CHAR_W * 2) / 2;
    gfx->setCursor(tx, 195);
    gfx->print("X  BACK");
}

// Returns true if overlay should close (X tapped or command sent)
static bool handleOverlayTouch(int tx, int ty) {
    // X / Back button
    if (tx >= 10 && tx <= 310 && ty >= 182 && ty <= 224) {
        return true;
    }
    for (int i = 0; i < N_OV_BUTTONS; i++) {
        OvButton& b = ov_buttons[i];
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
