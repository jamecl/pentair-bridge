// main.c — ESP32 Pentair RS-485 bridge with security and reliability fixes
// ESP-IDF v5.x
// API KEY AUTHENTICATION DISABLED FOR TESTING

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "driver/uart.h"
#include "driver/gpio.h"

#include "esp_netif.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "esp_task_wdt.h"

#include "esp_http_server.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "credentials.h"

// -------------------------- Configuration ---------------------------------
#ifndef WIFI_SSID
#define WIFI_SSID "YOUR_WIFI_SSID"
#endif
#ifndef WIFI_PASS
#define WIFI_PASS "YOUR_WIFI_PASSWORD"
#endif
#ifndef API_KEY
#define API_KEY "your-secret-api-key-change-this"
#endif

#define WIFI_MAX_RETRY 10
#define WIFI_RETRY_DELAY_MS 5000
// ------------------------------------------------------------------------

#define TAG "PENTAIR"

// Log-but-don't-abort helper
#define TRY(stage, call) do{ \
    esp_err_t __e = (call); \
    if (__e != ESP_OK){ \
        ESP_LOGE(TAG, "[%s] %s failed: %s (0x%x)", stage, #call, esp_err_to_name(__e), (unsigned)__e); \
    } \
}while(0)

// ---------------------------- UART/RS485 ---------------------------------
#define UART_PORT           UART_NUM_2
#define UART_BAUD           9600
#define UART_TX             (17)
#define UART_RX             (16)
#define UART_RTS            (4)
#define UART_CTS            UART_PIN_NO_CHANGE

// ------------------------------ DATA ------------------------------------
#define STREAM_BUF   1024
#define FRAME_MAX    128
#define HISTORY_MAX  50
#define PREVIEW_MAX  64

typedef struct {
    uint64_t usec;
    uint16_t len;
    uint8_t  data[FRAME_MAX];
} frame_t;

typedef struct {
    frame_t  items[HISTORY_MAX];
    int      head;
    int      count;
} history_t;

static history_t g_hist;
static SemaphoreHandle_t g_hist_lock;

typedef struct {
    bool     valid;
    int      pool_f;
    int      spa_f;
    int      air_f;
    uint8_t  equip1;
    bool     spa_mode;
    bool     pool_on;
    bool     cleaner;
    bool     pool_light;
    bool     water_feature;
    uint64_t last_us;
} main_state_t;

typedef struct {
    bool     valid;
    uint8_t  pump_id;
    uint16_t rpm;
    uint16_t watts;
    uint8_t  gpm;
    uint8_t  started;
    uint64_t last_us;
} pump_state_t;

static main_state_t g_main;
static pump_state_t g_pump;
static SemaphoreHandle_t g_state_lock;

// ------------------------ API RATE LIMITING ------------------------------
#define MAX_CLIENTS 10
#define RATE_LIMIT_WINDOW_MS 60000
#define RATE_LIMIT_MAX_REQUESTS 100

typedef struct {
    uint32_t ip;
    uint32_t count;
    uint64_t window_start_us;
} rate_limit_entry_t;

typedef struct {
    rate_limit_entry_t entries[MAX_CLIENTS];
    SemaphoreHandle_t lock;
} rate_limiter_t;

static rate_limiter_t g_rate_limiter;

// ----------------------------- UTIL -------------------------------------
static inline uint64_t now_us(void){ return esp_timer_get_time(); }

static void init_rate_limiter(void){
    memset(&g_rate_limiter, 0, sizeof(g_rate_limiter));
    g_rate_limiter.lock = xSemaphoreCreateMutex();
}

static bool check_rate_limit(uint32_t ip){
    if (!g_rate_limiter.lock) return true;
    
    xSemaphoreTake(g_rate_limiter.lock, portMAX_DELAY);
    uint64_t now = now_us();
    bool allowed = false;
    int free_slot = -1;
    
    for (int i = 0; i < MAX_CLIENTS; i++){
        if (g_rate_limiter.entries[i].ip == ip){
            if ((now - g_rate_limiter.entries[i].window_start_us) > (RATE_LIMIT_WINDOW_MS * 1000)){
                g_rate_limiter.entries[i].count = 0;
                g_rate_limiter.entries[i].window_start_us = now;
            }
            
            if (g_rate_limiter.entries[i].count < RATE_LIMIT_MAX_REQUESTS){
                g_rate_limiter.entries[i].count++;
                allowed = true;
            }
            goto done;
        }
        if (g_rate_limiter.entries[i].ip == 0 && free_slot == -1){
            free_slot = i;
        }
    }
    
    if (free_slot >= 0){
        g_rate_limiter.entries[free_slot].ip = ip;
        g_rate_limiter.entries[free_slot].count = 1;
        g_rate_limiter.entries[free_slot].window_start_us = now;
        allowed = true;
    } else {
        int oldest = 0;
        for (int i = 1; i < MAX_CLIENTS; i++){
            if (g_rate_limiter.entries[i].window_start_us < g_rate_limiter.entries[oldest].window_start_us){
                oldest = i;
            }
        }
        g_rate_limiter.entries[oldest].ip = ip;
        g_rate_limiter.entries[oldest].count = 1;
        g_rate_limiter.entries[oldest].window_start_us = now;
        allowed = true;
    }
    
done:
    xSemaphoreGive(g_rate_limiter.lock);
    return allowed;
}

static bool check_api_key(httpd_req_t *req){
    char buf[128];
    int ret = httpd_req_get_hdr_value_str(req, "X-API-Key", buf, sizeof(buf));
    if (ret == ESP_OK){
        if (strcmp(buf, API_KEY) == 0){
            return true;
        }
    }
    return false;
}

static esp_err_t send_unauthorized(httpd_req_t *req){
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_send(req, "Unauthorized - Invalid or missing API key", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_rate_limit(httpd_req_t *req){
    httpd_resp_set_status(req, "429 Too Many Requests");
    httpd_resp_set_type(req, "text/plain");
    return httpd_resp_send(req, "Rate limit exceeded", HTTPD_RESP_USE_STRLEN);
}

static int hex_to_str(const uint8_t *src, int len, char *dst, size_t dstsz){
    size_t pos = 0;
    for (int i=0;i<len;i++){
        int n = snprintf(dst + pos, (pos<dstsz? dstsz-pos:0), "%02X%s",
                         src[i], (i+1<len? " ":""));
        if (n < 0) n = 0;
        pos += (size_t)n;
        if (pos+1 >= dstsz) break;
    }
    if (pos < dstsz) dst[pos] = '\0'; else dst[dstsz-1] = '\0';
    return (int)pos;
}

static void push_frame(const uint8_t *buf, uint16_t len){
    if (!g_hist_lock) return;
    xSemaphoreTake(g_hist_lock, portMAX_DELAY);
    int idx = g_hist.head;
    g_hist.items[idx].usec = now_us();
    g_hist.items[idx].len  = len;
    if (len > FRAME_MAX) len = FRAME_MAX;
    memcpy(g_hist.items[idx].data, buf, len);
    g_hist.head = (idx + 1) % HISTORY_MAX;
    if (g_hist.count < HISTORY_MAX) g_hist.count++;
    xSemaphoreGive(g_hist_lock);
}

// ----------------------------- DECODE -----------------------------------
static void decode_frame(const uint8_t *s, int i, int end){
    int header_start;
    int checksum_start;
    
    // Check for 11-byte preamble (main controller broadcasts)
    if (i+11 <= end && 
        s[i]==0xFF && s[i+1]==0xFF && s[i+2]==0xFF && s[i+3]==0xFF &&
        s[i+4]==0xFF && s[i+5]==0xFF && s[i+6]==0xFF && s[i+7]==0xFF &&
        s[i+8]==0x00 && s[i+9]==0xFF && s[i+10]==0xA5) {
        header_start = i + 11;
        checksum_start = i + 10;  // Start at 0xA5
    }
    // Check for 4-byte preamble (pump and other devices)
    else if (i+4 <= end &&
             s[i]==0xFF && s[i+1]==0x00 && s[i+2]==0xFF && s[i+3]==0xA5) {
        header_start = i + 4;
        checksum_start = i + 3;   // Start at 0xA5
    }
    else {
        return;  // Invalid preamble
    }

    // Parse header (5 bytes)
    if (header_start+5 > end) return;
    uint8_t ver  = s[header_start];
    uint8_t dst  = s[header_start+1];
    uint8_t src  = s[header_start+2];
    uint8_t cmd  = s[header_start+3];
    uint8_t dlen = s[header_start+4];

    int dstart = header_start + 5;
    int dend   = dstart + dlen;
    if (dend + 2 > end) return;

    // Checksum includes from 0xA5 through end of data
    uint16_t sum = 0;
    for (int k=checksum_start; k<dend; ++k) sum += s[k];
    uint16_t chk = ((uint16_t)s[dend]<<8) | s[dend+1];
    bool cs_ok = (sum == chk);

    int frame_len = dend + 2 - i;
    push_frame(&s[i], (uint16_t)frame_len);
    
    // Log complete frame to serial monitor for debugging
    if (src==0x10 && dst==0x0F && cmd==0x02) {
        ESP_LOGI(TAG, "MAIN frame (%d bytes, checksum %s):", frame_len, cs_ok?"OK":"FAIL");
        char hex_buf[256];
        int pos = 0;
        for (int j = 0; j < frame_len && pos < 240; j++) {
            pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, "%02X ", s[i+j]);
        }
        ESP_LOGI(TAG, "%s", hex_buf);
    }
    
    // Log pump frames too
    if (dst==0x10 && (src>=0x60 && src<=0x63) && cmd==0x07) {
        ESP_LOGI(TAG, "PUMP frame (%d bytes, checksum %s):", frame_len, cs_ok?"OK":"FAIL");
        char hex_buf[256];
        int pos = 0;
        for (int j = 0; j < frame_len && pos < 240; j++) {
            pos += snprintf(hex_buf + pos, sizeof(hex_buf) - pos, "%02X ", s[i+j]);
        }
        ESP_LOGI(TAG, "%s", hex_buf);
    }
    
    if (!cs_ok) {
        ESP_LOGW(TAG, "Checksum fail: calculated=0x%04X, expected=0x%04X", sum, chk);
        return;
    }

    // MAIN broadcast: src=0x10->dst=0x0F, cmd=0x02, len>=0x1D
    if (src==0x10 && dst==0x0F && cmd==0x02 && dlen>=0x1D){
        const uint8_t *d = &s[dstart];
        main_state_t m;
        memset(&m, 0, sizeof(m));
        m.valid  = true;
        m.equip1 = d[2];
        m.pool_f = (int)d[14];
        m.spa_f  = (int)d[15];
        m.air_f  = (int)d[18];
        m.spa_mode = false;
        m.pool_on  = ((m.equip1 >> 5) & 1) != 0;
        m.cleaner  = ((m.equip1 >> 0) & 1) != 0;
        m.pool_light = ((m.equip1 >> 1) & 1) != 0;
        m.water_feature = ((m.equip1 >> 2) & 1) != 0;
        m.last_us = now_us();
        
        ESP_LOGI(TAG, "DECODED: Pool=%d°F, Air=%d°F, Spa=%d°F, Equip=0x%02X, PoolOn=%d", 
                 m.pool_f, m.air_f, m.spa_f, m.equip1, m.pool_on);
        
        if (g_state_lock){
            xSemaphoreTake(g_state_lock, portMAX_DELAY);
            g_main = m;
            xSemaphoreGive(g_state_lock);
        }
        return;
    }

    // PUMP status: dst=0x10, src=0x60..0x63, cmd=0x07, len>=0x0F
    if (dst==0x10 && (src>=0x60 && src<=0x63) && cmd==0x07 && dlen>=0x0F){
        const uint8_t *d = &s[dstart];
        pump_state_t p;
        memset(&p, 0, sizeof(p));
        p.valid   = true;
        p.pump_id = (uint8_t)(src - 0x60);
        p.started = d[0];
        p.watts   = ((uint16_t)d[3] << 8) | d[4];
        p.rpm     = ((uint16_t)d[5] << 8) | d[6];
        p.gpm     = d[7];
        p.last_us = now_us();
        
        ESP_LOGI(TAG, "PUMP: RPM=%d, Watts=%d, GPM=%d, Running=%d", 
                 p.rpm, p.watts, p.gpm, p.started);
        
        if (g_state_lock){
            xSemaphoreTake(g_state_lock, portMAX_DELAY);
            g_pump = p;
            xSemaphoreGive(g_state_lock);
        }
        return;
    }
}

// -------------------------- UART TASK -----------------------------------
static void uart_task(void *arg){
    ESP_LOGI(TAG, "UART task start");
    
    esp_task_wdt_add(NULL);

    uint8_t stream[STREAM_BUF];
    int have = 0;

    uart_config_t uc = {
        .baud_rate  = UART_BAUD,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0
    };

    TRY("uart", uart_param_config(UART_PORT, &uc));
    TRY("uart", uart_set_pin(UART_PORT, UART_TX, UART_RX, UART_RTS, UART_CTS));
    esp_err_t e_drv = uart_driver_install(UART_PORT, STREAM_BUF, 0, 0, NULL, 0);
    if (e_drv != ESP_OK){
        ESP_LOGE(TAG, "[uart] uart_driver_install failed, RS-485 disabled");
    }else{
        esp_err_t e_mode = uart_set_mode(UART_PORT, UART_MODE_RS485_HALF_DUPLEX);
        if (e_mode != ESP_OK){
            ESP_LOGE(TAG, "[uart] uart_set_mode(UART_MODE_RS485_HALF_DUPLEX) failed: %s", esp_err_to_name(e_mode));
        }else{
            ESP_LOGI(TAG, "UART RS-485 half-duplex ready @%d (TX=%d RX=%d RTS=%d)",
                     UART_BAUD, UART_TX, UART_RX, UART_RTS);
        }
    }

    while (1){
        esp_task_wdt_reset();
        
        int n = uart_read_bytes(UART_PORT, stream + have, STREAM_BUF - have, pdMS_TO_TICKS(100));
        if (n > 0){
            have += n;
            int i = 0;
            
            while (i < have){
                // Check for 11-byte preamble (main controller broadcasts)
                if (i + 16 <= have && 
                    stream[i]==0xFF && stream[i+1]==0xFF && stream[i+2]==0xFF && stream[i+3]==0xFF &&
                    stream[i+4]==0xFF && stream[i+5]==0xFF && stream[i+6]==0xFF && stream[i+7]==0xFF &&
                    stream[i+8]==0x00 && stream[i+9]==0xFF && stream[i+10]==0xA5) {
                    
                    uint8_t dlen = stream[i+15];
                    int frame_end = i + 16 + dlen + 2;
                    if (frame_end <= have){
                        decode_frame(stream, i, frame_end);
                        i = frame_end;
                        continue;
                    } else break;
                }
                // Check for 4-byte preamble (other messages)
                else if (i + 9 <= have &&
                         stream[i]==0xFF && stream[i+1]==0x00 && stream[i+2]==0xFF && stream[i+3]==0xA5) {
                    
                    uint8_t dlen = stream[i+8];
                    int frame_end = i + 9 + dlen + 2;
                    if (frame_end <= have){
                        decode_frame(stream, i, frame_end);
                        i = frame_end;
                        continue;
                    } else break;
                }
                i++;
            }
            
            if (i > 0){
                int remain = have - i;
                if (remain > 0) memmove(stream, stream+i, remain);
                have = remain;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

// --------------------------- HTTP/UI ------------------------------------
static const char *INDEX_HTML =
"<!doctype html><html><head><meta charset='utf-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Pentair RS-485 Live</title>"
"<style>"
"body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',sans-serif;margin:12px;background:#fafafa;color:#111}"
".grid{display:grid;grid-template-columns:repeat(4,minmax(240px,1fr));gap:12px}"
".card{background:#fff;border-radius:10px;padding:12px;box-shadow:0 1px 3px rgba(0,0,0,.07)}"
".k{font-size:12px;color:#666;margin-bottom:6px}.v{font-size:20px;font-weight:600}"
".bar{background:#111;color:#0f0;border-radius:8px;padding:6px 10px;font-family:ui-monospace,Consolas,monospace;white-space:nowrap;overflow:auto}"
"table{width:100%;border-collapse:collapse;margin-top:10px}"
"th,td{border-bottom:1px solid #eee;padding:6px 8px;font-size:12px}"
"th{color:#666;text-align:left}.mono{font-family:ui-monospace,Consolas,monospace}"
"button{padding:6px 10px;border:1px solid #ccc;border-radius:8px;background:#fff;cursor:pointer}"
"</style></head><body>"
"<h2>Pentair RS-485 Live</h2>"
"<div class='grid'>"
  "<div class='card'><div class='k'>Pool</div><div class='v' id='pool'>—</div></div>"
  "<div class='card'><div class='k'>Air</div><div class='v' id='air'>—</div></div>"
  "<div class='card'><div class='k'>Spa</div><div class='v' id='spa'>off</div></div>"
  "<div class='card'><div class='k'>Pool Circuit</div><div class='v' id='poolckt'>off</div></div>"
  "<div class='card'><div class='k'>Pump</div><div class='v'><span id='pon'>—</span>, rpm: <span id='rpm'>—</span>, watts: <span id='watts'>—</span>, gpm: <span id='gpm'>—</span></div></div>"
  "<div class='card'><div class='k'>Cleaner</div><div class='v' id='clean'>off</div></div>"
  "<div class='card'><div class='k'>Pool Light</div><div class='v' id='light'>off</div></div>"
  "<div class='card'><div class='k'>Water Feature</div><div class='v' id='wf'>off</div></div>"
"</div>"
"<p>Status: <span id='stat'>loading…</span> • Latest len: <span id='len'>0</span></p>"
"<div class='bar mono'><span id='hex'></span></div>"
"<p><button onclick='dl()'>Download history (JSON)</button></p>"
"<table id='t'><thead><tr><th>#</th><th>Age (ms)</th><th>Len</th><th>Preview (first 64 bytes)</th></tr></thead><tbody></tbody></table>"
"<script>"
"function fmtT(v){return (v&&v>=30&&v<=125)?(v+'°F'):'—'};"
"async function dl(){const r=await fetch('/api/frames');const j=await r.json();"
"const blob=new Blob([JSON.stringify(j,null,2)],{type:'application/json'});"
"const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='frames.json';a.click();}"
"async function tick(){try{"
"  let s=await (await fetch('/api/status')).json();"
"  document.getElementById('pool').textContent=fmtT(s.main.pool_f);"
"  document.getElementById('air').textContent =fmtT(s.main.air_f);"
"  document.getElementById('spa').textContent =s.main.spa_mode?'on':'off';"
"  document.getElementById('poolckt').textContent=s.main.pool_on?'on':'off';"
"  document.getElementById('clean').textContent=s.main.cleaner?'on':'off';"
"  document.getElementById('light').textContent=s.main.pool_light?'on':'off';"
"  document.getElementById('wf').textContent   =s.main.water_feature?'on':'off';"
"  if(s.pump.valid){"
"    document.getElementById('pon').textContent=s.pump.started?'yes':'no';"
"    document.getElementById('rpm').textContent=s.pump.rpm||'—';"
"    document.getElementById('watts').textContent=s.pump.watts||'—';"
"    document.getElementById('gpm').textContent=s.pump.gpm||'—';"
"  }"
"  let l=await (await fetch('/api/latest')).json();"
"  document.getElementById('stat').textContent=l.len?'OK':'waiting…';"
"  document.getElementById('len').textContent=l.len||0;"
"  document.getElementById('hex').textContent=l.hex||'';"
"  let h=await (await fetch('/api/frames')).json();"
"  let tb=document.querySelector('#t tbody');tb.innerHTML='';"
"  let now=h.now_us||0;"
"  (h.items||[]).forEach((it,idx)=>{"
"    let tr=document.createElement('tr');"
"    let age=now&&it.usec?((now-it.usec)/1000).toFixed(0):'';"
"    tr.innerHTML='<td>'+(idx+1)+'</td><td>'+age+'</td><td>'+it.len+'</td><td class=\"mono\">'+it.preview+(it.truncated?' …':'')+'</td>';"
"    tb.appendChild(tr);"
"  });"
"}catch(e){console.error(e);document.getElementById('stat').textContent='error';}}"
"setInterval(tick,60000);tick();"
"</script></body></html>";

static esp_err_t index_get(httpd_req_t *req){
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, INDEX_HTML, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t api_latest_get(httpd_req_t *req){
    char hex[PREVIEW_MAX*3+4]; hex[0]='\0';
    uint16_t last_len = 0;

    xSemaphoreTake(g_hist_lock, portMAX_DELAY);
    if (g_hist.count > 0){
        int last = (g_hist.head + HISTORY_MAX - 1) % HISTORY_MAX;
        const frame_t *f = &g_hist.items[last];
        last_len = f->len;
        int dump = f->len; if (dump > PREVIEW_MAX) dump = PREVIEW_MAX;
        hex_to_str(f->data, dump, hex, sizeof(hex));
    }
    xSemaphoreGive(g_hist_lock);

    char json[PREVIEW_MAX*3+64];
    int r = snprintf(json, sizeof(json), "{\"len\":%u,\"hex\":\"%s\"}", (unsigned)last_len, hex);
    if (r < 0) r = 0;
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, r);
}

static esp_err_t api_frames_get(httpd_req_t *req){
    frame_t *snap = (frame_t*)malloc(HISTORY_MAX * sizeof(frame_t));
    if (!snap){
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_send(req, "Out of memory", HTTPD_RESP_USE_STRLEN);
    }
    
    int cnt = 0;
    uint64_t now = now_us();

    xSemaphoreTake(g_hist_lock, portMAX_DELAY);
    cnt = g_hist.count; if (cnt > HISTORY_MAX) cnt = HISTORY_MAX;
    for (int k=0;k<cnt;k++){
        int idx = (g_hist.head + HISTORY_MAX - cnt + k) % HISTORY_MAX;
        snap[k] = g_hist.items[idx];
    }
    xSemaphoreGive(g_hist_lock);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "{\"now_us\":");
    char buf[64];
    int r = snprintf(buf, sizeof(buf), "%" PRIu64 ",\"count\":%d,\"items\":[", now, cnt);
    if (r < 0) r = 0;
    httpd_resp_send_chunk(req, buf, r);

    for (int i=0;i<cnt;i++){
        char hex[PREVIEW_MAX*3+4];
        int dump = snap[i].len; bool trunc=false;
        if (dump > PREVIEW_MAX){ dump = PREVIEW_MAX; trunc=true; }
        hex_to_str(snap[i].data, dump, hex, sizeof(hex));

        r = snprintf(buf, sizeof(buf), "%s{\"usec\":%" PRIu64 ",\"len\":%u,\"preview\":\"",
                     (i?",":""), snap[i].usec, (unsigned)snap[i].len);
        if (r < 0) r = 0;
        httpd_resp_send_chunk(req, buf, r);
        httpd_resp_send_chunk(req, hex, HTTPD_RESP_USE_STRLEN);
        r = snprintf(buf, sizeof(buf), "\",\"truncated\":%s}", trunc?"true":"false");
        if (r < 0) r = 0;
        httpd_resp_send_chunk(req, buf, r);
    }
    httpd_resp_sendstr_chunk(req, "]}");
    
    free(snap);
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t api_status_get(httpd_req_t *req){
    main_state_t m;
    pump_state_t p;
    if (g_state_lock){
        xSemaphoreTake(g_state_lock, portMAX_DELAY);
        m = g_main;
        p = g_pump;
        xSemaphoreGive(g_state_lock);
    } else {
        m = g_main;
        p = g_pump;
    }

    uint32_t m_age = (m.last_us? (uint32_t)((now_us()-m.last_us)/1000) : 0);
    uint32_t p_age = (p.last_us? (uint32_t)((now_us()-p.last_us)/1000) : 0);

    char json[384];
    int r = snprintf(json, sizeof(json),
        "{"
        "\"main\":{\"valid\":%s,\"pool_f\":%d,\"spa_f\":%d,\"air_f\":%d,"
        "\"equip1\":%u,\"spa_mode\":%s,\"pool_on\":%s,\"cleaner\":%s,\"pool_light\":%s,\"water_feature\":%s,\"last_age_ms\":%u},"
        "\"pump\":{\"valid\":%s,\"pump_id\":%u,\"rpm\":%u,\"watts\":%u,\"gpm\":%u,"
        "\"started\":%u,\"last_age_ms\":%u}"
        "}",
        m.valid?"true":"false", m.pool_f, m.spa_f, m.air_f,
        (unsigned)m.equip1, m.spa_mode?"true":"false", m.pool_on?"true":"false", m.cleaner?"true":"false", m.pool_light?"true":"false", m.water_feature?"true":"false", (unsigned)m_age,
        p.valid?"true":"false", (unsigned)p.pump_id, (unsigned)p.rpm, (unsigned)p.watts, (unsigned)p.gpm,
        (unsigned)p.started, (unsigned)p_age
    );
    if (r < 0) r = 0;
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, r);
}

static httpd_handle_t start_http(void){
    ESP_LOGI(TAG, "HTTP server start");
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = 80;
    cfg.stack_size  = 12288;
    cfg.recv_wait_timeout = 10;
    cfg.send_wait_timeout = 10;
    cfg.lru_purge_enable = true;
    cfg.max_open_sockets = 4;

    httpd_handle_t server = NULL;
    esp_err_t e = httpd_start(&server, &cfg);
    if (e != ESP_OK){
        ESP_LOGE(TAG, "httpd_start failed: %s (0x%x)", esp_err_to_name(e), (unsigned)e);
        return NULL;
    }

    httpd_uri_t u_idx = { .uri="/",           .method=HTTP_GET, .handler=index_get };
    httpd_uri_t u_l   = { .uri="/api/latest", .method=HTTP_GET, .handler=api_latest_get };
    httpd_uri_t u_f   = { .uri="/api/frames", .method=HTTP_GET, .handler=api_frames_get };
    httpd_uri_t u_s   = { .uri="/api/status", .method=HTTP_GET, .handler=api_status_get };
    httpd_register_uri_handler(server, &u_idx);
    httpd_register_uri_handler(server, &u_l);
    httpd_register_uri_handler(server, &u_f);
    httpd_register_uri_handler(server, &u_s);

    ESP_LOGI(TAG, "HTTP server started on port %u", cfg.server_port);
    return server;
}

// --------------------------- Wi-Fi --------------------------------------
static void wifi_event_handler(void* arg, esp_event_base_t base, int32_t id, void* data){
    static int retry_num = 0;
    
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START){
        ESP_LOGI(TAG, "WiFi STA started, connecting...");
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED){
        wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t*) data;
        ESP_LOGW(TAG, "WiFi disconnect reason: %d", event->reason);
        retry_num++;
        if (retry_num <= WIFI_MAX_RETRY){
            ESP_LOGW(TAG, "Wi-Fi disconnected, retry %d/%d in %dms", retry_num, WIFI_MAX_RETRY, WIFI_RETRY_DELAY_MS);
            vTaskDelay(pdMS_TO_TICKS(WIFI_RETRY_DELAY_MS));
            esp_wifi_connect();
        } else {
            ESP_LOGE(TAG, "Wi-Fi connection failed after %d retries, will keep trying...", WIFI_MAX_RETRY);
            vTaskDelay(pdMS_TO_TICKS(30000));
            retry_num = 0;
            esp_wifi_connect();
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED){
        wifi_event_sta_connected_t *event = (wifi_event_sta_connected_t*) data;
        ESP_LOGI(TAG, "WiFi connected to AP, SSID:%s, Channel:%d", event->ssid, event->channel);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP){
        ip_event_got_ip_t *e = (ip_event_got_ip_t*)data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&e->ip_info.ip));
        retry_num = 0;
    }
}

static void wifi_start(void){
    ESP_LOGI(TAG, "Wi-Fi start (SSID len=%d)", (int)strlen(WIFI_SSID));

    TRY("wifi", esp_netif_init());
    TRY("wifi", esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    TRY("wifi", esp_wifi_init(&cfg));

    TRY("wifi", esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    TRY("wifi", esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t sta = {0};
    strncpy((char*)sta.sta.ssid, WIFI_SSID, sizeof(sta.sta.ssid));
    strncpy((char*)sta.sta.password, WIFI_PASS, sizeof(sta.sta.password));
    sta.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    sta.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    sta.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;

    TRY("wifi", esp_wifi_set_mode(WIFI_MODE_STA));
    TRY("wifi", esp_wifi_set_config(WIFI_IF_STA, &sta));
    TRY("wifi", esp_wifi_start());
    
    TRY("wifi", esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_LOGI(TAG, "WiFi power save disabled for stability");
}

// ---------------------------- app_main ----------------------------------
void app_main(void){
    esp_log_level_set(TAG, ESP_LOG_INFO);
    ESP_LOGI(TAG, "------ Boot ------");
    ESP_LOGI(TAG, "API KEY AUTHENTICATION DISABLED FOR TESTING");

    esp_task_wdt_config_t wdt_config = {
        .timeout_ms = 30000,
        .idle_core_mask = 0,
        .trigger_panic = true
    };
    esp_task_wdt_reconfigure(&wdt_config);
    ESP_LOGI(TAG, "Watchdog timer configured (30s timeout)");

    esp_err_t nvs = nvs_flash_init();
    if (nvs != ESP_OK){
        ESP_LOGW(TAG, "NVS init failed (%s), erasing and reinitializing", esp_err_to_name(nvs));
        TRY("nvs", nvs_flash_erase());
        nvs = nvs_flash_init();
    }
    if (nvs != ESP_OK){
        ESP_LOGE(TAG, "[nvs] init failed after erase: %s (0x%x)", esp_err_to_name(nvs), (unsigned)nvs);
    }

    wifi_start();

    memset(&g_hist, 0, sizeof(g_hist));
    g_hist_lock = xSemaphoreCreateMutex();
    
    memset(&g_main, 0, sizeof(g_main));
    memset(&g_pump, 0, sizeof(g_pump));
    g_state_lock = xSemaphoreCreateMutex();
    
    init_rate_limiter();

    start_http();

    xTaskCreate(uart_task, "uart_task", 4096, NULL, 10, NULL);
}