# Pentair RS-485 Bridge

ESP32-based bridge that monitors Pentair pool equipment via RS-485 and exposes the data over HTTP for Home Assistant integration.

## What it does

- Listens on the Pentair RS-485 bus (9600 baud)
- Decodes main controller broadcasts (temperatures, circuit states)
- Decodes pump status (RPM, watts, GPM)
- Serves a live web dashboard at `http://<device-ip>/`
- Provides a JSON API consumed by Home Assistant

## Hardware

- ESP32-WROOM-32 DevKit (CP2102), MAC: `68:25:dd:45:f2:e4`, reserved IP: `192.168.0.30`
- ANMBEST MAX485 RS-485 transceiver module, connected to UART2 (TX=17, RX=16, RTS=4)
- **Recommended power supply: Meanwell HDR-15-5** (DIN rail mount, 5VDC, built-in noise filtering) — USB chargers are unreliable in the noisy electrical environment of a pool equipment panel and can cause flash corruption on power cycling

See the [wiring diagram](docs/wiring-diagram.svg) for full connection details.

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Live web dashboard |
| `GET /api/status` | Current pool and pump state (JSON) |
| `GET /api/latest` | Most recent raw RS-485 frame (hex) |
| `GET /api/frames` | History of last 200 frames (JSON) |

## Credentials

Copy `main/credentials.h.example` to `main/credentials.h` and fill in your WiFi credentials before building. This file is excluded from git.

```c
#define WIFI_SSID "your-wifi-ssid"
#define WIFI_PASS "your-wifi-password"
#define API_KEY   "your-secret-api-key-change-this"
```

## Building and flashing

Requires ESP-IDF v5.1. From the project root:

```bash
idf.py build
idf.py -p /dev/tty.usbserial-0001 flash monitor
```

## Home Assistant

See `ha/configuration.yaml` for the REST sensor configuration. Add it to your HA `configuration.yaml` and reload.

Sensors provided:
- Pool Temperature, Air Temperature, Spa Temperature
- Pool Pump RPM, Pool Pump Power
- Pool Circuit, Pool Pump Running, Pool Cleaner, Pool Light, Water Feature

## Troubleshooting

**Device not appearing on the network**
The most common cause is corrupted firmware from a power supply failure. Reflash using the commands above and it will recover.

**Sensors showing unavailable in HA**
Check that `http://192.168.0.30/api/status` returns valid JSON with `main.valid: true`. If valid is false, the ESP32 is not receiving RS-485 data — check the wiring to the Pentair bus.

**Wrong IP address assigned**
The router has a DHCP reservation for MAC `68:25:dd:49:1d:18` → `192.168.0.30`. If the IP changes, update the `resource` URL in `ha/configuration.yaml`.
