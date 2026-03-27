# UFI 4G USB Dongle — Stock Firmware Security Analysis

**Date:** 2026-03-27
**Device:** Juzhen UFI 4G USB WiFi Dongle (JZ0145-v33, MSM8916)
**Firmware:** Android 4.4.4 KTU84P, build `eng.richal.20251104`, test-keys
**Management App:** `com.youdo.server` v1.0, Qihoo 360 jiagu-packed
**Scope:** Authorized security research on owned hardware
**Method:** Binary string extraction, APK extraction/decompilation, configuration analysis
**Tools:** strings, grep, debugfs, binwalk 2.1.0, jadx 1.5.1, dtc

---

## Executive Summary

The stock firmware presents **severe, systemic security failures** across every
layer of the software stack. The analysis identified **8 critical**, **7 high**,
and **5 medium** severity findings.

The firmware is insecure both **by design** (Chinese carrier telemetry, Qualcomm
data collection, OMA remote management) and **by negligence** (test-keys signing,
disabled SELinux, hardcoded passwords, broken encryption, exposed debug interfaces).

**For the user's deployment scenario** (dongle connected via USB/WiFi, traffic
routed through Tailscale/NetBird VPN), the stock firmware completely undermines
the VPN's security guarantees. The dongle phones home over LTE independently
of the VPN tunnel, leaking device identifiers, GPS coordinates, and traffic
metadata to Chinese and Qualcomm servers.

**Replacing the firmware with OpenStick Debian eliminates all identified threats.**

---

## Finding Summary

| ID | Severity | Finding | Category |
|----|----------|---------|----------|
| C1 | **CRITICAL** | Hardcoded identical passwords on all devices | Credentials |
| C2 | **CRITICAL** | Firmware signed with public AOSP test-keys | Code integrity |
| C3 | **CRITICAL** | SELinux mandatory access control disabled | Access control |
| C4 | **CRITICAL** | Qihoo 360 jiagu packer with location API hooks | Obfuscation |
| C5 | **CRITICAL** | China Mobile auto-registration (zzhc) — IMSI/IMEI exfiltration | Phone-home |
| C6 | **CRITICAL** | Hardcoded YouDo cloud server (154.48.236.92:7001) | Phone-home |
| C7 | **CRITICAL** | IMEI modification API endpoint (identity fraud) | API abuse |
| C8 | **CRITICAL** | DES encryption with keys sent in cleartext | Cryptography |
| H1 | **HIGH** | Qualcomm RIDL — GPS + diagnostics uploaded every 15 min | Telemetry |
| H2 | **HIGH** | Qualcomm CNE — traffic analysis sent to Qualcomm | Telemetry |
| H3 | **HIGH** | OMA Device Management — remote carrier control via SMS | Remote access |
| H4 | **HIGH** | Qualcomm DIAG + serial debug exposed on USB | Debug exposure |
| H5 | **HIGH** | ADB enabled by default with pre-installed auth key | Remote access |
| H6 | **HIGH** | 14 dangerous Android permissions (SMS, contacts, location) | Permissions |
| H7 | **HIGH** | 802.11 Shared Key Auth enabled, client isolation disabled | WiFi security |
| M1 | **MEDIUM** | Chinese carrier bloatware with silent app install | Bloatware |
| M2 | **MEDIUM** | Crash data sent to Qihoo 360 servers | Telemetry |
| M3 | **MEDIUM** | Google geolocation services active | Telemetry |
| M4 | **MEDIUM** | Management frame protection (802.11w) disabled | WiFi security |
| M5 | **MEDIUM** | CrashLogger + StatManDo system daemons | Data collection |

---

## Risk Assessment: VPN Use Case

The user connects the dongle via USB or WiFi and routes all host traffic
through a VPN (Tailscale/NetBird). Does the VPN protect against these threats?

**No. The VPN protects host traffic but not the dongle's own traffic.**

```
┌─────────────────────────────────────────────────────────────────┐
│  Data flows with STOCK FIRMWARE                                  │
│                                                                  │
│  ┌────────┐   USB/WiFi    ┌──────────────┐   LTE    ┌────────┐ │
│  │  Host  │──────────────→│    Dongle     │─────────→│Internet│ │
│  │  (HA)  │               │  (And. 4.4)  │          └────────┘ │
│  └────────┘               └──────────────┘                      │
│       │                    │ │ │ │ │ │                           │
│       │  VPN protects      │ │ │ │ │ └→ zzhc.vnet.cn (IMSI)    │
│       │  THIS traffic      │ │ │ │ └──→ appjiagu.com (crashes)  │
│       │  only ──────→      │ │ │ └────→ 154.48.236.92 (YouDo)   │
│       │                    │ │ └──────→ Qualcomm RIDL (GPS)     │
│       │                    │ └────────→ Qualcomm CNE (traffic)  │
│       │                    └──────────→ OMA DM (remote ctrl)    │
│       │                                                          │
│       │  All dongle phone-home bypasses the VPN because it       │
│       │  goes over LTE directly from the dongle's own apps.      │
└─────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────┐
│  Data flows with OPENSTICK DEBIAN                                │
│                                                                  │
│  ┌────────┐   USB/WiFi    ┌──────────────┐   LTE    ┌────────┐ │
│  │  Host  │──────────────→│    Dongle     │─────────→│Internet│ │
│  │  (HA)  │               │   (Debian)   │          └────────┘ │
│  └────────┘               └──────────────┘                      │
│       │                    │                                     │
│       │  VPN protects      └→ Nothing. No phone-home.            │
│       │  ALL traffic ──→     No telemetry. No remote management. │
│       │                      Transparent NAT gateway only.       │
└─────────────────────────────────────────────────────────────────┘
```

| Threat | Risk with stock + VPN | Risk with Debian |
|---|---|---|
| Traffic interception by dongle | **HIGH** — sits before VPN, sees DNS + metadata | **NONE** — transparent NAT |
| Phone-home telemetry | **HIGH** — IMEI/IMSI/GPS leaked over LTE | **NONE** — no telemetry apps |
| Remote firmware update | **HIGH** — OMA DM pushes updates via carrier | **NONE** — no OMA DM |
| WiFi password exposure | **MEDIUM** — default `1234567890` | **LOW** — user-configured |
| Location tracking | **MEDIUM** — GPS collected and uploaded | **NONE** — no collection |
| Malicious firmware update via MITM | **HIGH** — test-keys, anyone can sign | **NONE** — no OTA mechanism |

---

## Detailed Findings

### CRITICAL

#### C1: Hardcoded Default Credentials

All passwords are hardcoded in cleartext as Android system properties, **identical
on every device** of this model:

```properties
persist.sys.juzhen.web.pd  = admin          # Web admin password
persist.sys.juzhen.ssid.pd = 1234567890     # WiFi hotspot password
persist.sys.juzhen.sim.pd  = UFIadmin88888  # SIM management password
```

Additionally, the push notification system uses a hardcoded password `123456`
(documented in the web UI: "initial password is 123456").

**Impact:** Any device within WiFi range can connect with `1234567890`. The web
admin panel at the dongle's IP gives full control over APN, WiFi, modem, and
system settings with password `admin`.

#### C2: Firmware Signed with Public Test Keys

```properties
ro.build.tags = test-keys    # AOSP default test keys (publicly known)
ro.build.type = user         # Production build
```

A production (`user`) build signed with AOSP's test keys, which are published
in the Android Open Source Project. Any attacker can:
- Create APKs with system-level privileges
- Push OTA updates the device will accept as genuine
- Replace any system component

**Impact:** Complete system compromise via any package installation vector.

#### C3: SELinux Disabled

```properties
ro.boot.selinux = disable
```

Android's mandatory access control system is explicitly turned off at boot.
Combined with test-keys signing, there are zero security boundaries between
applications and the system.

#### C4: Qihoo 360 Jiagu Application Packer

The main management app (`ufilauncherzx.apk`, package `com.youdo.server`) is
packed with **Qihoo 360's jiagu** (加固) commercial obfuscation tool.

**Packer architecture:**
```
ufilauncherzx.apk
├── classes.dex             ← Stub only (5 classes)
│   ├── com.stub.StubApp    ← Entry point, loads libjiagu.so
│   ├── com.tianyu.util.DtcLoader  ← Dynamic class loader
│   └── com.tianyu.util.a   ← XOR string decoder, file extractor
├── assets/
│   ├── libjiagu.so         ← ARM32 decryptor/loader
│   ├── libjiagu_a64.so     ← ARM64 decryptor/loader
│   ├── libjiagu_x86.so     ← x86 decryptor/loader
│   └── libjiagu_x64.so     ← x86_64 decryptor/loader
├── lib/
│   └── libjgdtc.so         ← "Data Tracking Collection" library
└── [encrypted DEX]         ← Actual app code, decrypted at runtime only
```

**Concerning native methods in the packer stub:**
```java
// Location API interception — the PACKER hooks GPS, not just the app
public static native Location mark(LocationManager locationManager, String str);
public static native void mark(Location location);

// Permission management hooks
public static native void interface24(Activity, String[], int);

// 50+ obfuscated native methods (n010333, n0110, n0111, etc.)
```

The packer also includes:
- **Crash reporting** to `http://c.appjiagu.com/apk/cr.html` (Qihoo 360)
- **Performance tracking** (`Configuration.ENABLE_PT = true`)
- **Device fingerprinting**: collects ANDROID_ID, BRAND, MODEL, SIM operator
- **XOR-16 string obfuscation** to hide class and method names

**Why this matters:** The actual application code cannot be analyzed (encrypted
in native libraries). Only runtime decryption (e.g., Frida) could reveal the
real behavior. The packer's own location API hooks mean GPS interception
happens regardless of what the wrapped app does.

#### C5: China Mobile Auto-Registration (zzhc)

```
zzhc.vnet.cn
```

The `zzhc` service (自主号码采集 — "autonomous number collection") is a
China Mobile carrier requirement that:
- Reads the SIM card's IMSI (subscriber identity)
- Reads the device IMEI (hardware identity)
- Sends both to China Mobile's servers automatically
- Runs without user interaction or consent

This service was left active in the export firmware despite being intended
only for the Chinese domestic market.

#### C6: Hardcoded External Server

```javascript
// Found in the Vue.js web management UI embedded in the APK
m["default"].prototype.$imgPath = "http://154.48.236.92:7001"
```

The IP `154.48.236.92:7001` is a **YouDo Technology** (优度科技) cloud server
hardcoded into the management web interface. The dongle contacts this server
for image/resource loading. This creates an external dependency that:
- Leaks the dongle's IP address to YouDo's infrastructure
- Could be used for tracking or command-and-control
- Cannot be disabled without replacing the firmware

#### C7: IMEI Modification API

```
API endpoint: system/setSystemImei
```

The management app exposes an API endpoint that allows **changing the device's
IMEI** (International Mobile Equipment Identity). IMEI modification is:
- **Illegal** in most jurisdictions (EU, US, UK, Australia)
- Used for **identity fraud**, stolen device laundering, and tracking evasion
- A serious liability for anyone deploying these dongles

This is one of **103 API endpoints** discovered in the management web interface.
Other notable endpoints include:
- `gpsRecord/gpsRecordWithPage` — GPS location history with pagination
- `system/addApn` — add custom APN (can redirect all data traffic)
- `formalPackage/selectUpdateFile2Client` — push firmware updates
- `notice/sendNotify` — push notifications to devices
- `userInfo/batchAddUserInfo` — batch user management (fleet management)

#### C8: Broken Encryption

All API communication uses **DES encryption** (a 56-bit cipher broken since
1998) with a critically flawed key exchange:

```javascript
// The "secret" key is derived from a Snowflake ID
// BOTH the full ID AND the character positions are sent in cleartext
return {
    data: DES_encrypt(plaintext, secretkey),    // DES-encrypted data
    pulickKey: snowflakeId + "$" + positions    // Key reconstruction info!
}
```

Anyone intercepting the HTTP traffic (no TLS) can:
1. Read the `pulickKey` field
2. Extract the Snowflake ID and position array
3. Reconstruct the 6-character DES key
4. Decrypt all communication

**Impact:** All management API traffic is effectively plaintext.

---

### HIGH

#### H1: Qualcomm RIDL — Remote Information & Data Logger

**App:** `RIDLClient.apk` (com.qualcomm.RIDL, v4.3.12)

Qualcomm's RIDL system collects and uploads device data:
- **GPS coordinates** (latitude, longitude, altitude — confirmed via database schema)
- Network type and signal quality
- Bluetooth device information
- Call and device diagnostics
- **Uploads every 15 minutes** to `https://statmando.qualcomm.com/RIDL.php`

The SSL implementation **bypasses hostname verification**:
```java
httpCon.setHostnameVerifier(new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return "statmando.qualcomm.com".equalsIgnoreCase(hostname);
        // Only checks hostname string, NOT the certificate chain
    }
});
```

This makes the upload vulnerable to MITM attacks with any certificate
that presents the correct hostname.

**Permissions:** INTERNET, READ_LOGS, ACCESS_FINE_LOCATION,
PROCESS_OUTGOING_CALLS, BLUETOOTH, BLUETOOTH_ADMIN, REBOOT

#### H2: Qualcomm CNE — Connectivity Engine

Sends traffic analysis and WiFi environment data to `cne.qualcomm.com`.
Continuously evaluates network quality by analyzing actual traffic patterns,
WiFi access point characteristics, and connection metadata.

#### H3: OMA Device Management

**App:** `DM.apk` (com.android.dm)

A full OMA-DM client that allows the carrier to remotely manage the device:
- **Receives commands via data SMS on port 16998**
- Receives OMA-DM WAP push messages
- Can modify APN settings (redirect all traffic)
- Can modify system settings and browser bookmarks
- Has a secret dialer code `*#*#3636#*#*` for debug access
- Auto-starts on boot via `DmReceiver`
- Uses native JNI for the OMA-DM protocol (`DMNativeMethod`)

**Permissions:** RECEIVE_SMS, SEND_SMS, RECEIVE_WAP_PUSH, WRITE_APN_SETTINGS,
ACCESS_FINE_LOCATION, READ_HISTORY_BOOKMARKS, CONNECTIVITY_INTERNAL

**Impact:** The carrier (or anyone who can send data SMS to port 16998) can
remotely control the device, completely bypassing any VPN or firewall.

#### H4: Qualcomm Diagnostic Interface Exposed

```properties
persist.sys.usb.config = diag,serial_smd,rmnet_bam,adb
```

The default USB configuration exposes:
- **DIAG** — Qualcomm diagnostic interface (read/write modem NV items, IMEI,
  raw AT commands, over-the-air radio capture)
- **serial_smd** — serial debug access to modem subsystem
- **ADB** — Android Debug Bridge (full shell access)

#### H5: ADB with Pre-installed Auth Key

ADB is enabled by default, and a pre-installed public key (`/etc/adbkey.pub`,
owner `unknown@unknown`) is embedded in the system partition. Whoever holds
the corresponding private key has permanent, passwordless shell access.

#### H6: Dangerous Android Permissions

The management app requests **14 dangerous permissions** out of 21 total:

| Permission | Capability |
|---|---|
| READ_SMS, WRITE_SMS, SEND_SMS | Read, modify, and send text messages |
| READ_CONTACTS, WRITE_CONTACTS | Read and modify contact list |
| READ_CALL_LOG, WRITE_CALL_LOG | Read and modify call history |
| ACCESS_FINE_LOCATION | Precise GPS location |
| READ_PHONE_STATE | Read IMEI, phone number, SIM info |
| MODIFY_PHONE_STATE | Modify telephony state |
| WRITE_APN_SETTINGS | Modify APN (redirect all data traffic) |
| WRITE_SETTINGS | Modify system settings |
| RECEIVE_BOOT_COMPLETED | Auto-start on boot |
| KILL_BACKGROUND_PROCESSES | Kill other applications |

Both background services (`UfiServer`, `HttpService`) are declared as
`exported="true"`, meaning any app on the device can interact with them.

#### H7: WiFi Security Weaknesses

```
auth_algs=3              # Enables legacy Shared Key Authentication
# ap_isolate not set     # Clients can communicate with each other
# ieee80211w not set     # Management frame protection disabled
```

- **Shared Key Authentication** (WEP-era, cryptographic weaknesses)
  enabled alongside WPA2
- **Client isolation disabled** — connected devices can scan and attack
  each other
- **802.11w disabled** — deauthentication attacks possible

---

### MEDIUM

#### M1: Chinese Carrier Bloatware

Pre-installed apps for all three Chinese carriers (15 APKs from China Mobile
alone), including:
- `CarrierLoadService.apk` — **silent app download and installation**
- `CmccServer.apk` — China Mobile service with CALL_PHONE and SEND_SMS
- `AutoRegistration.apk` — auto-registers device with carrier on boot
- `10086cn.apk`, `CmccWifi.apk`, `CmccCustom.apk` — China Mobile portals

#### M2: Crash Reporting to Qihoo 360

```
http://c.appjiagu.com/apk/cr.html
qihoo_jiagu_crash_report.xml
```

Crash reports sent unencrypted to Qihoo 360's servers, including device
identifiers, app state, and stack traces.

#### M3: Google Geolocation Services

WiFi access point and cell tower data sent to Google for geolocation.
Standard Android behavior but undisclosed on a USB dongle.

#### M4: Management Frame Protection Disabled

802.11w (Protected Management Frames) not enabled. Allows deauthentication
attacks against connected WiFi clients.

#### M5: Statistics Collection Daemons

```
CrashLogger.apk    — system-level crash collection
StatManDo.apk      — usage statistics daemon
MediaUploader.apk  — media metadata upload service
```

System daemons that collect and potentially upload device usage data.
Exact data destinations unclear due to jiagu obfuscation of the main app.

---

## System App Inventory

19 APKs extracted from the system partition. Key apps by risk:

| APK | Package | Risk | Capabilities |
|---|---|---|---|
| **ufilauncherzx.apk** | com.youdo.server | CRITICAL | Jiagu-packed, 103 API endpoints, YouDo cloud, IMEI mod, GPS tracking |
| **RIDLClient.apk** | com.qualcomm.RIDL | HIGH | GPS + diagnostics → Qualcomm every 15 min, SSL bypass |
| **DM.apk** | com.android.dm | HIGH | OMA-DM, SMS port 16998, remote APN/settings control |
| **CmccServer.apk** | com.android.cmcc | MEDIUM | CALL_PHONE, SEND_SMS without user consent |
| **CarrierLoadService.apk** | — | MEDIUM | Silent app download and installation |
| **AutoRegistration.apk** | — | MEDIUM | Auto-register device with carrier on boot |
| **CrashLogger.apk** | — | MEDIUM | System crash collection |
| **StatManDo.apk** | — | MEDIUM | Usage statistics |
| **DataMonitor.apk** | — | LOW | Data usage monitoring |
| **NetworkSetting.apk** | — | LOW | Network settings UI |
| **ModemTestMode.apk** | — | LOW | Modem diagnostics |

---

## Build Identity

| Property | Value |
|---|---|
| Build fingerprint | `qcom/msm8916_32_512/msm8916_32_512:4.4.4/KTU84P/eng.richal.20251104:user/test-keys` |
| Build engineer | `richal` |
| Source path | `/home/richal/code3/jz0116/Android/kernel/` |
| Build host | `server` |
| Build date | 2025-11-04 |
| Board | JZ0116 → JZ0145 v33 variant |
| Product | UFI branded (`ro.product.model=UFI`) |

The build path (`jz0116`) and engineer username (`richal`) indicate a
small-scale operation at Juzhen (矩阵) Technology.

---

## Methodology

### Tools

| Tool | Version | Purpose |
|---|---|---|
| `strings` | GNU coreutils | Extract printable text from 3.4 GB of partition images |
| `grep` | GNU grep | Pattern matching (URLs, credentials, services, phone-home indicators) |
| `debugfs` | e2fsprogs | Read ext4 partition images without mounting (no root needed) |
| `binwalk` | 2.1.0 | Scan for and extract embedded files from raw images |
| `jadx` | 1.5.1 | Decompile Android APK/DEX to Java source code |
| `file` | GNU | File type identification |
| `dtc` | system | Device tree compiler/decompiler |

### Process

1. **System properties** — parsed `getprop.txt` (278 properties) for credentials,
   debug flags, vendor configuration, carrier settings
2. **WiFi configuration** — analyzed `hostapd.conf` (1045 lines) for authentication
   weaknesses, WPS state, management frame protection
3. **Binary string extraction** — ran `strings` on system.bin (800 MB) and
   userdata.bin (2.6 GB), extracted 4.5M+ strings, filtered for URLs (1,014 unique),
   IP addresses (760), Chinese domains (278), credential patterns (522),
   certificate references (374)
4. **APK extraction** — used `debugfs` to extract 48 APKs from the ext4 system
   partition image without root access
5. **APK decompilation** — decompiled 4 key APKs with jadx (ufilauncherzx,
   RIDLClient, DM, CmccServer), analyzed Java source for network connections,
   data collection, API endpoints, permissions
6. **Jiagu packer analysis** — analyzed the 5 stub classes visible through the
   Qihoo 360 jiagu obfuscation, identified native method signatures including
   location API hooks
7. **Service analysis** — searched for init scripts, daemon definitions, listening
   ports, remote access mechanisms, SMS interception

### Limitations

- **Jiagu encryption** — the main app's actual code is encrypted in native
  libraries (`libjiagu.so`). Full analysis requires runtime decryption
  (e.g., Frida instrumentation on a running device)
- **No filesystem mount** — partition images analyzed via binary string extraction
  and `debugfs`, not mounted. Some metadata not accessible
- **Modem firmware** — the Qualcomm MPSS modem firmware is a proprietary binary
  blob not analyzed. Modem-level backdoors cannot be ruled out
- **Network traffic** — no live traffic capture was performed. Phone-home
  behavior inferred from code analysis, not observed network connections

---

## Conclusion

The stock firmware is **compromised by default** through a combination of:

1. **Manufacturer negligence** — test-keys signing, SELinux disabled, hardcoded
   passwords, broken DES encryption, IMEI modification endpoint, debug
   interfaces exposed
2. **Intentional Chinese carrier requirements** — zzhc IMSI collection, OMA-DM
   remote management, auto-registration, carrier bloatware with call/SMS
   permissions
3. **Qualcomm telemetry** — RIDL GPS tracking (15-min uploads), CNE traffic
   analysis, with deliberately weakened SSL verification
4. **Third-party obfuscation** — Qihoo 360 jiagu packer hides app behavior,
   includes its own location API hooks and crash reporting to Chinese servers

For any security-conscious deployment, the stock firmware should be replaced
immediately. The OpenStick Debian installation eliminates all identified
software-level threats while retaining full hardware functionality (LTE modem,
WiFi, USB networking).

The only remaining proprietary components after flashing Debian are the
Qualcomm coprocessor firmwares (modem, WiFi, TrustZone, RPM), which are
standard across all MSM8916 devices and operate below the OS level.

---

## Appendix: Detailed Findings

- [01 — System Properties and WiFi Configuration](findings/01-properties-and-wifi.md) (342 lines)
- [02 — URLs, Domains, IPs, and Credentials](findings/02-urls-and-credentials.md) (679 lines)
- [03 — Services, Daemons, and Backdoor Assessment](findings/03-services-and-backdoors.md) (372 lines)
- [04 — APK Extraction and Decompilation](findings/04-apk-analysis.md) (478 lines)
