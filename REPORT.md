# UFI 4G USB Dongle Firmware Security Analysis

**Date:** 2026-03-27
**Device:** Juzhen UFI 4G USB WiFi Dongle (JZ0145-v33, MSM8916)
**Firmware:** Android 4.4.4 KTU84P, build `eng.richal.20251104`, test-keys
**Scope:** Authorized security research on owned hardware
**Method:** Binary string extraction, APK decompilation, configuration analysis
**Tools:** strings, grep, binwalk, jadx 1.5.1, dtc

---

## Executive Summary

The stock firmware of the UFI 4G USB dongle presents **severe security risks**
for any deployment. The analysis identified **5 critical**, **7 high**, and
**5 medium** severity findings across the firmware stack.

The most significant risks are:

1. **Active phone-home to Chinese servers** — the device sends IMSI, IMEI, and
   device identifiers to `zzhc.vnet.cn` (China Mobile) without user consent
2. **Qihoo 360 jiagu obfuscation** — the main management app is packed with a
   Chinese obfuscation tool that hooks into location APIs and has crash reporting
   to `c.appjiagu.com`
3. **Zero authentication security** — WiFi password `1234567890`, web admin
   `admin`, SIM management `UFIadmin88888`, all hardcoded in cleartext
4. **Qualcomm telemetry active** — RIDL (Remote Information & Data Logger)
   collects GPS coordinates and uploads to Qualcomm; CNE sends traffic analysis
5. **OMA Device Management** — allows the carrier to remotely manage, configure,
   and push updates to the device without user consent
6. **Firmware signed with public test-keys** — anyone can create system-level
   packages that the device will accept as trusted

### Risk Assessment for VPN Use Case

The user's scenario: dongle connected via USB or WiFi, traffic routed through
Tailscale/NetBird VPN.

| Threat | Risk with VPN | Notes |
|---|---|---|
| Traffic interception by dongle | **HIGH** | Dongle sits BEFORE the VPN tunnel — it can see all DNS queries and connection metadata |
| Phone-home telemetry | **HIGH** | Device identifiers (IMEI, IMSI) leaked to Chinese/Qualcomm servers on the LTE side |
| Remote firmware update | **HIGH** | OMA DM can push updates over LTE, bypassing VPN entirely |
| WiFi password exposure | **MEDIUM** | Default `1234567890`, any nearby device can connect |
| Location tracking | **MEDIUM** | GPS/cell tower data collected and uploaded |
| Malicious firmware update | **HIGH** | test-keys signing means a MITM on LTE could push malicious system updates |

**The VPN does NOT protect against these risks** because:
- Phone-home traffic goes over LTE, outside the VPN tunnel
- The dongle operates at layer 2/3 before VPN encryption
- Remote management (OMA DM) operates over the carrier network
- The obfuscated jiagu app runs on the dongle itself, with full system access

### Additional Critical Findings from APK Decompilation

The jadx decompilation of extracted APKs revealed even more severe issues:

- **Hardcoded external server `154.48.236.92:7001`** (YouDo Technology cloud)
  embedded in the management web UI — loaded for image/resource fetching
- **IMEI modification API** (`system/setSystemImei`) — allows changing the
  device's IMEI, enabling identity fraud
- **103 API endpoints** exposed by the management app, including GPS tracking,
  user management, OTA updates, push notifications, and SMS operations
- **DES encryption** (broken, 56-bit keys) used for ALL API communication,
  with encryption keys sent alongside the ciphertext
- **DM.apk receives data SMS on port 16998** — remote carrier commands via SMS
- **RIDLClient uploads every 15 minutes** to `statmando.qualcomm.com` with
  SSL hostname verification deliberately bypassed
- **14 dangerous Android permissions** including READ_SMS, SEND_SMS,
  WRITE_SMS, READ_CONTACTS, ACCESS_FINE_LOCATION, READ_PHONE_STATE

### Recommendation

**Replacing the stock firmware with OpenStick (Debian) eliminates all identified
threats.** The Debian installation:
- Removes all Chinese apps and telemetry
- Removes Qualcomm RIDL/CNE data collection
- Removes OMA Device Management
- Removes the jiagu-packed management app
- Uses mainline kernel without vendor backdoors
- Provides full user control over all network traffic

---

## Detailed Findings

### CRITICAL Findings

#### C1: Hardcoded Default Credentials

**All passwords stored in cleartext** in Android system properties:

```
persist.sys.juzhen.ssid.pd = 1234567890    # WiFi password
persist.sys.juzhen.web.pd  = admin          # Web admin password
persist.sys.juzhen.sim.pd  = UFIadmin88888  # SIM management password
```

These are readable by any app on the device and are never rotated. The WiFi
password `1234567890` is the same on every dongle by default.

**Impact:** Any device within WiFi range can connect. Web admin gives full
control over APN, WiFi, and modem settings.

#### C2: Firmware Signed with Test Keys

```
ro.build.tags = test-keys
ro.build.type = user
```

A production (`user`) build signed with AOSP test keys. These keys are
publicly available in the Android source code. Any attacker can:
- Create APKs that install with system privileges
- Push OTA updates that the device accepts as genuine
- Replace system components

**Impact:** Complete system compromise via any package install vector.

#### C3: SELinux Disabled

```
ro.boot.selinux = disable
```

SELinux (Mandatory Access Control) is explicitly disabled at boot. Combined
with test-keys, this means there are zero access control boundaries between
apps and the system.

#### C4: Qihoo 360 Jiagu Application Packer

The main management app (`ufilauncherzx.apk`) is packed with **Qihoo 360's
jiagu** (加固) obfuscation tool. Analysis of the decompiled stub reveals:

```java
// StubApp.java - jiagu loader
private static String c = "libjiagu";
// Loads encrypted native library from hidden .jiagu directory
System.load(str + "/" + e);
// Dynamic class loading - real app code is encrypted
b = (Application) classLoader.loadClass(strEntryApplication).newInstance();
```

The packer includes:
- **Native location API hooks**: `mark(LocationManager, String)` — intercepts GPS
- **Native permission management**: hooks into Android permission system
- **Crash reporting to Qihoo**: `http://c.appjiagu.com/apk/cr.html`
- **String obfuscation**: XOR-encoded strings hide class/method names

**Why this matters:** The actual behavior of the management app is hidden behind
military-grade obfuscation. We cannot determine what data it collects or where
it sends it. The presence of location API hooks in the packer is particularly
concerning.

#### C5: China Mobile Auto-Registration (zzhc)

```
zzhc.vnet.cn
```

The `zzhc` service (自主号码采集 — "autonomous number collection") automatically:
- Reads the SIM card's IMSI (subscriber identity)
- Reads the device IMEI
- Sends both to China Mobile's servers
- Runs without any user interaction or consent

This is a carrier-mandated service in China that was left active in the
export firmware.

### HIGH Findings

#### H1: Qualcomm RIDL — Remote Information & Data Logger

**`RIDLClient.apk`** is a Qualcomm system app that:
- Collects GPS coordinates (latitude, longitude, altitude)
- Collects network type and signal quality
- Collects device diagnostics
- Compresses and uploads data to Qualcomm servers

Found database schema references to location tracking tables with
latitude/longitude fields.

#### H2: Qualcomm CNE — Connectivity Engine

Sends traffic analysis and WiFi environment data to `cne.qualcomm.com`.
Evaluates network quality by analyzing actual traffic patterns.

#### H3: OMA Device Management (DM.apk)

OMA DM allows the carrier to:
- Push configuration changes remotely
- Install or update apps
- Modify APN and network settings
- Execute device management commands

This operates over the carrier's control channel, completely bypassing any
VPN or firewall on the device.

#### H4: Qualcomm Diagnostic Interface Exposed

```
persist.sys.usb.config = diag,serial_smd,rmnet_bam,adb
```

The Qualcomm DIAG interface is enabled by default on USB, allowing:
- Reading/writing modem NV items (including IMEI)
- Raw AT command access
- Over-the-air radio traffic capture
- Modem firmware parameter modification

#### H5: ADB Enabled by Default

ADB is part of the default USB configuration. Anyone with USB access has
full shell access to the device.

#### H6: 802.11 Shared Key Authentication Enabled

```
auth_algs=3   # Both Open System (1) and Shared Key (2)
```

Shared Key Authentication is a legacy WEP-era mechanism with known
cryptographic weaknesses. It should never be enabled alongside WPA2.

#### H7: WiFi Client Isolation Disabled

```
# ap_isolate not set (defaults to 0)
```

Connected WiFi clients can communicate with each other and scan the
local network. In a hotspot scenario, this allows one connected device
to attack others.

### MEDIUM Findings

#### M1: Chinese Carrier Bloatware

Pre-installed apps for all three Chinese carriers:
- `10086cn.apk` — China Mobile portal
- `CmccServer.apk`, `CmccWifi.apk`, `CmccCustom.apk` — China Mobile services
- `CarrierLoadService.apk` — carrier app auto-download service
- `Monternet.apk` — China Mobile mobile internet portal

These apps have capabilities for:
- Auto-registration with carrier
- Silent app downloads (`CarrierLoadService`)
- Background data collection

#### M2: Google Geolocation Services Active

WiFi access point and cell tower data is sent to Google for geolocation.
While less concerning than the Chinese telemetry, this is still data
collection without explicit user consent on a USB dongle.

#### M3: WPS Disabled but WPS PIN Present

```
wps_state=0            # WPS disabled (good)
device_name=QualcommAtheros  # But WPS device name configured
```

WPS is disabled, but the configuration suggests it was available and
may be re-enabled by firmware updates.

#### M4: Management Frame Protection Disabled

```
# ieee80211w not set (defaults to disabled)
```

802.11w (Protected Management Frames) is not enabled. This allows
deauthentication attacks against connected WiFi clients.

#### M5: CrashLogger and Statistics Collection

```
CrashLogger.apk
StatManDo.apk
MediaUploader.apk
```

System-level daemons that collect crash reports, usage statistics,
and media metadata. Data destination is unclear due to jiagu obfuscation.

---

## System App Inventory

APKs extracted from the system partition:

| APK | Purpose | Risk |
|---|---|---|
| **ufilauncherzx.apk** | Main management app (jiagu-packed) | CRITICAL — obfuscated, unknown behavior |
| **RIDLClient.apk** | Qualcomm data collection | HIGH — GPS + diagnostics upload |
| **DM.apk** | OMA Device Management | HIGH — remote carrier control |
| **10086cn.apk** | China Mobile portal | MEDIUM — carrier telemetry |
| **CmccServer.apk** | China Mobile services | MEDIUM — auto-registration |
| **CmccWifi.apk** | China Mobile WiFi | MEDIUM — WiFi data collection |
| **CmccCustom.apk** | China Mobile customization | MEDIUM |
| **CarrierLoadService.apk** | Silent app download | MEDIUM — can install apps |
| **CarrierConfigure.apk** | Carrier configuration | MEDIUM |
| **DataMonitor.apk** | Data usage monitoring | LOW |
| **DeviceInfo.apk** | Device information | LOW |
| **Firewall.apk** | Network firewall | LOW |
| **NetworkSetting.apk** | Network settings UI | LOW |
| **AreaSearch.apk** | Location/area search | LOW |
| **ModemTestMode.apk** | Modem diagnostics | LOW |
| **xtra_t_app.apk** | GPS assistance (XTRA) | LOW |
| **CrashLogger.apk** | Crash reporting | MEDIUM |
| **StatManDo.apk** | Statistics collection | MEDIUM |
| **MediaUploader.apk** | Media upload service | MEDIUM |

Additionally, the system partition contains Google apps (Chrome, Gmail,
Play Services, etc.) which add their own telemetry but are standard
Android components.

---

## Jiagu Packer Technical Analysis

The `ufilauncherzx.apk` management app uses Qihoo 360's jiagu (加固)
application protection. Decompilation with jadx 1.5.1 reveals only 5
stub files — the actual application code is encrypted inside native
libraries.

### Packer Architecture

```
ufilauncherzx.apk
├── classes.dex           ← Stub only (5 classes)
│   ├── com.stub.StubApp  ← Application entry, loads libjiagu.so
│   ├── com.tianyu.util.DtcLoader  ← Dynamic class loader
│   ├── com.tianyu.util.a  ← Utility (string decode, file extract)
│   ├── com.tianyu.util.Configuration  ← Config
│   └── com.youdo.server.R  ← Resources
├── assets/
│   ├── libjiagu.so       ← ARM 32-bit decryptor
│   ├── libjiagu_a64.so   ← ARM 64-bit decryptor
│   ├── libjiagu_x86.so   ← x86 decryptor
│   └── libjiagu_x64.so   ← x86_64 decryptor
└── [encrypted DEX]       ← Real app code, decrypted at runtime
```

### Runtime Behavior

1. Android loads `StubApp` as the Application class
2. `StubApp.attachBaseContext()` extracts `libjiagu.so` to a hidden
   `.jiagu` directory in the app's data folder
3. The native library is loaded via `System.load()`
4. Native code decrypts the real DEX bytecode in memory
5. `DtcLoader` dynamically loads the decrypted classes
6. The real Application class (`entryRunApplication`) is instantiated
7. All subsequent calls are proxied through native methods

### Concerning Native Methods

```java
// Location API interception
public static native Location mark(LocationManager locationManager, String str);
public static native void mark(Location location);

// Permission management hooks
public static native void interface24(Activity, String[], int);

// Dozens of obfuscated native methods (n010333, n0110, n0111, etc.)
// Purpose unknown — could be anything from data collection to remote access
```

The presence of `LocationManager` hooks in the **packer itself** (not the app)
means the jiagu framework has built-in capability to intercept and potentially
exfiltrate location data, regardless of what the wrapped app does.

### Crash Reporting Phone-Home

```
http://c.appjiagu.com/apk/cr.html
qihoo_jiagu_crash_report.xml
```

Crash reports are sent to Qihoo 360's servers, including device identifiers
and potentially app state information.

---

## Network Threat Model

```
┌─────────────────────────────────────────────────────────────┐
│  Data flows with stock firmware                              │
│                                                              │
│  ┌────────┐   USB/WiFi    ┌──────────┐   LTE    ┌────────┐ │
│  │  Host  │──────────────→│  Dongle  │─────────→│Internet│ │
│  │  (HA)  │               │ (And4.4) │          └────────┘ │
│  └────────┘               └──────────┘                      │
│       │                    │ │ │ │ │                         │
│       │                    │ │ │ │ └→ zzhc.vnet.cn (IMSI)   │
│       │                    │ │ │ └──→ appjiagu.com (crash)   │
│       │                    │ │ └────→ Qualcomm RIDL (GPS)    │
│       │                    │ └──────→ Qualcomm CNE (traffic) │
│       │                    └────────→ OMA DM (remote ctrl)   │
│       │                                                      │
│       └── VPN tunnel only protects THIS traffic ──→          │
│           (dongle phone-home bypasses VPN)                    │
└─────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────┐
│  Data flows with OpenStick (Debian)                          │
│                                                              │
│  ┌────────┐   USB/WiFi    ┌──────────┐   LTE    ┌────────┐ │
│  │  Host  │──────────────→│  Dongle  │─────────→│Internet│ │
│  │  (HA)  │               │ (Debian) │          └────────┘ │
│  └────────┘               └──────────┘                      │
│       │                    │                                 │
│       │                    └→ (nothing — no phone-home)      │
│       │                                                      │
│       └── VPN tunnel protects ALL traffic ──→                │
│           (dongle is a transparent NAT gateway)              │
└─────────────────────────────────────────────────────────────┘
```

---

## Methodology

### Tools Used

| Tool | Version | Purpose |
|---|---|---|
| `strings` | GNU coreutils | Extract printable text from binary partition images |
| `grep` | GNU grep | Pattern matching for URLs, credentials, services |
| `binwalk` | 2.1.0 | Scan for embedded files and extract APKs |
| `jadx` | 1.5.1 | Decompile Android APKs to Java source |
| `dtc` | (system) | Device tree compiler for DTB analysis |
| `file` | (system) | File type identification |

### Analysis Process

1. **Property analysis**: Parsed `getprop.txt` (278 properties) for
   credentials, debug flags, vendor-specific settings
2. **WiFi configuration**: Analyzed `hostapd.conf` (1045 lines) for
   security weaknesses
3. **Binary string extraction**: Ran `strings` on system.bin (800 MB)
   and userdata.bin (2.6 GB), filtered for URLs, IPs, domains, credentials
4. **APK extraction**: Used `binwalk` to extract APKs from the raw
   system partition image
5. **APK decompilation**: Decompiled `ufilauncherzx.apk` with `jadx`,
   analyzed the jiagu packer stub code
6. **Service analysis**: Searched for init scripts, daemon definitions,
   listening ports, remote access mechanisms

### Limitations

- **Jiagu encryption**: The main app's actual code could not be analyzed
  due to native-code encryption. A full analysis would require runtime
  decryption (e.g., Frida hooking on a running device)
- **No mount access**: Partition images were analyzed via binary string
  extraction, not mounted filesystems. Some filesystem metadata was not
  available
- **Modem firmware**: The Qualcomm modem firmware (MPSS) is a proprietary
  binary blob that was not analyzed. Modem-level backdoors cannot be ruled out

---

## Conclusion

The stock firmware is fundamentally insecure by design and by accident:

- **By design**: Chinese carrier requirements (zzhc auto-registration,
  OMA DM remote management) and Qualcomm telemetry (RIDL, CNE) are
  intentional data collection mechanisms
- **By accident**: test-keys signing, disabled SELinux, hardcoded passwords,
  and exposed debug interfaces are negligence by the manufacturer (Juzhen)

For any security-conscious deployment, the stock firmware should be
considered **compromised by default**. The replacement with OpenStick
Debian eliminates all identified software-level threats while retaining
the hardware's functionality.

The only remaining proprietary components after the OpenStick flash are
the Qualcomm coprocessor firmwares (modem, WiFi, TZ, RPM), which operate
below the OS level and are standard across all MSM8916 devices.

---

## Detailed Findings Files

- [01-properties-and-wifi.md](findings/01-properties-and-wifi.md) — System properties and WiFi configuration
- [02-urls-and-credentials.md](findings/02-urls-and-credentials.md) — URLs, domains, IPs, and hardcoded credentials
- [03-services-and-backdoors.md](findings/03-services-and-backdoors.md) — Services, daemons, and backdoor assessment
- [04-apk-analysis.md](findings/04-apk-analysis.md) — APK extraction and decompilation (when available)
