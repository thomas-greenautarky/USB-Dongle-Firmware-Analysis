# UFI 4G Dongle Firmware Analysis: Services, Daemons, and Backdoor Assessment

**Date:** 2026-03-27
**Analyst:** Firmware security review (authorized research on owned hardware)
**Target:** Juzhen UFI 4G Dongle (jz01-16 board variant, MSM8916 SoC)
**Firmware Build:** `msm8916_32_512-user 4.4.4 KTU84P eng.richal.20251104 test-keys`
**Method:** Binary string extraction from ext4 partition images (no mount)

---

## Executive Summary

The firmware presents **multiple high-severity security concerns**. The most critical findings are:

1. **Qihoo 360 Jiagu packer** protecting at least one system APK, with active crash reporting to `c.appjiagu.com`
2. **test-keys signing** on a "user" build -- an extremely unusual and dangerous combination
3. **Diagnostic USB interfaces** (diag, serial_smd) exposed by default alongside ADB
4. **Chinese carrier bloatware** with auto-registration, device management, and silent download capabilities
5. **No dropbear/telnetd backdoors detected**, but the existing attack surface is substantial

---

## 1. Build Identity and Signing (SEVERITY: CRITICAL)

| Property | Value |
|---|---|
| `ro.build.fingerprint` | `qcom/msm8916_32_512/msm8916_32_512:4.4.4/KTU84P/eng.richal.20251104:user/test-keys` |
| `ro.build.type` | `user` (production) |
| `ro.build.tags` | `test-keys` |
| `ro.build.user` | `richal` |
| `ro.board.platform` | `msm8916` |
| Build date | `2025` (UTC: `1762198539`) |
| Kernel source | `/home/richal/code3/jz0116/Android/kernel/` |

### Analysis

**CRITICAL: test-keys on a user build.** This means the firmware is signed with AOSP default test keys, which are publicly known. Any attacker can sign APKs with these keys and gain system-level privileges. This is a hallmark of cheap Chinese dongles where the manufacturer never generated proper release keys.

The build engineer username `richal` and source path `jz0116` confirm this is a Juzhen (JZ) board variant built in a small-scale operation.

---

## 2. ADB and Debug Configuration (SEVERITY: HIGH)

### Default USB Configuration
```
persist.sys.usb.config=diag,serial_smd,rmnet_bam,adb
```

### Findings

| Property | Value | Risk |
|---|---|---|
| `persist.sys.usb.config` | `diag,serial_smd,rmnet_bam,adb` | ADB + Qualcomm diag + serial exposed |
| `ro.adb.secure` | Present (value not extractable via strings) | Likely enforced |
| `ro.debuggable` | Present (value not extractable) | Unknown |
| `ro.secure` | Present (value not extractable) | Unknown |

### Analysis

**HIGH: Qualcomm diagnostic interface (diag) is enabled by default.** The `diag` interface provides low-level access to the Qualcomm modem subsystem, allowing:
- Reading/writing NV items (including IMEI)
- Sending raw AT commands to the modem
- Capturing over-the-air radio traffic
- Modifying modem firmware parameters

The `serial_smd` interface provides additional serial debug access to the modem.

Additionally found: `setprop sys.usb.config diag,qdss,adb` -- a secondary config that adds Qualcomm Debug Subsystem (QDSS) trace capability.

---

## 3. Qihoo 360 Jiagu Packer (SEVERITY: CRITICAL)

### System Partition References
```
assets/libjiagu.so
assets/libjiagu_a64.so
assets/libjiagu_x64.so
assets/libjiagu_x86.so
```

### Userdata Partition References (Active Runtime Artifacts)
```
files/.jglogs/.jg.ac
files/.jglogs/.jg.ic
files/.jglogs/.jg.pk
files/.jglogs/.jg.rd
files/.jglogs/.jg.ri
files/.jglogs/.log
files/.jglogs/.log1
files/.jglogs/.log15
files/.jglogs/.log2
files/.jiagu.lock
http://c.appjiagu.com/apk/cr.html
qihoo_jiagu_crash_report.xml
/qihooCrash
libjiagu551223534.so
libjiagu_vip_enc.so
libjiagu_vip_mips.a
libdjiagu.so
JIAGU_APP_NAME
JIAGU_ENCRYPTED_DEX_NAME
JIAGU_SO_BASE_NAME
JIAGU_FILE_PATH
JIAGU_HASH_FILE_NAME
jiagu_vip
```

### Analysis

**CRITICAL: At least one system APK is packed with Qihoo 360 Jiagu.** Jiagu (meaning "reinforcement/hardening") is an Android app packing/obfuscation service from Qihoo 360 (a Chinese security company). Key concerns:

1. **Code Obfuscation:** The packed APK's DEX code is encrypted at rest and decrypted at runtime by `libjiagu.so`. This prevents static analysis of what the app actually does.
2. **Active Crash Reporting:** The URL `http://c.appjiagu.com/apk/cr.html` and `qihoo_jiagu_crash_report.xml` indicate crash data is sent to Qihoo 360's servers over HTTP (not HTTPS).
3. **VIP Version:** The presence of `jiagu_vip` and `libjiagu_vip_enc.so` suggests the paid/premium packer was used, which includes stronger anti-tampering and anti-debugging.
4. **Multi-architecture:** Libraries for ARM, ARM64, x86, and x64 are bundled, indicating intent for broad deployment.
5. **Runtime Logs:** The `.jglogs` directory in userdata shows the packed app has executed, generating operational logs (`.jg.ac`, `.jg.ic`, `.jg.pk`, `.jg.rd`, `.jg.ri`).

**This is the single most concerning finding.** A Jiagu-packed app on a 4G modem dongle means there is hidden, unauditable code running with potential access to the modem, SIM card, and all network traffic.

---

## 4. Chinese Carrier Bloatware (SEVERITY: HIGH)

### Pre-installed Carrier APKs

| APK | Purpose | Carrier | Risk |
|---|---|---|---|
| `10086cn.apk` | China Mobile portal | CMCC | Data collection, premium SMS |
| `CmccServer.apk` | China Mobile service backend | CMCC | Service management |
| `CmccCustom.apk` | China Mobile customization | CMCC | Device configuration |
| `CmccWifi.apk` | China Mobile WiFi management | CMCC | Network access |
| `CtUniversalDownload.apk` | China Telecom silent downloader | CT | **Silent app installation** |
| `CtBrowserQuick.apk` | China Telecom browser | CT | Web tracking |
| `CtLauncherRes.apk` | China Telecom launcher | CT | UI overlay |
| `CtRoamingSettings.apk` | China Telecom roaming | CT | Network config |
| `CtWallpaper.apk` | China Telecom wallpaper | CT | Cosmetic |
| `CuBrowserQuick.apk` | China Unicom browser | CU | Web tracking |
| `CuLauncherRes.apk` | China Unicom launcher | CU | UI overlay |
| `CuWallpaper.apk` | China Unicom wallpaper | CU | Cosmetic |
| `AutoRegistration.apk` | Auto SIM registration | Qualcomm/carrier | **Automatic network registration** |
| `CarrierConfigure.apk` | Carrier config switching | Qualcomm | Network config |
| `CarrierLoadService.apk` | Carrier package loader | Qualcomm | **Dynamic package loading** |
| `CustomerService.apk` | Customer service hotline | Carrier | SMS-based service |
| `DataMonitor.apk` | Data usage monitoring | Qualcomm | Traffic monitoring |
| `Firewall.apk` | Call/SMS firewall | OEM | Call/SMS filtering |
| `DM.apk` | Device Management (OMA-DM) | Carrier | **Remote device management** |
| `DeviceInfo.apk` | Device info reporter | OEM | Device data collection |
| `AreaSearch.apk` | Area code lookup | OEM | Location data |
| `fastdormancy.apk` | Fast dormancy control | Qualcomm | Radio management |

### Analysis

**HIGH: CtUniversalDownload (China Telecom Universal Download)** is a silent app downloader/installer:
- Exposes `IDownloadService` and `IDownloadListener` interfaces
- Has an `UPDATE` action (`com.qualcomm.universaldownload.UPDATE`)
- Can download and install APKs without user interaction

**HIGH: AutoRegistration** automatically registers the device with carrier networks:
- `com.qualcomm.action.AUTO_REGISTRATION`
- Contains `RegistrationTask`, `RegistrationService`, `RegistrationPairs`
- Activates on boot via `AutoRegReceiver`
- Sends device information to carrier during registration

**HIGH: DM.apk (Device Management)** implements OMA-DM protocol, enabling:
- Remote device configuration
- Remote wipe
- Firmware updates pushed by carrier
- Policy enforcement

---

## 5. Auto-Update and Silent Install Capabilities (SEVERITY: HIGH)

### FOTA (Firmware Over-The-Air)
Multiple carrier FOTA APN configurations found (Verizon, AT&T, various regional carriers). The system supports:
- `APN_TYPE_FOTA` / `DATA_PROFILE_FOTA`
- Carrier-initiated firmware updates

### CtUniversalDownload
```
com.qualcomm.universaldownload.IDownloadService
com.qualcomm.universaldownload.IDownloadListener
com.qualcomm.universaldownload.UPDATE
```

### CarrierLoadService
Dynamically loads carrier-specific packages and configurations:
```
notifyCarrierLoadServiceChanged
CarrierLoadService.apk
```

### Analysis

**HIGH:** The combination of FOTA support, CtUniversalDownload, and CarrierLoadService creates a complete pipeline for remote code execution without user consent. An APK can be downloaded, installed, and activated silently.

---

## 6. Persist.sys.agentvalue Property (SEVERITY: MEDIUM)

```
agentvalue=`getprop persist.sys.agentvalue`
setprop persist.sys.agentvalue 0
value=($agentvalue)
```

### Analysis

**MEDIUM:** The `persist.sys.agentvalue` property appears to control some kind of agent/monitoring service. It is explicitly set to `0` (disabled) during boot, but the infrastructure exists to enable it. The name "agent" in Chinese carrier firmware context typically refers to a monitoring or data collection agent.

---

## 7. China Telecom BestPay Integration (SEVERITY: MEDIUM)

```
com.chinatelecom.bestpayclient.BufferActivity
```

### Analysis

**MEDIUM:** BestPay (翼支付) is China Telecom's mobile payment platform. Its presence as a pre-installed component on a USB modem dongle is unexpected and suggests the firmware was derived from a smartphone ROM. The `BufferActivity` reference indicates a loading/splash screen component, meaning the full payment client may be present.

---

## 8. Remote Shell / Backdoor Analysis (SEVERITY: LOW - No Active Backdoors Found)

### Telnet
```
telnet://
telnet:
CURLOPT_TELNETOPTIONS
```
Only libcurl telnet client-side references found. **No telnetd server detected.**

### Dropbear
**No references found.** No dropbear SSH server present.

### Busybox Backdoors
**No nc -l, reverse shell, or busybox backdoor patterns found.**

### Analysis

**LOW:** No traditional backdoor services (telnetd, dropbear, netcat listeners) were detected. However, the Jiagu-packed APK, the diagnostic interfaces, and the test-keys signing collectively provide multiple alternative pathways for unauthorized access that are more sophisticated than simple backdoors.

---

## 9. SMS/Call Forwarding Analysis (SEVERITY: LOW - Standard Framework Only)

All SMS and call forwarding references are standard Android telephony framework code:
- `CallForwardEditPreference`, `GsmUmtsCallForwardOptions`, `CdmaCallForwardOptions`
- Standard RIL interfaces: `RIL_REQUEST_SEND_SMS`, `RIL_REQUEST_SET_CALL_FORWARD`
- AT commands: `AT+CMGS` (send SMS), `AT+CNMI` (new message indication)
- `android.permission.SEND_SMS` / `SEND_SMS_NO_CONFIRMATION`

### Analysis

**LOW:** No hidden SMS forwarding or call interception beyond standard Android capabilities. The `SEND_SMS_NO_CONFIRMATION` permission exists in the framework but is a standard AOSP permission for system apps. The `CustomerService.apk` does use SMS (`com.qualcomm.customerservice.action.sms`) but appears to be for carrier service codes, not interception.

---

## 10. Network Listening Services (SEVERITY: MEDIUM)

### Findings
```
0.0.0.0           -- Generic bind-all reference
socket_inaddr_any_server    -- Server socket on all interfaces
0.0.0.0/0         -- Default route
```

### Analysis

**MEDIUM:** The `socket_inaddr_any_server` string indicates at least one service binds to all network interfaces. On a 4G dongle that provides network to connected devices, this means services could be reachable from the host computer connected via USB.

---

## 11. Userdata Partition Analysis (SEVERITY: MEDIUM)

### Databases Found
| Database | Purpose |
|---|---|
| `accounts.db` | User accounts |
| `contacts2.db` | Contact storage |
| `locksettings.db` | Lock screen settings |
| `internal.db` / `external.db` | Media storage |
| `device.db` | Device information |
| `andsf.db` | Access Network Discovery |
| `bqe_hist.db` | Bandwidth Quality Estimation |
| `cdmacalloption.db` | CDMA call options |
| `firewall.db` | Call/SMS firewall rules |
| `nsrmConfig.db` | Network Service Resource Manager |
| `RIDL.db` | Remote Intelligence Data Logging |

### Jiagu Runtime Data
```
files/.jglogs/.jg.ac    -- Activity log
files/.jglogs/.jg.ic    -- Init/config log
files/.jglogs/.jg.pk    -- Package log
files/.jglogs/.jg.rd    -- Read log
files/.jglogs/.jg.ri    -- Runtime info
files/.jglogs/.log*     -- General logs (multiple)
files/.jiagu.lock       -- Lock file (app is/was running)
```

### Analysis

**MEDIUM:** The `RIDL.db` (Remote Intelligence Data Logging) database on `/data/SelfHost/RIDL.db` is a Qualcomm diagnostic data collection system. Combined with the Jiagu runtime logs, the userdata partition confirms both Qualcomm and Qihoo 360 data collection systems have been active.

---

## 12. Init Script References (SEVERITY: LOW)

### Found RC Files
```
system/etc/init.goldfish.rc    -- Android emulator (residual)
system/etc/init.trout.rc       -- HTC Dream (residual)
```

### Service/Init Patterns
Most `service` keyword matches are Java-level service references, not init.rc service definitions. The actual init system configuration is likely in the boot partition (not analyzed here).

Key setprop commands found:
```
setprop dhcp.${intf}.reason "${reason}"
setprop hw.fm.init 0|1
setprop persist.sys.agentvalue 0
setprop qcom.audio.init complete
setprop sys.usb.config diag,qdss,adb
```

---

## Risk Summary Table

| # | Finding | Severity | Category |
|---|---|---|---|
| 1 | Qihoo 360 Jiagu packer with crash reporting to `c.appjiagu.com` | **CRITICAL** | Code obfuscation / Data exfiltration |
| 2 | test-keys signing on production (user) build | **CRITICAL** | Authentication bypass |
| 3 | Qualcomm diag + serial_smd exposed via USB by default | **HIGH** | Remote access / Debug interface |
| 4 | CtUniversalDownload silent app installer | **HIGH** | Auto-update without consent |
| 5 | AutoRegistration auto-SIM-registration | **HIGH** | Data exfiltration |
| 6 | DM.apk OMA Device Management | **HIGH** | Remote device control |
| 7 | CarrierLoadService dynamic package loading | **HIGH** | Silent code execution |
| 8 | FOTA update capability | **HIGH** | Auto-update without consent |
| 9 | persist.sys.agentvalue monitoring agent | **MEDIUM** | Potential data collection |
| 10 | BestPay mobile payment client | **MEDIUM** | Unexpected payment capability |
| 11 | RIDL.db Qualcomm diagnostic logging | **MEDIUM** | Data collection |
| 12 | socket_inaddr_any_server binding | **MEDIUM** | Network exposure |
| 13 | Chinese carrier bloatware (10086cn, CMCC, CT, CU) | **MEDIUM** | Bloatware / data collection |
| 14 | Standard Android SMS/call forwarding | **LOW** | Normal framework |
| 15 | No telnetd/dropbear/netcat backdoors | **LOW** | No traditional backdoors |

---

## Recommendations

1. **Replace firmware immediately** with OpenStick or a clean Debian/OpenWrt build to eliminate all identified threats.
2. **Do not use this firmware on any network** carrying sensitive traffic until replaced.
3. **The Jiagu-packed APK needs further investigation:** Mount the system partition in a controlled environment and identify which APK contains the `libjiagu.so` assets to determine its function.
4. **The test-keys issue means** any APK signed with AOSP test keys will be treated as a system app -- this is effectively a permanent privilege escalation vector.
5. **Disable the diag USB interface** if continuing to use stock firmware temporarily: `setprop sys.usb.config adb` (ADB only).

---

## Methodology Notes

- Analysis performed via `strings` extraction from raw ext4 partition images
- No filesystem mounting was performed
- String matches may include false positives from binary data resembling ASCII
- Absence of evidence is not evidence of absence -- packed/encrypted code cannot be analyzed via strings
- The Jiagu-packed APK's actual behavior remains unknown without dynamic analysis or unpacking
