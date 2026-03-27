# Firmware Security Analysis: System Properties and WiFi Configuration

**Device:** Juzhen UFI 4G Dongle (MSM8916 / Qualcomm Snapdragon 410)
**Firmware Build:** Android 4.4.4 (KTU84P), built 2025-11-04
**Analysis Date:** 2026-03-27
**Source Files:**
- `backup/getprop.txt` -- Android system properties dump
- `backup/hostapd.conf` -- WiFi access point configuration

---

## CRITICAL FINDINGS

### C1. Hardcoded WiFi Password in System Properties [Critical]

The WiFi passphrase is stored as a persistent system property in plaintext:

```
[persist.sys.juzhen.ssid.pd]: [1234567890]
```

This same value appears in `hostapd.conf` as the WPA passphrase:

```
wpa_passphrase=1234567890
```

**Impact:** The default WiFi password is a trivially guessable 10-digit sequential number. Every device using this firmware likely ships with identical or predictable credentials. Any nearby attacker can connect to the hotspot and intercept all traffic routed through the dongle.

---

### C2. Hardcoded Web Admin Password in System Properties [Critical]

```
[persist.sys.juzhen.web.pd]: [admin]
```

The web management interface password is `admin`. Combined with the weak WiFi password, any attacker who joins the network has full administrative control of the device.

**Impact:** Complete device takeover. An attacker can modify APN settings, intercept mobile data, change DNS servers, or flash new firmware.

---

### C3. Hardcoded SIM PIN/Password in System Properties [Critical]

```
[persist.sys.juzhen.sim.pd]: [UFIadmin88888]
```

A SIM-related credential is stored in plaintext as a persistent system property. This appears to be an administrative password for SIM management functions.

**Impact:** If this is used to authenticate SIM operations or unlock SIM management features, an attacker with ADB access or property read access gains control over the cellular modem and SIM card.

---

## HIGH SEVERITY FINDINGS

### H1. SELinux Disabled at Boot [High]

```
[ro.boot.selinux]: [disable]
```

SELinux, the mandatory access control framework, is explicitly disabled at the kernel boot level. This removes a critical security boundary that limits process privileges and contains exploitation of vulnerabilities.

**Impact:** Any vulnerability in any running service can be leveraged for full root-level compromise without SELinux containment.

---

### H2. ADB Enabled with Diagnostic Interfaces Exposed [High]

```
[persist.sys.usb.config]: [diag,serial_smd,rmnet_bam,adb]
[ro.sys.usb.default.config]: [diag,serial_smd,rmnet_bam,adb]
[sys.usb.config]: [rndis,none,adb]
[sys.usb.state]: [rndis,adb]
[init.svc.adbd]: [running]
```

ADB (Android Debug Bridge) is running and enabled by default. Additionally, Qualcomm diagnostic (`diag`) and serial debug (`serial_smd`) interfaces are exposed over USB. The `diag` interface provides direct access to the Qualcomm DIAG protocol, which can be used to read/write modem NV items, extract IMEI, and execute AT commands.

**Impact:** Anyone with physical USB access can obtain a root shell (ADB) and access low-level modem diagnostics. The DIAG interface in particular allows modem memory reads, NV item extraction, and baseband manipulation.

---

### H3. Firmware Signed with Test Keys [High]

```
[ro.build.tags]: [test-keys]
[ro.build.display.id]: [KTU84P test-keys]
[ro.build.fingerprint]: [qcom/msm8916_32_512/msm8916_32_512:4.4.4/KTU84P/eng.richal.20251104:user/test-keys]
```

The firmware is signed with Android test keys rather than proper release keys. Test keys are publicly known (they are part of the AOSP source tree).

**Impact:** Anyone can build and sign APKs or OTA updates that the system will accept as legitimate. This enables trivial installation of malicious system applications or firmware modifications that bypass signature verification.

---

### H4. Ancient Android Version with Known Vulnerabilities [High]

```
[ro.build.version.release]: [4.4.4]
[ro.build.version.sdk]: [19]
```

Android 4.4.4 (API 19) reached end of life years ago. It lacks hundreds of security patches including fixes for critical vulnerabilities such as Stagefright (CVE-2015-1538 et al.), Dirty COW (CVE-2016-5195), and many others.

**Impact:** The device is vulnerable to a large number of publicly known exploits with available proof-of-concept code.

---

### H5. WiFi Authentication Allows Shared Key (WEP-compatible) [High]

```
auth_algs=3
```

The `auth_algs=3` setting enables both Open System Authentication (bit 0) and Shared Key Authentication (bit 1). Shared Key Authentication is a legacy WEP mechanism that is cryptographically broken and actually makes attacks easier than open authentication.

**Impact:** While WPA2 is enabled as the primary security mechanism, the auth_algs setting creates an unnecessary legacy attack surface. A downgrade or confusion attack could exploit this.

---

## MEDIUM SEVERITY FINDINGS

### M1. Unencrypted Filesystem [Medium]

```
[ro.crypto.state]: [unencrypted]
```

The device storage is not encrypted. All data on the eMMC, including system properties with hardcoded passwords, cached data, and any user data, is stored in plaintext.

**Impact:** Physical extraction of the eMMC (or EDL-mode access, which this device supports) exposes all stored data including credentials.

---

### M2. Suspicious Service in Restart Loop [Medium]

```
[init.svc.syssn]: [restarting]
```

A service called `syssn` is in a `restarting` state, indicating it is crashing and being restarted by init. This is an unusual service name not part of standard AOSP. The name suggests it may be Juzhen's system serial number or device registration service.

**Impact:** A continuously crashing service may be attempting to phone home or register the device. The restart loop could also indicate a stability issue or a missing server endpoint. Further investigation of the `syssn` init script is warranted.

---

### M3. Management Frame Protection (802.11w) Disabled [Medium]

```
#ieee80211w=0
```

Management frame protection is not enabled (commented out, defaults to disabled). This leaves the WiFi network vulnerable to deauthentication attacks, which can be used to force clients to disconnect and rejoin (facilitating WPA handshake capture).

**Impact:** An attacker can trivially deauthenticate connected clients using tools like `aireplay-ng`, then capture the WPA2 handshake during reconnection and attempt offline password cracking (which is trivial given the weak default password).

---

### M4. Client Isolation Disabled [Medium]

```
#ap_isolate=1
```

Client isolation is commented out (disabled by default). This means any device connected to the WiFi hotspot can communicate directly with other connected devices at the Layer 2 level.

**Impact:** If multiple devices are connected, a compromised or malicious client can perform ARP spoofing, MITM attacks, or direct attacks against other clients on the same network.

---

### M5. IMEI/Serial Number Exposed in System Properties [Medium]

```
[persist.sys.juzhen.sncode]: [35158010517311]
[ro.boot.serialno]: [e80fd820]
[ro.serialno]: [e80fd820]
[persist.sys.iccid]: [89123400000000000001]
```

The device IMEI (or a serial/IMEI-like number), hardware serial number, and ICCID are exposed as system properties. The `sncode` value (`35158010517311`) follows IMEI format (14 digits before the check digit).

**Impact:** IMEI cloning is a concern if an attacker can read these values. The ICCID appears to be a placeholder/test value, but on a device with an active SIM, this would be the real ICCID.

---

## LOW SEVERITY FINDINGS

### L1. Data Roaming Enabled by Default [Low]

```
[ro.com.android.dataroaming]: [true]
```

Data roaming is enabled by default, which could result in unexpected charges if the device is used with an international SIM card.

---

### L2. Bluetooth Address Hardcoded in Properties [Low]

```
[persist.service.bdroid.bdaddr]: [22:22:0b:e8:e6:92]
```

The Bluetooth address is stored as a persistent property. While not a direct security risk, it is a stable device identifier useful for tracking.

---

### L3. Lockscreen Disabled by Default [Low]

```
[ro.lockscreen.disable.default]: [true]
[keyguard.no_require_sim]: [true]
```

The device lockscreen is disabled and no SIM PIN is required. This is expected for a headless dongle but eliminates a layer of physical access protection.

---

### L4. GTK Rekey Interval is 24 Hours [Low]

```
wpa_group_rekey=86400
```

The group temporal key (used for broadcast/multicast) is rekeyed only once every 24 hours (86400 seconds). The recommended interval is 3600 seconds or less.

**Impact:** A longer rekey window slightly increases the exposure time if a GTK is compromised.

---

## INFORMATIONAL FINDINGS

### I1. Juzhen Vendor Properties Summary [Info]

The following Juzhen-specific properties reveal the device configuration model:

| Property | Value | Meaning |
|---|---|---|
| `persist.sys.juzhen.type` | `ufi` | Device type: USB WiFi (UFI) dongle |
| `persist.sys.juzhen.ssid.prefix` | `4G-UFI-` | Default SSID prefix |
| `persist.sys.juzhen.ssid.suffix` | `2` | Suffix mode (last N digits of serial) |
| `persist.sys.juzhen.ssid.pd` | `1234567890` | Default WiFi password |
| `persist.sys.juzhen.web.pd` | `admin` | Default web admin password |
| `persist.sys.juzhen.sim.pd` | `UFIadmin88888` | SIM management password |
| `persist.sys.juzhen.sn` | `1` | Serial number index |
| `persist.sys.juzhen.sncode` | `35158010517311` | Device serial/IMEI code |

The SSID is constructed as `{prefix}{last N digits of sncode}` = `4G-UFI-3112` (confirmed by hostapd.conf `ssid=4G-UFI-3112`). The suffix mode `2` means the last 4 digits of the sncode are used.

---

### I2. Build Identity Information [Info]

```
[ro.build.user]: [richal]
[ro.build.host]: [server]
[ro.build.date]: [2025-11-04 03:35:39 CST]
[ro.product.brand]: [UFI]
[ro.product.manufacturer]: [unknown]
```

The firmware was built by user `richal` on a machine named `server`. The manufacturer is set to `unknown`, suggesting a white-label/ODM product. The timezone is `Asia/Shanghai`, consistent with a Chinese manufacturer.

---

### I3. WiFi Configuration Summary [Info]

| Setting | Value | Notes |
|---|---|---|
| Interface | `wlan0` | Standard |
| Driver | `nl80211` | Standard Linux wireless driver |
| SSID | `4G-UFI-3112` | Broadcast, not hidden |
| Hidden SSID | No (`ignore_broadcast_ssid=0`) | SSID is visible |
| Mode | 802.11g/n | 2.4 GHz only |
| Channel | 6 | Fixed channel |
| WPA version | WPA2 only (`wpa=2`) | Good: WPA1 disabled |
| Cipher | CCMP/AES (`rsn_pairwise=CCMP`) | Good: TKIP not used |
| WPS state | Disabled (`#wps_state=2` commented out) | Good |
| AP Setup Locked | Yes (`ap_setup_locked=1`) | Good: prevents WPS registration |
| WMM | Enabled | Standard |
| IEEE 802.11n | Enabled | Standard |
| Max stations | 255 | Reasonable |
| MAC filtering | Accept all (`macaddr_acl=0`) | No MAC filtering |
| EAP server | Enabled (`eap_server=1`) | Unusual for a simple PSK AP |

---

### I4. Qualcomm Location Service [Info]

```
[persist.gps.qc_nlp_in_use]: [1]
[persist.loc.nlp_name]: [com.qualcomm.services.location]
[ro.gps.agps_provider]: [1]
```

Qualcomm's location services are enabled, including Assisted GPS. For a USB dongle, GPS/location functionality is unexpected and may be used for regulatory compliance or carrier requirements, but it also represents an unnecessary attack surface.

---

### I5. Running Services of Note [Info]

Notable services running on the device:

| Service | Status | Notes |
|---|---|---|
| `adbd` | running | ADB debug daemon |
| `qseecomd` | running | Qualcomm Secure Execution Environment |
| `qmuxd` | running | Qualcomm multiplexer daemon |
| `qcamerasvr` | running | Camera service (no camera on this device -- unnecessary) |
| `loc_launcher` | running | Location service launcher |
| `wcnss-service` | running | WiFi/BT/FM combo chip service |
| `syssn` | restarting | Unknown Juzhen service (crashing) |
| `carrier_switcher` | stopped | Carrier profile switching |
| `copy_apps` | running | App copying service |
| `ppd` | running | Post-processing daemon |

Several services (camera, location, post-processing) are unnecessary for a headless 4G dongle and increase the attack surface.

---

## SUMMARY

| Severity | Count | Key Issues |
|---|---|---|
| Critical | 3 | Hardcoded default passwords (WiFi, web admin, SIM management) |
| High | 5 | SELinux disabled, ADB+DIAG exposed, test-keys signing, EOL Android, weak auth_algs |
| Medium | 5 | No encryption, crashing service, no MFP, no client isolation, exposed IMEI |
| Low | 4 | Data roaming, BT address exposed, no lockscreen, slow GTK rekey |
| Info | 5 | Vendor property mapping, build identity, WiFi config summary, location services, unnecessary services |

**Overall Assessment:** This firmware has severe security deficiencies. The combination of hardcoded trivial passwords, disabled SELinux, test-key signing, exposed debug interfaces, and an ancient unpatched Android version means the device offers effectively no security against either network-based or physical attackers. Any device running this firmware on an open network should be considered fully compromised.

**Recommended Next Steps:**
1. Analyze the `syssn` service binary and init scripts for phone-home behavior
2. Examine the web management interface for additional vulnerabilities
3. Check for any OTA update mechanism and whether it validates signatures
4. Inspect `/system/etc/whitelist_appops.xml` referenced by `persist.sys.whitelist`
5. Extract and analyze the `copy_apps` service to determine what apps are being installed
