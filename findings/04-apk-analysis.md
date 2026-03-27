# APK Analysis - UFI 4G Dongle System Partition

**Date:** 2026-03-27
**Source:** `/home/user/git/USB-Dongle-OpenStick/backup/partitions/system.bin` (800MB ext4)
**Method:** debugfs extraction (no root required), jadx decompilation, strings analysis

---

## 1. System Overview

**Build Properties (from `/build.prop`):**
- Platform: Qualcomm MSM8916 (ARM 32-bit, 512MB RAM)
- Android: 4.4.4 (KitKat), SDK 19
- Build user: `richal` on host `server`
- Build date: 2025-11-04 (Chinese locale timestamp)
- Product: UFI branded (`ro.product.model=UFI`, `ro.product.brand=UFI`)
- **Signed with test-keys** (not production keys)
- **SELinux explicitly disabled:** `ro.boot.selinux=disable`

---

## 2. APKs Extracted

### System Apps (`/app/` - 32 APKs)
| APK | Size | Purpose |
|-----|------|---------|
| LatinIME.apk | 12.7 MB | Keyboard |
| Camera2.apk | 4.96 MB | Camera |
| Bluetooth.apk | 1.59 MB | Bluetooth stack |
| ObjectCloneRemove.apk | 944 KB | Clone removal |
| DocumentsUI.apk | 419 KB | File manager |
| RIDLClient.apk | 203 KB | **Qualcomm telemetry** |
| DM.apk | 161 KB | **OMA Device Management** |
| DataMonitor.apk | 55 KB | Data monitoring |
| CarrierConfigure.apk | 57 KB | Carrier config |
| NetworkSetting.apk | 29 KB | Network settings |
| ims.apk | 139 KB | IMS service |
| + 21 more standard Android system apps | | |

### Privileged Apps (`/priv-app/` - 16 APKs)
| APK | Size | Purpose |
|-----|------|---------|
| **ufilauncherzx.apk** | **8.41 MB** | **Main UFI management app (JIAGU PACKED)** |
| Settings.apk | 4.81 MB | System settings |
| SystemUI.apk | 2.81 MB | System UI |
| Dialer.apk | 2.64 MB | Phone dialer |
| Contacts.apk | 1.98 MB | Contacts |
| Keyguard.apk | 1.51 MB | Lock screen |
| TeleService.apk | 1.04 MB | Telephony service |
| xtra_t_app.apk | 29 KB | XTRA GPS assistance |
| + 8 more standard Android priv-apps | | |

### China Mobile Carrier Apps (`/vendor/ChinaMobile/system/app/` - 15 APKs)
| APK | Size | Purpose |
|-----|------|---------|
| Backup.apk | 1.21 MB | Backup service |
| AreaSearch.apk | 885 KB | Area search |
| CmccServer.apk | 86 KB | **CMCC service (SEND_SMS, CALL_PHONE)** |
| Firewall.apk | 54 KB | Firewall |
| NotePad2.apk | 57 KB | Notepad |
| DM.apk | 161 KB | Device management |
| + 9 more CMCC apps | | |

---

## 3. Main Management App: `ufilauncherzx.apk` (CRITICAL)

### 3.1 Package Identity

- **Package:** `com.youdo.server`
- **Developer:** YouDo Technology (优度科技)
- **Version:** 1.0 (versionCode 1), targets SDK 34 (Android 14)
- **Title in web UI:** `UFI-JZ_V3.0.0` (JZ = Juzhen)
- **APK signed:** 2025-09-18, Certificate CN=android, OU=android
- **Certificate SHA256:** `8B:33:9E:B9:B7:11:23:08:09:47:13:F2:0E:81:6B:78:4E:38:0C:41:4E:6B:D0:FC:A1:9D:E1:B4:E7:CA:43:77`

### 3.2 Jiagu (加固) Packing - Qihoo 360

**Severity: HIGH** - Code obfuscation hides actual app behavior

The APK is protected with **Qihoo 360 Jiagu** (libjiagu.so), a commercial Android app packer:
- Native libraries: `libjiagu.so` (ARM32), `libjiagu_a64.so` (ARM64), `libjiagu_x86.so`, `libjiagu_x64.so`
- Additional library: `libjgdtc.so` (DTC = Data Tracking Collection)
- Jiagu App ID (`.jgapp`): `26f899340c2abcb6`
- **Crash reporting enabled** (`Configuration.ENABLE_CRASH_REPORT = true`)
- **Performance tracking enabled** (`Configuration.ENABLE_PT = true`)

**Jiagu crash data is sent to:** `http://c.appjiagu.com/apk/cr.html` (Qihoo 360 servers)

The jiagu packer:
1. Stores the real DEX encrypted inside the native library (`JIAGU_ENCRYPTED_DEX_NAME`)
2. At runtime, decrypts and loads the real application code via `StubApp`
3. Collects device data: `ANDROID_ID`, `BRAND`, `MODEL`, `versionCode`, `versionName`, SIM operator, network type
4. Sends crash reports via HTTP POST to `c.appjiagu.com`
5. Uses XOR-16 string obfuscation for class/method names

**String obfuscation examples decoded (XOR ^ 0x10):**
- `q~tb\x7fyt>q``>QsdyfydiDxbuqt` -> `android.app.ActivityThread`
- `sebbu~dQsdyfydiDxbuqt` -> `currentActivityThread`
- `}Xyttu~Q`yGqb~y~wCx\x7fg~` -> `mHiddenApiWarningShown`
- `BuwycdubQsdyfydiSq||Rqs{c` -> `RegisterActivityCallBacks`

### 3.3 Permissions Requested (CRITICAL)

| Permission | Risk | Purpose |
|------------|------|---------|
| `INTERNET` | HIGH | Network access |
| `READ_PHONE_STATE` | HIGH | Read IMEI, phone number, SIM info |
| `READ_SMS` | **CRITICAL** | Read all SMS messages |
| `WRITE_SMS` | **CRITICAL** | Modify SMS messages |
| `SEND_SMS` | **CRITICAL** | Send SMS (potential premium SMS) |
| `READ_CONTACTS` | HIGH | Read contact list |
| `WRITE_CONTACTS` | HIGH | Modify contacts |
| `READ_CALL_LOG` | HIGH | Read call history |
| `WRITE_CALL_LOG` | HIGH | Modify call history |
| `ACCESS_FINE_LOCATION` | HIGH | Precise GPS location |
| `ACCESS_COARSE_LOCATION` | MEDIUM | Approximate location |
| `MODIFY_PHONE_STATE` | **CRITICAL** | Modify telephony state |
| `WRITE_APN_SETTINGS` | **CRITICAL** | Modify APN (redirect traffic) |
| `RECEIVE_BOOT_COMPLETED` | MEDIUM | Auto-start on boot |
| `WRITE_SETTINGS` | HIGH | Modify system settings |
| `WRITE_EXTERNAL_STORAGE` | MEDIUM | Write to SD card |
| `READ_EXTERNAL_STORAGE` | MEDIUM | Read SD card |
| `CHANGE_NETWORK_STATE` | MEDIUM | Change network config |
| `CHANGE_WIFI_STATE` | MEDIUM | Change WiFi config |
| `KILL_BACKGROUND_PROCESSES` | MEDIUM | Kill other apps |
| `WAKE_LOCK` | LOW | Prevent sleep |

**Total dangerous permissions: 14 out of 21**

### 3.4 Application Components

```xml
<!-- Main activity (HOME launcher replacement) -->
<activity android:name="com.youdo.ufi.ui.MainActivity">
    <intent-filter>
        <category android:name="android.intent.category.HOME"/>
    </intent-filter>
</activity>

<!-- Background services -->
<service android:name="com.youdo.ufi.ui.UfiServer" android:exported="true"/>
<service android:name="com.youdo.ufi.core.HttpService" android:exported="true"/>

<!-- System info receiver -->
<receiver android:name="com.youdo.ufi.core.SystemInfoReceiver" android:exported="true">
    <!-- Listens for: connected count, signal, data limits, WiFi state, LED, SIM slot -->
</receiver>
```

**Note:** Both services are `exported="true"`, meaning any app on the device can interact with them without permission.

### 3.5 Embedded Web Management Interface

The APK contains a complete **Vue.js + Element UI** web management interface served via the built-in HTTP server:

**Web UI title:** `UFI-JZ_V3.0.0`

#### Hardcoded External Server (CRITICAL)
```javascript
m["default"].prototype.$imgPath = "http://154.48.236.92:7001"
m["default"].prototype.$httpUrl = window.location.host + "/api"
```

**IP `154.48.236.92:7001`** is a hardcoded external server used for image/resource loading. This IP appears to be a **YouDo Technology cloud server**.

#### API Endpoints Discovered (103 endpoints)

**Authentication:**
- `loginInfo/loginWithPwd` - Password login (DES encrypted)
- `loginInfo/loginWithPwd2PC` - PC login
- `loginInfo/loginWithMsgCode` - SMS code login
- `loginInfo/sendMsgCode` - Send SMS verification
- `loginInfo/registerWithTel` - Phone registration
- `loginInfo/verifyLoginPwd` - Verify password
- `loginInfo/changeLoginPwd` / `updateLoginPwd` - Change password
- `loginInfo/loginOut` - Logout

**Device Management:**
- `system/setSystemImei` - **Set/change IMEI** (CRITICAL - IMEI fraud)
- `system/changeDeviceStatus` - Change device status
- `system/getSettings` / `putSettings` - Get/set system settings
- `system/limitDeviceSpeed` - Limit device speed
- `system/getBattery` - Battery status
- `system/getOperator` / `setOperator` - Get/set operator
- `system/getDeviceType` - Device type
- `system/editDataUsage` / `getDataUsage` - Data usage
- `system/getConfigForGetSwitchPwd` - Get switch password config
- `system/getBlackList` - Get blacklist
- `system/getSystemLang` - System language

**WiFi Management:**
- `wifi/getWifiConfig` / `setWifiConfig` - WiFi configuration
- `wifi/getWifiInfo` / `updateWifiInfo` - WiFi info
- `wifi/getNetSpeed` - Network speed
- `wifi/getLimitAllAddr` / `setLimitAllAddr` - Limit addresses
- `system/setWifiIp` / `getWifiIp` - WiFi IP address

**APN Management:**
- `system/getCurrentApn` - Get current APN
- `system/addApn` - **Add custom APN** (can redirect all data traffic)

**User/Agent Management (Cloud Platform):**
- `userInfo/getUserInfo` / `editUserInfo` / `delUserInfo`
- `userInfo/batchAddUserInfo` - Batch add users
- `userInfo/changeUserRole` - Change role
- `userInfo/certificationrWithPage` / `dealCertification` - Certification system
- `agentInfo/createAgentInfo` / `agentInfoWithPage` - Agent management
- `userInfo/listenCahnnelList` - Listen channel list
- `userInfo/userAllChannel` - All channels

**GPS Tracking:**
- `gpsRecord/gpsRecordWithPage` - **GPS location records with pagination**

**Intercom/Talkback:**
- Intercom server configuration
- Channel management
- Contact group management

**Push Notifications:**
- `notice/sendNotify` - Send notifications to devices
- `notice/getNotifyPwd` - Get notification password
- `notice/noticeCreate` / `noticeDel` - Create/delete notices

**OTA Updates:**
- `formalPackage/createUpdateInfo` - Create update
- `formalPackage/selectUpdateFile2Client` - Select update file
- `formalPackage/versionInfoWithPage` - Version info
- `version/versionCreate` - Create version
- `upload/uploadSingleFile` / `uploadMultipartFile` - File upload

**Industry/Group Management:**
- `industry/editIndustryInfo` / `moveIndustryInfo`
- `contactGroup/channelInfo` / `editGroupInfo` / `removeGroup`

### 3.6 Encryption Implementation (WEAK)

All API communication uses **DES encryption** (not AES/TLS):

```javascript
// Key generation: Random 6-char key derived from Snowflake ID
t.encryptDES = function(e) {
    var t = l();  // createIKey() - generates random key
    return {
        data: o(e, t.secretkey),      // DES encrypt
        pulickKey: t.pulickKey        // Key hint sent in cleartext
    }
};

// createIKey: Generates a Snowflake ID, picks 6 random positions
var w = function() {
    var r = v();  // getGuid16() - Snowflake ID as hex
    var o = [];
    while (o.length < 6) {
        var s = 16 * Math.random() | 0;
        if (-1 === o.indexOf(s)) o.push(s);
    }
    var c = "";
    o.forEach(function(e) { c += r[e] });
    return {
        code: 1,
        secretkey: c,                    // 6-char DES key
        pulickKey: r + "$" + o.join(",") // Full ID + positions (SENT IN CLEARTEXT!)
    }
};
```

**Security issues:**
1. **DES encryption is broken** - 56-bit keys, vulnerable to brute force
2. **Key derivation is trivially reversible** - The `pulickKey` contains the full Snowflake ID AND the character positions, allowing anyone intercepting traffic to reconstruct the secret key
3. **No TLS** - HTTP used for API communication (port 80)
4. **Hardcoded notification password:** `123456` (documented in UI: "initial password is 123456")

### 3.7 Service Switching / Backup URL

The web app includes a **service switching** mechanism with backup URL failover:
```javascript
serviceSwitching: {
    isOpen: false,
    strategies: function(){},
    backupUrl: ""
}
```
When enabled, if the primary server fails, traffic is redirected to `backupUrl`. This could be used for traffic hijacking.

---

## 4. Hardcoded Credentials (from build.prop)

**Severity: CRITICAL**

```properties
# Web management password
persist.sys.juzhen.web.pd=admin

# SIM management password
persist.sys.juzhen.sim.pd=UFIadmin88888

# WiFi default password
persist.sys.juzhen.ssid.pd=1234567890

# WiFi SSID format
persist.sys.juzhen.ssid.prefix=4G-UFI-
persist.sys.juzhen.ssid.suffix=2   # suffix type: 2=IMEI

# Device type
persist.sys.juzhen.type=ufi

# Default USB config exposes debug interfaces
persist.sys.usb.config=diag,serial_smd,rmnet_bam,adb
```

**All these credentials are identical across all devices of this model.**

---

## 5. DM.apk - OMA Device Management (HIGH RISK)

**Package:** `com.android.dm`

### Permissions
| Permission | Risk |
|------------|------|
| `RECEIVE_BOOT_COMPLETED` | Auto-start |
| `READ_PHONE_STATE` | Read IMEI, phone number |
| `SEND_SMS` | Send SMS messages |
| `RECEIVE_SMS` | Intercept incoming SMS |
| `RECEIVE_WAP_PUSH` | Receive WAP push |
| `RECEIVE_DM_REGISTER_SMS` | Receive DM registration SMS |
| `BROADCAST_SMS` | Broadcast SMS |
| `INTERNET` | Network access |
| `ACCESS_FINE_LOCATION` | GPS location |
| `WRITE_APN_SETTINGS` | Modify APN |
| `READ_HISTORY_BOOKMARKS` | Read browser history |
| `WRITE_HISTORY_BOOKMARKS` | Modify browser bookmarks |
| `CONNECTIVITY_INTERNAL` | Internal network control |
| `WRITE_SETTINGS` | Modify settings |

### Key Findings
- Listens for **OMA-DM WAP push messages** (`application/vnd.syncml.dm+wbxml`)
- Receives **data SMS on port 16998** for remote commands
- Has a **secret dialer code `*#*#3636#*#*`** to access debug menu
- Auto-starts on boot via `DmReceiver`
- Can modify APN settings and browser bookmarks
- Uses native JNI methods (`DMNativeMethod`) for OMA-DM protocol

**This is a full OMA Device Management client that allows remote over-the-air management of the device, including APN changes, settings modification, and potentially software installation.**

---

## 6. RIDLClient.apk - Qualcomm Telemetry (MEDIUM RISK)

**Package:** `com.qualcomm.RIDL` (v4.3.12)

### Data Collection
- Collects device data as JSON files
- Zips and uploads to **`https://statmando.qualcomm.com/RIDL.php`**
- Uploads every **15 minutes** (900,000ms sleep cycle)
- Also uploads when connectivity changes

### Hostname Verification Bypass
```java
httpCon.setHostnameVerifier(new HostnameVerifier() {
    public boolean verify(String hostname, SSLSession session) {
        return "statmando.qualcomm.com".equalsIgnoreCase(hostname);
    }
});
```
This bypasses proper SSL certificate chain validation - only checks hostname, not the certificate itself. Vulnerable to MITM with a valid cert for that hostname.

### Permissions
- `INTERNET`, `READ_LOGS`, `ACCESS_FINE_LOCATION`
- `PROCESS_OUTGOING_CALLS` - Monitor outgoing calls
- `BLUETOOTH` / `BLUETOOTH_ADMIN` - Bluetooth access
- `REBOOT` - Can reboot device
- `MANAGE_ACCOUNTS` / `AUTHENTICATE_ACCOUNTS` - Account management

---

## 7. CmccServer.apk - China Mobile Service (MEDIUM RISK)

**Package:** `com.android.cmcc`

### Permissions
- `CALL_PHONE` - Make phone calls without user interaction
- `SEND_SMS` - Send SMS messages

This carrier app can make calls and send SMS without user consent.

---

## 8. Embedded ADB Key (LOW-MEDIUM RISK)

**File:** `/etc/adbkey.pub`

A pre-installed ADB public key is embedded in the system partition, meaning whoever holds the corresponding private key can connect to the device via ADB without authorization. Combined with the default USB config (`diag,serial_smd,rmnet_bam,adb`), the device is permanently ADB-accessible.

Key fingerprint owner: `unknown@unknown`

---

## 9. Overall Risk Assessment

### CRITICAL Findings
| # | Finding | Impact |
|---|---------|--------|
| 1 | **SELinux disabled** | No mandatory access control, any exploit gets full access |
| 2 | **Test-keys signing** | Anyone can create system-signed APKs |
| 3 | **IMEI modification endpoint** (`setSystemImei`) | IMEI fraud, illegal in most jurisdictions |
| 4 | **SMS read/write/send permissions** on management app | SMS interception, premium SMS fraud |
| 5 | **Hardcoded identical passwords** across all devices | `admin`, `UFIadmin88888`, `1234567890` |
| 6 | **DES encryption with key sent in cleartext** | All API traffic trivially decryptable |
| 7 | **Jiagu packing hides actual app behavior** | Cannot verify what code actually runs |
| 8 | **Hardcoded external server** `154.48.236.92:7001` | Phones home to YouDo/Juzhen cloud |

### HIGH Findings
| # | Finding | Impact |
|---|---------|--------|
| 9 | OMA-DM client with SMS port listener | Remote device management via SMS |
| 10 | GPS tracking with paginated records API | Location history stored/accessible |
| 11 | APN modification capability | Traffic redirection |
| 12 | Qualcomm RIDL telemetry with SSL bypass | Data leaks to Qualcomm, MITM possible |
| 13 | Pre-installed ADB key with ADB always enabled | Unauthorized device access |
| 14 | Exported services without permissions | Any app can control HTTP/UFI services |
| 15 | Call log, contacts read/write access | Privacy violation |

### MEDIUM Findings
| # | Finding | Impact |
|---|---------|--------|
| 16 | Crash data sent to Qihoo 360 (`c.appjiagu.com`) | Device fingerprinting |
| 17 | CmccServer can make calls and send SMS | Carrier service abuse |
| 18 | Default WiFi password `1234567890` | Unauthorized network access |
| 19 | Notification system default password `123456` | Push notification abuse |
| 20 | `hostapd.conf` backup loop to SD card | WiFi config exposure |

---

## 10. Architecture Summary

```
UFI 4G Dongle (Qualcomm MSM8916, Android 4.4.4)
|
|-- ufilauncherzx.apk (com.youdo.server)
|   |-- Jiagu (Qihoo 360) packed native code
|   |-- Embedded HTTP server (port 80)
|   |-- Vue.js web management UI
|   |-- API endpoints (103 discovered)
|   |-- DES-encrypted communication
|   |-- Connects to 154.48.236.92:7001 (YouDo cloud)
|
|-- DM.apk (OMA Device Management)
|   |-- Remote management via WAP push / SMS port 16998
|   |-- Can modify APN, settings, bookmarks
|
|-- RIDLClient.apk (Qualcomm telemetry)
|   |-- Uploads JSON data to statmando.qualcomm.com
|   |-- Collects location, call, device data
|
|-- CmccServer.apk (China Mobile)
|   |-- Can make calls and send SMS
|
|-- System services
    |-- ADB always enabled with pre-installed key
    |-- SELinux disabled
    |-- Test-key signed (no code integrity)
```

---

## 11. Files and Paths

- Extracted APKs: `/home/user/git/USB-Dongle-Firmware-Analysis/extracted/apks/`
- Decompiled UFI launcher: `/home/user/git/USB-Dongle-Firmware-Analysis/extracted/decompiled_ufilauncherzx/`
- Decompiled CmccServer: `/home/user/git/USB-Dongle-Firmware-Analysis/extracted/decompiled_CmccServer/`
- Decompiled DM: `/home/user/git/USB-Dongle-Firmware-Analysis/extracted/decompiled_DM/`
- Decompiled RIDLClient: `/home/user/git/USB-Dongle-Firmware-Analysis/extracted/decompiled_RIDLClient/`
- Web UI assets: `/tmp/ufi_apk_extract/assets/` (extracted from APK)
- Build properties: extracted via `debugfs -R "cat /build.prop" system.bin`
