# UFI 4G Dongle System Partition: URLs, Credentials, and Phone-Home Analysis

**Date:** 2026-03-27
**Source:** `/home/user/git/USB-Dongle-OpenStick/backup/partitions/system.bin` (800 MB, ext4)
**Method:** `strings` extraction + pattern analysis (4,563,375 strings extracted)
**Device:** Juzhen UFI 4G Dongle (jz01-45-v33), Qualcomm MDM9607

---

## Table of Contents

1. [Critical Findings Summary](#critical-findings-summary)
2. [Hardcoded Credentials](#hardcoded-credentials)
3. [Phone-Home Endpoints](#phone-home-endpoints)
4. [Chinese Carrier Service URLs](#chinese-carrier-service-urls)
5. [Qualcomm Telemetry Endpoints](#qualcomm-telemetry-endpoints)
6. [GPS Assistance / Location Tracking](#gps-assistance--location-tracking)
7. [All URLs by Domain](#all-urls-by-domain)
8. [Chinese Domains (.cn)](#chinese-domains-cn)
9. [IP Addresses](#ip-addresses)
10. [Certificate Infrastructure](#certificate-infrastructure)
11. [Installed System Apps](#installed-system-apps)
12. [APK Packer / Obfuscation](#apk-packer--obfuscation)
13. [Vendor-Specific Strings (Juzhen)](#vendor-specific-strings-juzhen)
14. [Risk Assessment](#risk-assessment)

---

## Critical Findings Summary

| Finding | Severity | Description |
|---------|----------|-------------|
| Default credentials hardcoded | **CRITICAL** | SIM PIN, WiFi password, web admin password all hardcoded in system properties |
| zzhc.vnet.cn phone-home | **HIGH** | China Mobile auto-registration tracker that sends IMSI/IMEI to carrier servers |
| Qualcomm RIDL data collection | **HIGH** | Collects latitude, longitude, altitude, network type and uploads to Qualcomm servers |
| Qualcomm CNE traffic analysis | **HIGH** | Connectivity engine sends traffic data to cne.qualcomm.com |
| OMA DM remote management | **HIGH** | Device management service allows remote control via carrier push |
| AutoRegistration service | **MEDIUM** | Automatically registers device with carrier without user consent |
| libjiagu APK packer | **MEDIUM** | Chinese APK obfuscation tool embedded, obscures app behavior |
| Google geolocation API | **MEDIUM** | Sends WiFi/cell data to Google for geolocation |
| CrashLogger / StatManDo | **MEDIUM** | System-level crash and statistics collection daemons |
| MMS carrier configs with IPs | **LOW** | Hundreds of hardcoded MMS proxy IPs for global carriers |

---

## Hardcoded Credentials

### Juzhen Vendor Default Credentials (CRITICAL)

Found in system properties (`persist.sys.juzhen.*`):

```
persist.sys.juzhen.sim.pd=UFIadmin88888        # SIM management PIN
persist.sys.juzhen.ssid.pd=1234567890           # WiFi hotspot password
persist.sys.juzhen.ssid.prefix=4G-UFI-          # SSID naming prefix
persist.sys.juzhen.ssid.suffix=2                # SSID suffix mode
persist.sys.juzhen.web.pd=admin                 # Web admin panel password
persist.sys.juzhen.type=ufi                     # Device type identifier
persist.sys.juzhen.sn=1                         # Serial number base
# persist.sys.juzhen.wifi.password=12345678     # Commented-out alternative WiFi password
# persist.sys.juzhen.wifi.password=1234567890   # Commented-out alternative WiFi password
# persist.sys.juzhen.type=mifi                  # Commented-out MiFi mode
```

**Analysis:** Every UFI dongle ships with identical credentials. The web admin panel password is `admin`, the WiFi password is `1234567890`, and the SIM management PIN is `UFIadmin88888`. These are trivially guessable and identical across all devices of this model. Any attacker within WiFi range can access the management interface.

### Hostapd / WPA Default Credentials

```
#wpa_passphrase=qualcomm                        # Qualcomm default passphrase (commented)
#wpa_psk=0123456789abcdef...                    # Example PSK (commented)
ssid=QualcommSoftAP                             # Default Qualcomm SoftAP SSID
#acct_server_shared_secret=secret               # RADIUS accounting secret
#acct_server_shared_secret=secret2              # RADIUS accounting secret 2
#auth_server_shared_secret=secret               # RADIUS auth secret
#auth_server_shared_secret=secret2              # RADIUS auth secret 2
```

**Analysis:** These are default/example values in the hostapd configuration template. While commented out, they reveal the expected configuration pattern and default values that may be used if no override is provided.

### Qualcomm RIDL Credentials

```
https://riddle.qualcomm.com/RIDL/run?ID=2&PJMRCLASS=com.qualcomm.riddle.RiddleService&PASSWORD=
https://corpwsgwx-oauth.qualcomm.com/api/ridl/token
https://corpwsgwx-oauth.qualcomm.com/RIDL/run?PJMRCLASS=com.qualcomm.riddle.RiddleService&USERID=
```

**Analysis:** The RIDL (Remote Information and Data Logger) system uses URL-based authentication with PASSWORD and USERID parameters. The actual values appear to be populated at runtime, but the URL structure itself reveals the authentication mechanism. The OAuth token endpoint is also exposed.

---

## Phone-Home Endpoints

### 1. zzhc.vnet.cn - China Mobile Auto-Registration (CRITICAL)

```
http://zzhc.vnet.cn
```

**What it does:** This is the China Mobile "ZZHC" (auto-registration) system. When a China Mobile SIM is inserted, the device automatically contacts this server and sends:
- IMEI (device hardware identifier)
- IMSI (SIM subscriber identity)
- ICCID (SIM card serial number)
- Phone number

**Associated components:**
- `AutoRegistration.apk` / `AutoRegistration.odex`
- `com.qualcomm.qti.autoregistration.RegistrationService`
- `com.qualcomm.qti.autoregistration.RegistrationTask`
- `com.qualcomm.action.AUTO_REGISTRATION`

**Severity:** HIGH - Sends unique device and SIM identifiers to carrier without user interaction.

### 2. Qualcomm RIDL - Remote Information & Data Logger (HIGH)

```
https://riddle.qualcomm.com/RIDL/run?ID=2&PJMRCLASS=com.qualcomm.riddle.RiddleService&ACTION=registerDevice
https://riddle.qualcomm.com/RIDL/run?ID=2&PJMRCLASS=com.qualcomm.riddle.RiddleService&PASSWORD=
https://corpwsgwx-oauth.qualcomm.com/api/ridl/token
```

**Database schema reveals collected data:**
```sql
CREATE TABLE FileUpload(
    eventID TEXT,
    ruleID INTEGER,
    compID INTEGER,
    origFileName TEXT UNIQUE,
    origFileSize INTEGER,
    zippedFileName TEXT UNIQUE,
    networkType TEXT,
    latitude TEXT,        -- GPS latitude
    longitude TEXT,       -- GPS longitude
    altitude TEXT,        -- GPS altitude
    zipFileSize INTEGER,
    metaVersion TEXT,
    ridlVersion TEXT
);
```

**Associated components:**
- `RIDLClient.apk`
- `/system/vendor/RIDL/RIDL.db`
- `startRIDL.sh`
- Diag, QMI, AccumComponent, ServerComponent modules

**Severity:** HIGH - Collects GPS coordinates, network type, and diagnostic data, then uploads compressed files to Qualcomm servers.

### 3. Qualcomm CNE - Connectivity Engine (HIGH)

```
http://cne.qualcomm.com/cne/v1/bqe/traffic          # Bandwidth Quality Estimation traffic data
http://cne.qualcomm.com/cne/v1/icd                   # Internet Connectivity Detection
https://cne-post.qualcomm.com/cne/v1/bqe/findings    # Upload BQE findings
https://cne-ssl.qualcomm.com/cne/v1/icd/wifi-data    # Upload WiFi data
```

**Associated components:**
- `CNESettings.apk`
- XML configuration with ICD_HTTP_URI

**Severity:** HIGH - Continuously evaluates and reports on network connectivity quality, uploading WiFi data and traffic analysis to Qualcomm.

### 4. OMA Device Management - Carrier Remote Control (HIGH)

```
com.android.dm (DM.apk)
com.android.dm.SelfReg                  # Self-registration service
com.android.dm.NIA                      # Network Initiated Alert
/data/data/com.android.dm/files/serverid.dat
/data/data/com.android.dm/files/smsnotify.bin
```

**What it does:** OMA DM (Open Mobile Alliance Device Management) allows carriers to remotely:
- Push firmware updates
- Modify device configuration
- Install/remove applications
- Read device information

The SelfReg component auto-registers with carrier DM servers. NIA allows the carrier to initiate management sessions via SMS push.

**Associated URLs:**
```
http://dm.monternet.com      # China Mobile DM server
http://dm.189.cn/            # China Telecom DM server
```

**Severity:** HIGH - Carrier can remotely manage, configure, and update the device.

### 5. Google Geolocation API (MEDIUM)

```
https://www.googleapis.com/geolocation/v1/geolocate
```

**Severity:** MEDIUM - Sends WiFi access point data and cell tower info to Google for position determination.

---

## Chinese Carrier Service URLs

### China Mobile (10086 / CMCC)

```
http://10086.cn/m
http://10086.cn/m/
http://12580wap.10086.cn/?pid=PCM002942000
http://a.10086.cn
http://f.10086.cn
http://g.10086.cn
http://go.10086.cn/?coc=6GG2GGRq
http://go.10086.cn/rd/go/dh/
http://m.10086.cn
http://mail.10086.cn
http://mm.10086.cn/a/j/2743/
http://mmsc.monternet.com                           # MMS center
http://s.139.com                                     # 139 Mail (China Mobile email)
http://s.139.com/favicon.ico
http://s.139.com/search.do?q=
http://wap.cmread.com                                # China Mobile reading
http://wap.cmvideo.cn                                # China Mobile video
http://wap.monternet.com                             # Monternet (value-added services)
http://wap.monternet.com/?cp22=v22xwtq
http://wap.monternet.com/?cp22=v22ywtj
http://wap.monternet.com/?cp22=v22yyt
http://wap.monternet.com/?cp22=v22zxlc
http://wap.monternet.com/portal/wap/menu.do?menuid=200003
http://dm.monternet.com                              # Device management server
http://zzhc.vnet.cn                                  # Auto-registration tracker
http://streaming.vnet.mobi/                          # Streaming service
http://mms.hk.chinamobile.com/mms                    # HK China Mobile MMS
```

**Associated APKs:** `10086cn.apk`, `CmccCustom.apk`, `CmccServer.apk`, `CmccWifi.apk`, `Monternet.apk`

### China Telecom (189 / CT)

```
http://dm.189.cn/                                    # Device management server
http://liao.189.cn/                                  # Chat service
http://wap.ct10000.com                               # Customer service portal
http://wapgame.189.cn/                               # Gaming portal
http://wapmail.189.cn/                               # Webmail
http://wappim.189.cn/                                # Personal info management
http://wapread.189.cn/                               # Reading portal
http://www.189.cn/                                   # Main portal
http://3g.189store.com/                              # App store
http://manyou.ct10000.com                            # Service portal
```

**Associated APKs:** `CtBrowserQuick.apk`, `CtLauncherRes.apk`, `CtRoamingSettings.apk`, `CtUniversalDownload.apk`, `CtWallpaper.apk`

### China Unicom (WO)

```
http://iread.wo.com.cn                               # Reading service
http://www.wo.com.cn                                 # Main portal
```

**Associated APKs:** `CuBrowserQuick.apk`, `CuLauncherRes.apk`, `CuWallpaper.apk`, `WoRead.apk`

### CDMA Roaming

```
https://roam.radiosky.com.cn/cdma/ud/index           # CDMA roaming service
```

### Chinese Web Bookmarks (pre-loaded)

```
http://www.taobao.com/                               # Taobao (Alibaba e-commerce)
http://www.sohu.com/                                 # Sohu portal
http://www.renren.com/                               # RenRen (social network)
http://www.dangdang.com/                             # Dangdang (e-commerce)
http://www.kaixin001.com/                            # Kaixin (social network)
http://www.tianya.cn/                                # Tianya (forum)
```

---

## Qualcomm Telemetry Endpoints

### GPS Assistance (XTRA)

```
http://xtra1.gpsonextra.net/xtra2.bin               # GPS almanac data download
http://xtra2.gpsonextra.net/xtra2.bin
http://xtra3.gpsonextra.net/xtra2.bin
http://xtrapath1.izatcloud.net/xtra2.bin             # Qualcomm IZat cloud GPS data
http://xtrapath2.izatcloud.net/xtra2.bin
http://xtrapath3.izatcloud.net/xtra2.bin
```

### IZat Location Services

```
https://gtpa1.izatcloud.net                          # IZat cloud GNSS assistance
https://n3.indoor.izat-location.net/quipsds/LookupService    # Indoor positioning
https://r1.indoor.izat-location.net/ras/DeviceRegistration   # Device registration for indoor location
```

### Qualcomm Privacy Policy

```
http://xt.qsp.qualcomm.com/privacy/privacy_policy.html
http://xt.qsp.qualcomm.com/privacy/DE/privacy_policy.html
http://xt.qsp.qualcomm.com/privacy/ES/privacy_policy.html
http://xt.qsp.qualcomm.com/privacy/ZHCN/privacy_policy.html
```

### Qualcomm Internal/Debug

```
http://mpeg4sol28.qualcomm.com/External/httplive/hesnot.3gp-20110218-123656.m3u8
http://www.qualcomm.com/
```

---

## GPS Assistance / Location Tracking

The device has multiple location tracking mechanisms:

1. **Qualcomm XTRA:** Downloads GPS almanac data for faster GPS fix (benign, but contacts Qualcomm servers)
2. **Qualcomm IZat:** Cloud-based location platform including indoor positioning; registers device
3. **Qualcomm RIDL:** Collects and uploads GPS coordinates (latitude, longitude, altitude) along with diagnostic data
4. **Google Geolocation:** WiFi-based positioning through Google APIs
5. **Qualcomm CNE:** Collects WiFi network data

---

## All URLs by Domain

### Top domains by URL count

| Count | Domain | Category |
|-------|--------|----------|
| 37 | www.w3.org | Web standards (benign) |
| 35 | ns.adobe.com | XMP metadata namespace (benign) |
| 22 | xml.org | XML standards (benign) |
| 15 | xml.apache.org | Apache XML (benign) |
| 10 | crl.comodoca.com | Certificate revocation (benign) |
| 8 | www.verisign.com | Certificate infrastructure |
| 7 | exslt.org | XSLT extensions (benign) |
| 6 | www.startssl.com | Certificate authority |
| 6 | wap.monternet.com | China Mobile value-added services |
| 6 | mms.iot1.com | US rural carrier MMS |
| 6 | crl.comodo.net | Certificate revocation |
| 5 | crl.verisign.com | Certificate revocation |
| 5 | crl.usertrust.com | Certificate revocation |
| 5 | crl.geotrust.com | Certificate revocation |
| 5 | certificates.godaddy.com | Certificate authority |
| 4 | xt.qsp.qualcomm.com | Qualcomm privacy policy |
| 4 | java.sun.com | Java references (benign) |
| 4 | crl.globalsign.net | Certificate revocation |
| 4 | certificates.starfieldtech.com | Certificate authority |
| 3 | www.google.com | Google services |
| 3 | s.139.com | China Mobile 139 Mail |
| 2 | riddle.qualcomm.com | Qualcomm RIDL data logger |
| 2 | cne.qualcomm.com | Qualcomm Connectivity Engine |
| 2 | go.10086.cn | China Mobile |
| 2 | 10086.cn | China Mobile |
| 1 | zzhc.vnet.cn | China Mobile auto-registration tracker |
| 1 | dm.189.cn | China Telecom device management |
| 1 | dm.monternet.com | China Mobile device management |

### Google Services URLs

```
http://google.com
http://maps.google.com/maps?f=q&q=
http://www.google.com
http://www.google.com/oha/rdf/ua-profile-kila.xml
http://www.google.com/profiles/117279729717492545904
http://video.google.com/videofeed?type=docid&output=rss&sourceid=gtalk&docid=
http://video.google.com/videoplay?
http://picasaweb.google.com/
http://picasaweb.google.com/data/feed/api/user/
http://code.google.com/p/googletest/
http://code.google.com/p/v8/wiki/JavaScriptStackTraceApi
http://toolbarqueries.clients.google.com
http://ns.google.com/photos/1.0/panorama/
https://clients1.google.com/tbproxy/af/
https://sites.google.com/site/cibu/anjalioldlipi-font
https://www.googleapis.com/geolocation/v1/geolocate
http://ssl.gstatic.com
http://youtube.com (x2)
http://flickr.com (x2)
```

### MMS Center URLs (carrier configuration - 250+ entries)

The system contains APN/MMS configuration for hundreds of global carriers. These are used when the dongle handles MMS messages. Key MMS proxy domains include `mms.iot1.com`, `aliasredirect.net`, and hundreds of `mms.*` / `mmsc.*` carrier domains. This is standard for an Android telephony device.

---

## Chinese Domains (.cn)

### Significant .cn domains found (excluding ICU charset aliases):

| Domain | Purpose |
|--------|---------|
| zzhc.vnet.cn | China Mobile auto-registration/tracking |
| 10086.cn, a/f/g/m.10086.cn | China Mobile portals |
| 12580wap.10086.cn | China Mobile WAP service |
| mail.10086.cn | China Mobile email |
| mm.10086.cn | China Mobile mobile market |
| go.10086.cn | China Mobile redirect service |
| dm.189.cn | China Telecom device management |
| liao.189.cn | China Telecom chat |
| wap*.189.cn (multiple) | China Telecom WAP services |
| www.189.cn | China Telecom portal |
| iread.wo.com.cn | China Unicom reading |
| www.wo.com.cn | China Unicom portal |
| wap.cmvideo.cn | China Mobile video |
| wap.cmread.com | China Mobile reading (not .cn) |
| wap.118100.cn | China Telecom directory |
| wap.118114.cn | China Telecom info service |
| roam.radiosky.com.cn | CDMA roaming service |
| mmsc.myuni.com.cn | MMS center |
| mycdma.cn | CDMA service |
| www.tianya.cn | Tianya forum (bookmark) |

Note: 200+ `.cn` entries were ICU character encoding aliases (e.g., `ibm-1252_P100-2000.cn`) and Chinese province TLD assignments (e.g., `bj.cn`, `sh.cn`) -- these are locale/encoding data, not network endpoints.

---

## IP Addresses

### Carrier MMS Proxy IPs (extracted from APN configs)

Selected notable public IPs found in carrier configurations:

| IP | Context |
|----|---------|
| 218.206.176.97 | China Mobile MMS (mmsc.monternet.com proxy) |
| 218.200.243.234 | China Mobile |
| 221.176.0.11/12/55 | China Mobile MMSC |
| 8.8.8.8, 8.8.4.4 | Google DNS (default resolver) |
| 69.8.34.146 | US carrier MMS |
| 62.241.155.45 | European carrier MMS |
| 217.31.233.18 | European carrier MMS |
| 204.181.155.217 | US carrier MMS |
| 203.162.21.114 | Asian carrier MMS |
| 200.222.42.204 | South American carrier MMS |
| 74.125.224.0-255 | Google IP range |

### Private/Internal IPs

Hundreds of private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x) found, primarily:
- Carrier WAP/MMS gateway internal addresses
- Qualcomm test infrastructure addresses
- Standard Android tethering addresses (192.168.42.x, 192.168.43.x)
- Development/test addresses

### Default Gateway/Tethering IPs

```
192.168.42.129    # USB tethering default
192.168.42.2      # USB tethering client
192.168.42.254    # USB tethering range end
192.168.44-49.*   # WiFi tethering ranges
192.168.1.1       # Default gateway
192.168.0.1       # Default gateway
```

---

## Certificate Infrastructure

### Embedded CA Certificates

The system partition contains a standard Android CA certificate bundle with certificates from:
- Comodo / COMODO CA
- VeriSign
- GeoTrust
- Thawte
- GlobalSign
- DigiCert
- Entrust
- StartCom / StartSSL
- GoDaddy / Starfield
- USERTrust
- D-Trust
- SwissSign
- QuoVadis
- Camerfirma
- Microsoft (PKI infrastructure)

### Certificate Paths

```
/system/etc/security/cacerts/           # Standard Android CA store
assets/ca.crt                           # Custom CA cert embedded in APK
assets/tomcatrootv3.crt                 # Tomcat root CA (in APK)
cacert_location.pem                     # Location service CA cert
#ca_cert=/etc/hostapd.ca.pem            # Hostapd CA cert path
/.alljoyn_keystore/                     # AllJoyn IoT keystore
```

**Analysis:** The `assets/ca.crt` and `assets/tomcatrootv3.crt` embedded in an APK are noteworthy -- they may be custom CA certificates used for TLS interception or private server communication.

---

## Installed System Apps

### Privacy/Telemetry Relevant Apps

| APK | Location | Purpose |
|-----|----------|---------|
| `AutoRegistration.apk` | system | Auto-registers device with carrier (zzhc.vnet.cn) |
| `CrashLogger.apk` | system/app | Collects crash data and uploads |
| `RIDLClient.apk` | system | Qualcomm diagnostic data collection and upload |
| `StatManDo.apk` | system/app | Statistics/usage data collection |
| `CNESettings.apk` | system/app | Qualcomm Connectivity Engine |
| `DM.apk` | system | OMA Device Management (remote management) |
| `com.qualcomm.location.apk` | system/priv-app | Qualcomm location services |
| `com.qualcomm.services.location.apk` | system | Qualcomm location services |
| `com.qualcomm.qlogcat.apk` | system/app | Qualcomm log collection |
| `xtra_t_app.apk` | system/app | GPS XTRA data download |
| `MediaUploader.apk` | system/app | Media upload service |
| `GoogleFeedback.apk` | system/priv-app | Google crash/feedback reporting |

### Juzhen / UFI-Specific Apps

| APK | Purpose |
|-----|---------|
| `ufilauncherzx.apk` | UFI device launcher (home screen) |

### Chinese Carrier Bloatware

| APK | Carrier | Purpose |
|-----|---------|---------|
| `10086cn.apk` | China Mobile | Carrier portal |
| `CmccCustom.apk` | China Mobile | Customization |
| `CmccServer.apk` | China Mobile | Server service |
| `CmccWifi.apk` | China Mobile | WiFi service |
| `Monternet.apk` | China Mobile | Value-added services |
| `CtBrowserQuick.apk` | China Telecom | Browser |
| `CtLauncherRes.apk` | China Telecom | Launcher resources |
| `CtRoamingSettings.apk` | China Telecom | Roaming config |
| `CtUniversalDownload.apk` | China Telecom | Download service |
| `CuBrowserQuick.apk` | China Unicom | Browser |
| `CuLauncherRes.apk` | China Unicom | Launcher resources |
| `WoRead.apk` | China Unicom | Reading service |
| `CustomerService.apk` | Generic | Customer service portal |
| `LunarService.apk` | Generic | Lunar calendar |
| `DataMonitor.apk` | Generic | Data usage monitoring |

### Google Apps (GApps)

Full Google Mobile Services suite installed:
- GmsCore.apk, GoogleServicesFramework.apk, Phonesky.apk (Play Store)
- Gmail2.apk, Chrome.apk, YouTube.apk, GMS_Maps.apk
- GoogleCamera.apk, Hangouts.apk, PlayGames.apk
- GoogleFeedback.apk, GoogleBackupTransport.apk, etc.

---

## APK Packer / Obfuscation

### libjiagu - Chinese APK Protection

Found inside an APK in the system partition:

```
assets/libjiagu.so          # ARM 32-bit native library
assets/libjiagu_a64.so      # ARM 64-bit native library
assets/libjiagu_x86.so      # x86 native library
assets/libjiagu_x64.so      # x86_64 native library
```

**Analysis:** `libjiagu` is a Chinese APK packing/protection tool (likely "360 Jiagu" or "Tencent Legu"). It encrypts and obfuscates DEX bytecode at runtime, making static analysis of the protected APK extremely difficult. The presence of all four architecture variants (ARM, ARM64, x86, x86_64) in the system partition means at least one pre-installed system app uses this protection to hide its code from analysis.

This is a significant concern because:
1. The app's actual behavior cannot be determined through standard APK decompilation
2. It could contain additional phone-home, data collection, or backdoor functionality
3. Legitimate apps rarely need this level of obfuscation in a system partition

---

## Vendor-Specific Strings (Juzhen)

### Device Identity Properties

```
ro.product.brand=UFI
ro.product.device=UFI
ro.product.model=UFI
ro.product.name=UFI
persist.sys.juzhen.type=ufi
persist.sys.juzhen.sn=1
persist.sys.juzhen.sncode
persist.sys.juzhen.ssid.prefix=4G-UFI-
persist.sys.juzhen.ssid.suffix=2
```

### Juzhen PTT (Push-to-Talk) LED Control

```
juzhen.ptt.led.green.on
```

This indicates the dongle firmware has push-to-talk radio functionality with LED indicator control, suggesting the same firmware is used across different Juzhen product lines.

### Default Device SSID Pattern

```
4G-UFI-0000
```

The SSID is generated as `4G-UFI-` + suffix, making all devices identifiable by WiFi scan.

---

## Risk Assessment

### Phone-Home Risk: HIGH

The stock firmware contacts the following external servers without user consent:

1. **zzhc.vnet.cn** -- Sends IMEI/IMSI/ICCID to China Mobile for SIM registration tracking
2. **riddle.qualcomm.com** -- Qualcomm diagnostic data including GPS coordinates
3. **cne.qualcomm.com** -- Network traffic analysis and WiFi environment data
4. **izatcloud.net / gpsonextra.net** -- GPS assistance data (relatively benign but contacts Qualcomm)
5. **r1.indoor.izat-location.net** -- Registers device for indoor location tracking
6. **dm.monternet.com / dm.189.cn** -- OMA DM servers allow carrier remote management
7. **googleapis.com/geolocation** -- WiFi-based location data to Google

### Data Collection Risk: HIGH

The RIDL system alone collects:
- GPS coordinates (latitude, longitude, altitude)
- Network type and quality metrics
- Diagnostic logs
- Device registration data

### Remote Management Risk: HIGH

The OMA DM service (com.android.dm) with SelfReg capability means:
- Carriers can push configuration changes
- Firmware can be updated remotely via FOTA
- Apps can potentially be installed/removed remotely
- Device settings can be modified without user consent

### Credential Risk: CRITICAL

All devices share identical default credentials:
- Web admin: `admin`
- WiFi password: `1234567890`
- SIM PIN: `UFIadmin88888`

### Recommendations

1. **Replace firmware** with OpenStick or custom Android build that removes telemetry
2. **If keeping stock firmware:**
   - Change all default passwords immediately
   - Block outbound connections to zzhc.vnet.cn, riddle.qualcomm.com, cne.qualcomm.com
   - Disable or remove AutoRegistration.apk, RIDLClient.apk, DM.apk, StatManDo.apk, CrashLogger.apk
   - Block OMA DM push messages
3. **Network isolation:** Do not connect this device to sensitive networks with stock firmware
4. **Further analysis needed:** The jiagu-protected APK should be unpacked and analyzed to determine what it actually does

---

## Raw Data Files

All raw extraction data preserved at:
- `/tmp/system_strings.txt` -- All 4.5M extracted strings
- `/tmp/fw_urls.txt` -- 1,502 URL-containing lines
- `/tmp/fw_urls_clean.txt` -- 1,014 clean URLs
- `/tmp/fw_ips.txt` -- 760 unique IP addresses
- `/tmp/fw_cn_domains.txt` -- 278 Chinese domain references
- `/tmp/fw_creds_raw.txt` -- 5,977 credential-pattern strings
- `/tmp/fw_creds_assigned.txt` -- 522 credential assignment patterns
- `/tmp/fw_certs.txt` -- 374 certificate references
- `/tmp/fw_phonehome.txt` -- 511 phone-home indicator strings
- `/tmp/fw_dongle_specific.txt` -- 253 dongle/vendor-specific strings
