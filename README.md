# UFI 4G USB Dongle — Firmware Security Analysis

Security analysis of the stock Android 4.4 firmware shipped on cheap Chinese
UFI 4G USB dongles (Juzhen/矩阵, MSM8916 SoC).

## TL;DR

The stock firmware is severely insecure:
- **5 critical**, **7 high**, **5 medium** severity findings
- Active phone-home to Chinese servers (IMSI/IMEI exfiltration)
- Main app obfuscated with Qihoo 360 jiagu packer (behavior unknown)
- Qualcomm RIDL collects GPS + uploads to Qualcomm
- OMA DM allows carrier to remotely control the device
- All passwords hardcoded: WiFi=`1234567890`, admin=`admin`
- SELinux disabled, firmware signed with public test-keys
- VPN does NOT protect against these risks (phone-home bypasses VPN)

**Recommendation:** Replace with [OpenStick Debian](https://github.com/thomas-greenautarky/USB-Dongle-OpenStick)

## Reports

- **[REPORT.md](REPORT.md)** — Full analysis with executive summary and risk assessment
- **[findings/01-properties-and-wifi.md](findings/01-properties-and-wifi.md)** — System properties and WiFi config
- **[findings/02-urls-and-credentials.md](findings/02-urls-and-credentials.md)** — URLs, domains, credentials
- **[findings/03-services-and-backdoors.md](findings/03-services-and-backdoors.md)** — Services and backdoor assessment
- **[findings/04-apk-analysis.md](findings/04-apk-analysis.md)** — APK decompilation

## Device

- UFI 4G USB WiFi Dongle (Amazon B0C3SC6ZG6)
- Juzhen JZ0145-v33, Qualcomm MSM8916
- Android 4.4.4 KTU84P, build eng.richal.20251104

## License

MIT
