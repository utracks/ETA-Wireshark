# EnterpriseTrafficAnalyzer (ETA-Wireshark)

A Wireshark-native Lua plugin that analyzes enterprise network traffic for suspicious behavior. It includes post-dissectors for DNS tunneling, HTTP anomalies, JA3 fingerprinting, and TLS version checking. Built for blue teamers, analysts, and network defenders.

##  Features

-  DNS Tunneling Detection (long queries, TXT/NULL record abuse)
-  HTTP Anomaly Detection (long URIs, suspicious User-Agents, threat patterns)
-  JA3 Fingerprint Matching for malicious TLS clients
-  Customizable alerts (desktop popups + logfile)
-  Configuration system with threat intel auto-update

##  Installation

1. Copy `ETAv1.lua` to your Wireshark plugin directory:
   - Windows: `%APPDATA%\Wireshark\plugins`
   - macOS/Linux: `~/.config/wireshark/plugins/`

2. Restart Wireshark.

3. Confirm loading via `Help → About Wireshark → Plugins`.
