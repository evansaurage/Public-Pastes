## What makes the A1502 Recovery & Network environment special/different?

* Intel-based MacBook Pro 13” with T1/T2 chip *not present* (so no Secure Enclave restrictions on recovery)
* Uses traditional Intel EFI-based Recovery (not Apple Silicon recovery)
* Wi-Fi and Ethernet hardware specifics can affect network detection
* Thunderbolt Ethernet adapter often required for more stable recovery net
* NVRAM and SMC reset commands can be critical on these models if network hangs occur
* Slightly different default network interface names (`en0` usually Wi-Fi, `en3` or `en4` Thunderbolt Ethernet)

---

# 🍏 A1502 MacBook Pro Recovery Network Hardening Guide (2015–2017 Intel Models)

> **Purpose:**
> This guide provides **advanced network hardening techniques for macOS Recovery on Intel-based A1502 MacBook Pros**. It aims to bypass enterprise/hotel DNS filtering, enforce reliable DNS resolution, and ensure successful macOS reinstall over restrictive networks.

---

## ⚠️ Critical Safety Notice

Use only if:

* You have physical access to the A1502 MacBook Pro
* You accept responsibility for network config changes in Recovery Mode
* You understand this guide is for temporary session-only Recovery fixes
* You have backups or are prepared for system recovery

---

## 📋 Table of Contents

* [✅ Prerequisites](#-prerequisites)
* [🧰 Step-by-Step Commands](#-step-by-step-commands)
* [🛠️ Troubleshooting & Model-Specific Tips](#️-troubleshooting--model-specific-tips)
* [🔐 Post-Install Security Checks](#-post-install-security-checks)
* [📌 Important Notes for A1502](#-important-notes-for-a1502)
* [📄 License & Disclaimer](#-license--disclaimer)

---

## ✅ Prerequisites

### Hardware & Network

* MacBook Pro 13" A1502 (2015-2017) powered on and connected to charger
* Thunderbolt to Ethernet adapter strongly recommended (bypass flaky Wi-Fi)
* Internet connection established (hotel Wi-Fi or Ethernet, captive portal completed if needed)

### macOS Recovery Environment

* Booted into macOS Recovery Mode (`Cmd + R`)
* Terminal opened (Utilities → Terminal)
* Wi-Fi or Ethernet recognized (`ifconfig` to verify interfaces)
* Power adapter connected

---

## 🧰 Step-by-Step Commands

### Step 1 — Verify Model and Recovery Environment

```bash
echo "=== Model Info ==="
system_profiler SPHardwareDataType | grep -E "Model Identifier|Serial Number|Model Name"
echo "=== NVRAM Recovery Info ==="
nvram -p | grep recovery
```

---

### Step 2 — Confirm Network Interfaces and Status

```bash
echo "=== Network Interfaces ==="
ifconfig -l

echo "=== Current IP Addresses ==="
ifconfig | grep inet

echo "=== Network Services ==="
networksetup -listallnetworkservices
```

---

### Step 3 — Set Reliable DNS for Recovery Network

* Use your Ethernet adapter interface if connected, otherwise Wi-Fi (`en0` usually Wi-Fi)

```bash
ETH_IFACE=$(networksetup -listallhardwareports | awk '/Thunderbolt Ethernet/{getline; print $2}')
WIFI_IFACE=$(networksetup -listallhardwareports | awk '/Wi-Fi/{getline; print $2}')

echo "Ethernet interface: $ETH_IFACE"
echo "Wi-Fi interface: $WIFI_IFACE"

# Prefer Ethernet DNS override if available
if [[ -n "$ETH_IFACE" ]]; then
    networksetup -setdnsservers "$ETH_IFACE" 1.1.1.1 1.0.0.1 9.9.9.9
else
    networksetup -setdnsservers "$WIFI_IFACE" 1.1.1.1 1.0.0.1 9.9.9.9
fi

echo "DNS servers set. Verifying:"
networksetup -getdnsservers "$ETH_IFACE" || networksetup -getdnsservers "$WIFI_IFACE"
```

---

### Step 4 — Use `scutil` to Force Global DNS Override (Session-Only)

```bash
scutil << EOF
open
get State:/Network/Global/IPv4
d.add ServerAddresses * 1.1.1.1 1.0.0.1 9.9.9.9
set State:/Network/Global/IPv4
close
EOF
echo "Global DNS override via scutil applied"
```

---

### Step 5 — Harden `/etc/hosts` with Apple Installer IPs

```bash
cat > /etc/hosts << 'EOF'
127.0.0.1       localhost
255.255.255.255 broadcasthost
::1             localhost

# Apple Installer Critical IPs
17.253.22.204  swcdn.apple.com
17.253.22.207  gg.apple.com
17.253.22.205  oscdn.apple.com
17.253.22.206  swscan.apple.com
17.253.22.203  mesu.apple.com
17.253.22.202  gdmf.apple.com

# DNS Providers (fallback)
1.1.1.1        one.one.one.one
1.0.0.1        one.one.one.one
9.9.9.9        dns.quad9.net
EOF
echo "Hosts file hardened with Apple IP overrides"
```

---

### Step 6 — Flush DNS Cache and Restart mDNSResponder

```bash
dscacheutil -flushcache
killall -HUP mDNSResponder
echo "DNS cache flushed and mDNSResponder restarted"
```

---

### Step 7 — Validate Apple Server Reachability

```bash
DOMAINS=(
"swcdn.apple.com"
"gg.apple.com"
"oscdn.apple.com"
"swscan.apple.com"
"mesu.apple.com"
"gdmf.apple.com"
)

for domain in "${DOMAINS[@]}"; do
    echo "Testing: $domain"
    nslookup $domain 1.1.1.1
    ping -c 2 $domain
    echo "---"
done
```

---

## 🛠️ Troubleshooting & Model-Specific Tips

* **No Ethernet detected?** Make sure Thunderbolt Ethernet adapter is firmly connected, then reboot Recovery.
* **Wi-Fi unstable?** Prefer Ethernet or create a USB bootable installer for offline install.
* **Network still blocking?** Use `/etc/hosts` IP overrides to bypass DNS-based filtering.
* **DNS changes reset after reboot?** Expected; Recovery environment is ephemeral. Re-apply on each boot.
* **If stuck in network loop:** Try resetting NVRAM and SMC:

```bash
# Reset NVRAM (from Recovery Terminal)
nvram -c

# SMC reset requires shutdown + key combo on Intel MacBook Pro:
# 1. Shutdown
# 2. Press Shift+Control+Option + Power for 10 sec
# 3. Release and power on
```

---

## 🔐 Post-Install Security Checks

* Verify DNS settings restored to defaults after OS install.
* Ensure `/etc/hosts` cleared or reset as expected post-install.
* Check that macOS Firewall and SIP (System Integrity Protection) are enabled after installation.

---

## 📌 Important Notes for A1502 MacBook Pro

* This guide targets Intel models **only** (2015–2017). Apple Silicon or T2 Macs use different recovery methods.
* Use Thunderbolt Ethernet adapter when possible for better network stability in recovery.
* All network configuration changes are **session-only** in Recovery and do not persist after reboot.
* This guide is designed to bypass DNS blocking caused by captive portals or enterprise network restrictions during reinstall.

---

## 📄 License & Disclaimer

This work is licensed under [MIT License](LICENSE). Use at your own risk. This guide is intended for authorized recovery operations only.

---

