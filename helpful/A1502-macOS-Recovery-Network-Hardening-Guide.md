# 🍏 A1502 macOS Recovery Network Hardening Guide

> **Intended purpose**: This guide provides **verbatim commands** for bypassing enterprise DNS restrictions when installing macOS on **MacBook Pro A1502 (2015-2017)** models in Recovery Mode. Use only when legitimate installation is blocked by network filtering.

## ⚠️ Critical Safety Notice

**WARNING**: Only use these techniques on systems you own or have explicit authorization to manage. These commands alter network configuration and may violate enterprise policies if used without permission.

---

## 📋 Table of Contents

- [Immediate Prerequisites](#-immediate-prerequisites)
- [Recovery Environment Tools](#-recovery-environment-tools)
- [Step-by-Step DNS Bypass](#-step-by-step-dns-bypass)
- [Installation Validation](#-installation-validation)
- [Troubleshooting](#-troubleshooting)
- [Success Indicators](#-success-indicators)
- [License & Disclaimer](#-license--disclaimer)

---

## 🚨 Immediate Prerequisites

- ✅ A1502 MacBook Pro in **Recovery Mode** (`Cmd + R`)
- ✅ **Terminal** open from Utilities menu
- ✅ **Wi-Fi connected** and captive portal completed
- ✅ **Power adapter** connected
- ✅ **Physical access** to machine

---

## 🛠️ Recovery Environment Tools

```bash
echo "=== Available Recovery Tools ==="
which scutil
which networksetup
which nslookup
which dns-sd
which curl
echo "=== Basic System Info ==="
system_profiler SPHardwareDataType | grep -E "Model Identifier|Serial Number"
networksetup -listallhardwareports
```

**Expected**: Should show `MacBookPro13,x` and network interfaces.

---

## 🛡️ Step-by-Step DNS Bypass

### Step 1: Network Assessment

```bash
echo "=== Current Network Status ==="
scutil --nwi
scutil --dns | head -20
networksetup -listallnetworkservices
```

### Step 2: Global DNS Override (Primary Method)

```bash
echo "=== Implementing Global DNS Bypass ==="
scutil << EOF
open
get State:/Network/Global/IPv4
d.add ServerAddresses * 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 8.8.8.8 8.8.4.4
set State:/Network/Global/IPv4
close
EOF
echo "Global DNS override complete"
```

### Step 3: Service-Specific DNS (Alternative)

```bash
echo "=== Service-Specific DNS Configuration ==="
for service in $(scutil <<< "list" | grep "State:/Network/Service" | awk -F'/| ' '{print $4}'); do
  echo "Configuring $service..."
  scutil << EOF
open
get State:/Network/Service/${service}/DNS
d.add ServerAddresses * 1.1.1.1 1.0.0.1 9.9.9.9
set State:/Network/Service/${service}/DNS
close
EOF
done
```

### Step 4: Hardened Hosts File

```bash
echo "=== Creating Hardened Hosts File ==="
cat > /etc/hosts << 'EOF'
127.0.0.1       localhost
255.255.255.255 broadcasthost
::1             localhost

# Apple Installation Servers (A1502 Specific)
17.253.22.204  swcdn.apple.com
17.253.22.207  gg.apple.com
17.253.22.205  oscdn.apple.com
17.253.22.206  swscan.apple.com
17.253.22.203  mesu.apple.com
17.253.22.202  gdmf.apple.com

# Secure DNS Providers
1.1.1.1        one.one.one.one
1.0.0.1        one.one.one.one
9.9.9.9        dns.quad9.net
149.112.112.112 dns.quad9.net
8.8.8.8        dns.google

# Block Telemetry
0.0.0.0        metrics.icloud.com
0.0.0.0        metrics.apple.com
0.0.0.0        sequoia.apple.com
EOF
echo "Hosts file configured"
```

### Step 5: DNS Testing

```bash
echo "=== Testing DNS Bypass ==="
nslookup apple.com 1.1.1.1
nslookup swcdn.apple.com
ping -c 2 gg.apple.com
ping -c 2 oscdn.apple.com
```

### Step 6: Cache Flush

```bash
echo "=== Flushing DNS Cache ==="
dscacheutil -flushcache
killall -HUP mDNSResponder
scutil --dns | head -10
```

---

## ✅ Installation Validation

```bash
echo "=== Apple Server Validation ==="
CRITICAL_DOMAINS=(
"swcdn.apple.com"
"gg.apple.com" 
"oscdn.apple.com"
"swdist.apple.com"
"swscan.apple.com"
"mesu.apple.com"
"gdmf.apple.com"
)

for domain in "${CRITICAL_DOMAINS[@]}"; do
    echo "Testing $domain:"
    nslookup $domain 2>/dev/null | grep -E "Address:|name ="
    ping -c 1 -t 2 $domain 2>/dev/null | grep "bytes from" || echo "Ping timeout"
    echo "---"
done
```

---

## 🚀 Troubleshooting

### Network Reset Options

```bash
echo "=== Network Reset Options ==="
echo "1. Interface reset:"
networksetup -setdnsservers "Wi-Fi" empty
networksetup -setdhcp "Wi-Fi"
echo "2. Manual refresh:"
ipconfig set en0 DHCP
echo "3. Cache flush:"
dscacheutil -flushcache
```

### Emergency Recovery

```bash
echo "=== Emergency Options ==="
echo "If installation still fails:"
echo "1. Try Thunderbolt Ethernet adapter"
echo "2. Use personal hotspot"
echo "3. Create bootable installer on another Mac"
echo "4. Contact IT for network exemption"
```

---

## ✅ Success Indicators

**Ready to install when:**
- ✅ `nslookup swcdn.apple.com` returns Apple IPs
- ✅ `ping gg.apple.com` gets responses  
- ✅ No DNS timeouts or "server can't find" errors
- ✅ Can access "Reinstall macOS" without network errors

**Installation steps:**
1. Close Terminal
2. Select "Reinstall macOS" from Utilities
3. Choose recommended version (macOS 10.12-12.x for A1502)
4. Follow installation prompts

---

## 📄 License & Disclaimer

**MIT License** - Use at your own risk. Not affiliated with Apple Inc.

**Responsible Use**: Only use for legitimate system recovery on authorized devices. Obtain proper permissions before bypassing enterprise network controls.

---

## 🔄 Post-Installation Cleanup

After successful installation, in the new macOS:

```bash
# Restore default hosts file
sudo rm /etc/hosts

# Reset to automatic DNS
sudo networksetup -setdnsservers Wi-Fi empty

# Verify normal operation
networksetup -getdnsservers "Wi-Fi"
```

**Note**: Most Recovery changes are temporary and won't persist after installation.

---

*Last updated: 2025 | A1502 MacBook Pro Recovery Guide* | Evan + DeepSeek
