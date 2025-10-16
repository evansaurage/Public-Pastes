# 🍏 Ultimate Mac Recovery & Pre-Boot Key Guide + A1502 Network Hardening (2012–2025)

> Purpose: This single, coherent, comprehensive markdown consolidates and preserves every command, explanation, and nuance from the three provided recovery and network-hardening guides. It includes:
> - Complete startup key combinations for Intel, T2, and Apple Silicon Macs (2012–2025)
> - Full, verbatim Recovery Terminal commands for A1502 (2015–2017) network hardening
> - Diagnostics, DNS override methods (`networksetup`, `scutil`), hosts hardening, validation loops, troubleshooting, boot-arg tweaks, manual `vi` instructions, emergency fallback options, and post-install cleanup & DNSSEC checks
>
> WARNING: These procedures change network configuration and system state in Recovery Mode. Use only on systems you own or are explicitly authorized to manage. The authors are not responsible for misuse.

---

## 📋 Table of Contents

- [Startup Key Combinations (Intel, T2, Apple Silicon)](#startup-key-combinations-intel-t2-apple-silicon)
- [What Makes A1502 Recovery Unique](#what-makes-a1502-recovery-unique)
- [Immediate Prerequisites](#immediate-prerequisites)
- [Recovery Environment Tools](#recovery-environment-tools)
- [Step-by-Step DNS Bypass and Hardening](#step-by-step-dns-bypass-and-hardening)
  - [Network Assessment](#network-assessment)
  - [Global DNS Override (Primary Method)](#global-dns-override-primary-method)
  - [Service-Specific DNS (Alternative)](#service-specific-dns-alternative)
  - [Hardened Hosts File (Automated)](#hardened-hosts-file-automated)
  - [Manual Hosts Editing with vi (Fallback)](#manual-hosts-editing-with-vi-fallback)
  - [DNS Testing and Cache Flush](#dns-testing-and-cache-flush)
- [Installation Validation (CRITICAL_DOMAINS Loop)](#installation-validation-critical_domains-loop)
- [A1502 Step-By-Step Recovery Walkthrough (Alternative presentation)](#a1502-step-by-step-recovery-walkthrough-alternative-presentation)
- [Troubleshooting & Emergency Recovery Options](#troubleshooting--emergency-recovery-options)
  - [Network Reset Options](#network-reset-options)
  - [Installer Log and Debugging](#installer-log-and-debugging)
  - [DNS Resolution Troubleshooting](#dns-resolution-troubleshooting)
  - [NVRAM and SMC Resets](#nvram-and-smc-resets)
- [Success Indicators & Ready-to-Install Checklist](#success-indicators--ready-to-install-checklist)
- [Post-Install Cleanup & Security Checks (DNSSEC, hosts removal)](#post-install-cleanup--security-checks-dnssec-hosts-removal)
- [A1502 Model-Specific Notes and Table](#a1502-model-specific-notes-and-table)
- [Comprehensive Summary Table (Pre-Boot Keys & Recovery Methods)](#comprehensive-summary-table-pre-boot-keys--recovery-methods)
- [License & Disclaimer](#license--disclaimer)

---

## 🔑 Startup Key Combinations (Intel, T2, Apple Silicon)

- Intel-based Macs (2012–2020) — use these key combos during startup for recovery, troubleshooting, boot selection, and hardware resets.

  - Recovery Mode  
    - Keys: Command (⌘) + R  
    - What it does: Boots into the built-in macOS Recovery system.  
    - When to use: To reinstall macOS, repair disks, restore from Time Machine, or run Disk Utility.  
    - How to use: Immediately after powering on, press and hold these keys until the Apple logo or spinning globe appears.

  - Startup Manager (Boot Disk Selection)  
    - Keys: Option (⌥)  
    - What it does: Shows all available bootable drives for manual selection.  
    - When to use: When you want to boot from an external drive or USB installer.  
    - How to use: Hold Option key after power on until boot options appear.

  - Internet Recovery Mode  
    - Keys:  
      - Command (⌘) + Option (⌥) + R — installs the latest compatible macOS over the internet.  
      - Command (⌘) + Shift (⇧) + Option (⌥) + R — installs the macOS version that shipped with your Mac or the closest available.  
    - What it does: Boots recovery tools via Apple’s servers using internet connection.  
    - When to use: If internal recovery partition is missing or damaged.  
    - How to use: Hold keys after powering on; a spinning globe will appear.

  - Safe Mode  
    - Keys: Shift (⇧)  
    - What it does: Boots with minimal drivers and disables login items.  
    - When to use: Troubleshooting startup issues caused by software or drivers.  
    - How to use: Hold Shift key immediately after powering on until login window appears.

  - Apple Diagnostics  
    - Keys: D (or Option (⌥) + D for network diagnostics)  
    - What it does: Tests your Mac’s hardware for problems.  
    - When to use: If you suspect hardware issues.  
    - How to use: Hold D after power on; for internet diagnostics, hold Option + D.

  - Single-User Mode  
    - Keys: Command (⌘) + S  
    - What it does: Boots into a command-line environment for advanced troubleshooting.  
    - When to use: Experienced users needing low-level access (less common in modern macOS).  
    - How to use: Hold keys after power on until text appears.

  - Verbose Mode  
    - Keys: Command (⌘) + V  
    - What it does: Displays detailed boot information for troubleshooting.  
    - When to use: When diagnosing boot problems.  
    - How to use: Hold keys after power on.

  - Target Disk Mode  
    - Keys: T  
    - What it does: Turns your Mac into an external drive accessible by another Mac.  
    - When to use: To transfer files between Macs via Thunderbolt or FireWire.  
    - How to use: Hold T key immediately after powering on.

  - Reset NVRAM  
    - Keys: Command (⌘) + Option (⌥) + P + R  
    - What it does: Resets stored settings like speaker volume, screen resolution, and startup disk.  
    - When to use: When experiencing hardware or boot configuration issues.  
    - How to use: Hold keys after power on, release after hearing second startup chime or after Apple logo appears and disappears twice.

  - Reset SMC (System Management Controller)  
    - Keys (MacBooks with non-removable battery): Hold Shift (⇧) + Control (^) + Option (⌥) (all left side) + Power button for 10 seconds.  
    - What it does: Resets low-level system functions like power, battery, and thermal management.  
    - When to use: For power, battery, fan, or performance issues.  
    - How to use: Shut down Mac, press keys simultaneously for 10 seconds, then release and power on.

- T2 Security Chip Macs (2018–2020) — T2 Macs add enhanced security and have some extra options.

  - Firmware Recovery Mode  
    - Keys: Command (⌘) + Option (⌥) + F + R  
    - What it does: Reinstalls or repairs T2 chip firmware via internet recovery.  
    - When to use: If firmware is corrupted or Mac won’t start normally.  
    - How to use: Hold keys immediately after power on, requires internet connection.

  - All other Intel combos apply, but with the added firmware security.

- Apple Silicon Macs (M1, M2, 2020–2025) — Apple Silicon Macs boot differently; key combos have changed.

  - Startup Options  
    - Keys: Press and hold Power button until startup options appear.  
    - What it does: Shows bootable volumes and options like Recovery and Safe Mode.  
    - When to use: To select boot disk, enter Recovery, or Safe Mode.  
    - How to use: Shut down Mac, hold power button until options appear.

  - Recovery Mode  
    - Keys: From startup options screen, click Options then continue.  
    - What it does: Boots into macOS Recovery.  
    - When to use: To reinstall macOS or repair disk.  
    - How to use: Hold power button at boot, then select Options > Continue.

  - Safe Mode  
    - Keys: From startup options, select startup disk, then hold Shift and click Continue in Safe Mode.  
    - What it does: Boots with limited drivers.  
    - When to use: Troubleshooting software conflicts.  
    - How to use: See above.

  - Apple Diagnostics  
    - Keys: From startup options, hold D key.  
    - What it does: Runs hardware diagnostic tests.  
    - When to use: To check hardware problems.  
    - How to use: From startup options, press and hold D.

  - Target Disk Mode  
    - Not supported on Apple Silicon. Use Migration Assistant or file sharing.

  - NVRAM Reset  
    - No manual reset needed. NVRAM resets automatically on shutdown.

  - SMC Reset  
    - Not applicable. SMC functions integrated in Apple Silicon chip.

---

## 🧠 What Makes A1502 Recovery Unique

- Intel-based MacBook Pro 13” with T1/T2 chip not present (no Secure Enclave restrictions on recovery).  
- Uses traditional Intel EFI-based Recovery (not Apple Silicon recovery).  
- Wi-Fi and Ethernet hardware specifics can affect network detection.  
- Thunderbolt Ethernet adapter often required for more stable recovery network.  
- NVRAM and SMC reset commands can be critical on these models if network hangs occur.  
- Slightly different default network interface names (`en0` usually Wi‑Fi, `en3` or `en4` Thunderbolt Ethernet).  
- A1502 model identifiers: MacBookPro12,1 (2015), MacBookPro13,1 (2016), MacBookPro14,1 (2017). OS compatibility: macOS 10.12 Sierra → 12.x Monterey.

---

## 🚨 Immediate Prerequisites

- A1502 MacBook Pro in Recovery Mode (`Cmd + R`).  
- Terminal open from Utilities menu.  
- Wi‑Fi connected and captive portal completed (Safari usable) or Ethernet connected.  
- Power adapter connected.  
- Physical access to the machine.  
- Recommended: Thunderbolt → Ethernet adapter for wired install.

---

## 🛠️ Recovery Environment Tools

Run these to confirm the Recovery environment has the tools necessary:

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

Expected: should show Mac model (e.g., `MacBookPro13,x`) and network interfaces.

If tools are missing or output is unexpected, note it before proceeding.

---

## 🛡️ Step-by-Step DNS Bypass and Hardening

This section provides multiple methods preserved verbatim. Use the ones appropriate for your environment. Apply only on authorized systems.

### Network Assessment

```bash
echo "=== Current Network Status ==="
scutil --nwi
scutil --dns | head -20
networksetup -listallnetworkservices
```

### Global DNS Override (Primary Method)

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

When to use: preferred when Recovery is allowed to use scutil and you require a session-only override that avoids editing system files directly.

### Service-Specific DNS (Alternative)

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

When to use: if global override is unavailable or you prefer per-service DNS configuration.

### Hardened Hosts File (Automated — overwrite `/etc/hosts`)

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

When to use: when DNS-based filtering prevents domain resolution and a direct IP-to-hostname override is required. Note: overwrites any existing hosts entries.

### Manual Hosts Editing With vi (Fallback)

```bash
vi /etc/hosts
```

Basic vi instructions (in Recovery where `nano` may not exist):
- Press `i` to enter insert mode.  
- Paste or type your entries.  
- Press `Esc` to exit insert mode.  
- Type `:wq` and press `Enter` to save and exit.

When to use: when heredoc or `cat` is not available or you need to make curated edits.

### DNS Testing

```bash
echo "=== Testing DNS Bypass ==="
nslookup apple.com 1.1.1.1
nslookup swcdn.apple.com
ping -c 2 gg.apple.com
ping -c 2 oscdn.apple.com
```

### Cache Flush

```bash
echo "=== Flushing DNS Cache ==="
dscacheutil -flushcache
killall -HUP mDNSResponder
scutil --dns | head -10
```

---

## ✅ Installation Validation

Full validation loop preserved verbatim:

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

Use this loop to confirm that Recovery can reach Apple CDNs and installer hosts before attempting reinstall. Successful nslookup results and at least one ping response indicate readiness.

---

## A1502 Step-By-Step Recovery Walkthrough (Alternative presentation of combined steps)

This walkthrough preserves all commands and ordering from the original materials and includes additional model-specific commands.

### Step 1 — Verify Model and Recovery Environment

```bash
echo "=== Model Info ==="
system_profiler SPHardwareDataType | grep -E "Model Identifier|Serial Number|Model Name"
nvram -p | grep recovery
```

Expected: should show `MacBookPro12,x`, `MacBookPro13,x`, or `MacBookPro14,x` and recovery nvram lines.

### Step 2 — Identify Network Interfaces

```bash
echo "=== Network Interfaces ==="
networksetup -listallhardwareports
ifconfig -l
ifconfig | grep inet
echo "=== Network Services ==="
networksetup -listallnetworkservices
```

Note: A1502 may use nonstandard interface names for Thunderbolt Ethernet (e.g., `en3`, `en4`). Always verify interfaces via `networksetup -listallhardwareports` and `ifconfig -l`.

### Step 3 — Set Secure DNS (preferred order: Ethernet then Wi‑Fi)

```bash
networksetup -setdnsservers "Wi-Fi" 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112
networksetup -setdnsservers "Thunderbolt Ethernet" 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112
networksetup -ordernetworkservices "Thunderbolt Ethernet" "Wi-Fi"
```

When to use: Use Thunderbolt Ethernet if available for stable download. Adjust service names if your interface names differ.

### Step 4 — Reset Network Configuration & Boot Args (optional/advanced)

```bash
nvram -c                                      # Clear NVRAM variables
nvram boot-args="-no_dns_relay"              # Disable DNS relay (reduces captive portal issues)
ipconfig set en0 DHCP                        # Renew Wi-Fi IP
ipconfig set en1 DHCP                        # Renew Ethernet IP
```

Caveat: `nvram boot-args` could alter boot behavior; use only with authorization and revert post‑install with `nvram -d boot-args`.

### Step 5 — Harden `/etc/hosts` (automated method recommended)

See the Hardened Hosts File block above for the full heredoc that overwrites `/etc/hosts`. This block includes Apple installer IPs, fallback DNS provider names, and telemetry blocks.

### Step 6 — Test Network & Apple Servers

```bash
echo "=== Network Interface Status ==="
ifconfig en0 | grep "status:"
ifconfig en1 | grep "status:"

echo "=== DNS Resolution Test ==="
nslookup apple.com 1.1.1.1
nslookup swcdn.apple.com

echo "=== Ping Apple CDN ==="
ping -c 2 swcdn.apple.com
ping -c 2 gg.apple.com
```

### Step 7 — Flush DNS and Restart Services

```bash
dscacheutil -flushcache
killall -HUP mDNSResponder
scutil --dns
```

### Step 8 — Reinstall macOS

```bash
echo "=== READY FOR INSTALLATION ==="
echo "1. Close Terminal"
echo "2. Select 'Reinstall macOS'"
echo "3. Choose recommended macOS version (Monterey or earlier for A1502)"
echo "4. Follow prompts to complete install"
```

---

## 🛠️ Troubleshooting & Emergency Recovery Options

This section contains every troubleshooting command and emergency fallback from the three sources.

### Network Reset Options (preserved verbatim)

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

### Emergency Recovery Options (preserved verbatim)

```bash
echo "=== Emergency Options ==="
echo "If installation still fails:"
echo "1. Try Thunderbolt Ethernet adapter"
echo "2. Use personal hotspot"
echo "3. Create bootable installer on another Mac"
echo "4. Contact IT for network exemption"
```

When to use: If hardened DNS and hosts overrides fail to allow Recovery to fetch installers, fall back to wired Ethernet, personal hotspot tethering, or a local bootable installer.

### Installer Log and Debugging (preserved)

```bash
log show --predicate 'process == "osinstaller"' --last 30m
```

Use the above to inspect installer logs when the installer stalls or fails.

### DNS Resolution Troubleshooting (preserved)

```bash
# Reset Wi-Fi
networksetup -setairportpower en0 off
sleep 2
networksetup -setairportpower en0 on

# Test with different DNS providers
networksetup -setdnsservers "Wi-Fi" 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220

# Verify connectivity
curl -I https://apple.com

# Test DNS port reachability
nc -z 1.1.1.1 53
nc -z 8.8.8.8 53
```

### NVRAM and SMC Resets (preserved and explicit)

#### Reset NVRAM (Recovery Terminal)

```bash
nvram -c
```

#### SMC Reset (Intel MacBook Pro with nonremovable battery)

1. Shutdown  
2. Press and hold Left Shift + Control + Option + Power for 10 seconds  
3. Release and power on

Use when power management, charging, or network interface behaviors appear inconsistent after other steps.

---

## ✅ Success Indicators & Ready-to-Install Checklist

Ready to install when:
- `nslookup swcdn.apple.com` returns Apple IPs  
- `ping gg.apple.com` gets responses  
- No DNS timeouts or "server can't find" errors  
- Can access "Reinstall macOS" from Recovery without network errors

Installation steps:
1. Close Terminal  
2. Select "Reinstall macOS" from Utilities  
3. Choose recommended version (macOS 10.12–12.x for A1502 where applicable)  
4. Follow installation prompts until completion

---

## Post-Install Cleanup & Security Checks (DNSSEC, hosts removal)

Run these in the newly installed macOS (or Recovery after install) to restore defaults and verify secure DNS behavior:

```bash
# Restore default hosts file
sudo rm /etc/hosts

# Reset to automatic DNS
sudo networksetup -setdnsservers Wi-Fi empty

# Verify normal operation
networksetup -getdnsservers "Wi-Fi"

# Clear custom boot args if set
sudo nvram -d boot-args || true

# DNSSEC and dig checks (run from installed macOS)
scutil --dns | grep "DNSSEC"
dig apple.com +dnssec
dig sigfail.verteiltesysteme.net
dig sigok.verteiltesysteme.net
```

Notes: Most Recovery changes are ephemeral and will not persist after full install, but explicitly remove overrides to ensure a clean production environment.

---

## A1502 Model-Specific Notes and Table

| Feature | Details |
|---------|---------|
| **Ethernet Preferred** | Use Thunderbolt Ethernet adapter for the most reliable installation |
| **OS Compatibility** | A1502 supports macOS 10.12 Sierra to 12.x Monterey |
| **Power Required** | Keep charger connected throughout installation |
| **Install Time** | Hotel Wi‑Fi installs may take 30–60 minutes |
| **Security Chip** | A1502 has T1/T2 differences; verify model before firmware recovery |
| **Recovery Types** | Internet Recovery (Cmd+Opt+R) vs Local Recovery (Cmd+R) |
| **Model Identifiers** | 2015: MacBookPro12,1; 2016: MacBookPro13,1; 2017: MacBookPro14,1 |

Model-specific Tip: interface names in Recovery can vary; always discover available hardware ports and map them to enX names with `networksetup -listallhardwareports`.

---

## Comprehensive Summary Table (Pre-Boot Keys & Recovery Methods)

| Function               | Intel (2012–2020)                | T2 (2018–2020)                  | Apple Silicon (2020+)            |
|------------------------|----------------------------------|---------------------------------|----------------------------------|
| Recovery Mode          | Cmd + R                          | Cmd + R                          | Hold Power → Options → Continue |
| Internet Recovery      | Cmd + Option + R / Shift + Cmd + Option + R | Same                  | N/A                              |
| Startup Manager        | Option                           | Option                           | Hold Power → Startup Options     |
| Safe Mode              | Shift                            | Shift                            | Hold Shift in Startup Options    |
| Apple Diagnostics      | D / Option + D                   | D / Option + D                   | Hold D in Startup Options        |
| Target Disk Mode       | T                                | T                                | Not supported                    |
| NVRAM Reset            | Cmd + Option + P + R             | Cmd + Option + P + R             | Automatic                        |
| SMC Reset              | Shift + Control + Option + Power | Same                             | Integrated                       |
| Firmware Recovery Mode | N/A                              | Cmd + Option + F + R             | Integrated                       |

---

## License & Disclaimer

- MIT License — Use at your own risk.  
- This guide is not affiliated with Apple Inc.  
- Responsible Use: Only use for legitimate system recovery and authorized device management. Obtain proper permission before bypassing enterprise network controls.  
- The authors are not responsible for data loss, misconfiguration, or policy violations resulting from following these procedures.

---

*Last updated: October 2025 | Consolidated from three provided recovery guides in found https://github.com/evansaurage/Public-Pasts/helpful/ | For technicians, system administrators, and advanced Mac users.*

