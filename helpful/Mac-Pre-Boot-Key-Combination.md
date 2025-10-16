### Mac Pre Boot Key Combinations 2012–2025
Official consolidated reference for startup key combinations, behaviors, and recommended use. Applicable to Intel, T2 security chip, and Apple Silicon Macs. Use this as the single source of truth when preparing, troubleshooting, or documenting Mac startup procedures.

---

### Table of Contents
- Intel based Macs 2012–2020
- T2 security chip Macs 2018–2020
- Apple Silicon Macs 2020–2025
- Common hardware resets NVRAM and SMC
- How to perform startup key combinations correctly
- Quick reference summary table

---

### Intel based Macs 2012–2020
Boot key combinations and behaviors for Macs with Intel processors. Use these to select boot targets, run diagnostics, reinstall or recover macOS, and access low level troubleshooting environments.

#### Recovery Mode
- **Keys:** Command + R  
- **Behavior:** Boots the built in macOS Recovery environment.  
- **Use when:** Reinstalling macOS, running Disk Utility, restoring from Time Machine, or accessing recovery utilities.  
- **How to perform:** Power on or restart, then press and hold Command + R until the Apple logo or a spinning globe appears.

#### Startup Manager Boot Selection
- **Keys:** Option  
- **Behavior:** Displays available bootable volumes for manual selection.  
- **Use when:** Booting from an external installer, USB drive, or alternate startup disk.  
- **How to perform:** Hold Option immediately after power on until boot options appear.

#### Internet Recovery
- **Keys:** Command + Option + R to install the latest compatible macOS; Command + Shift + Option + R to install the original macOS shipped or closest available version.  
- **Behavior:** Boots Recovery over the internet from Apple servers, indicated by a spinning globe.  
- **Use when:** Internal recovery partition is missing, damaged, or you need an internet based reinstall.  
- **How to perform:** Hold the required key combo at power on and wait for the spinning globe.

#### Safe Mode
- **Keys:** Shift  
- **Behavior:** Boots with essential kernel extensions only, disables login items, and performs basic disk checks.  
- **Use when:** Isolating software issues, testing with a minimal environment, or uninstalling problematic software.  
- **How to perform:** Hold Shift immediately after power on and release at the login window.

#### Apple Diagnostics
- **Keys:** D or Option + D for network diagnostics  
- **Behavior:** Runs Apple Diagnostics to test core hardware components.  
- **Use when:** Suspecting hardware faults such as logic board, memory, or sensors.  
- **How to perform:** Hold D after power on; use Option + D to force internet diagnostics when local diagnostics are unavailable.

#### Single User Mode
- **Keys:** Command + S  
- **Behavior:** Boots to a root command line environment for advanced filesystem and repair tasks.  
- **Use when:** Experienced troubleshooting or recovery using command line tools.  
- **How to perform:** Hold Command + S during startup; text console will appear when entered.

#### Verbose Mode
- **Keys:** Command + V  
- **Behavior:** Shows detailed boot log output to assist with diagnosing startup problems.  
- **Use when:** Gathering more information about kernel and driver load during startup.  
- **How to perform:** Hold Command + V during startup.

#### Target Disk Mode
- **Keys:** T  
- **Behavior:** Exposes the Mac’s internal storage as an external disk to another Mac over Thunderbolt or FireWire.  
- **Use when:** Transferring large data sets or recovering files from a nonworking Mac.  
- **How to perform:** Hold T during startup until a disk icon or connection protocol appears.

#### Reset NVRAM
- **Keys:** Command + Option + P + R  
- **Behavior:** Clears nonvolatile parameter memory such as speaker volume, display resolution, startup disk selection, and recent kernel panic information.  
- **Use when:** Resolving boot disk selection problems, display or audio settings that do not persist, or other low level configuration issues.  
- **How to perform:** Hold keys immediately after powering on and release after hearing the second startup chime or after the Apple logo appears and disappears twice.

#### Reset SMC System Management Controller
- **Keys for MacBooks with non removable battery:** Shift + Control + Option (left side) plus Power button for 10 seconds  
- **Behavior:** Resets low level system controllers responsible for power management, battery charging, thermal control, and system sleep behaviors.  
- **Use when:** Resolving power, charging, thermal fan, or wake/sleep problems.  
- **How to perform:** Shut down, press and hold the indicated keys and Power for 10 seconds, release, then power on normally.

---

### T2 security chip Macs 2018–2020
T2 equipped Macs include additional firmware and security functions. All Intel based key combos remain valid unless noted.

#### Firmware Recovery Mode
- **Keys:** Command + Option + F + R  
- **Behavior:** Initiates firmware repair or reinstall for the T2 security chip via internet recovery.  
- **Use when:** Firmware is corrupted or the Mac fails to start due to T2 firmware issues.  
- **How to perform:** Hold keys at power on; a network connection is required and a spinning globe may appear.

#### Notes
- Standard Intel key combos for recovery, diagnostics, Safe Mode, NVRAM, and SMC apply, but T2 introduces secure boot and firmware protections that can change behavior when Secure Boot settings or Startup Security Utility policies restrict external boot or firmware changes.

---

### Apple Silicon Macs 2020–2025
Apple Silicon Macs use a different startup architecture. The Power button driven Startup Options screen replaces many legacy key combos. Use the methods below tailored to M1 and later systems.

#### Startup Options
- **Action:** Press and hold the Power button after shutdown or during startup.  
- **Behavior:** Displays graphical Startup Options showing available volumes, an Options item for Recovery, and tools for diagnostics and safe startup.  
- **Use when:** Selecting a different startup disk, entering Recovery, or viewing boot options.  
- **How to perform:** Shut down, press and hold the Power button until the Startup Options screen appears.

#### Recovery Mode
- **Action:** From Startup Options select Options then Continue.  
- **Behavior:** Loads macOS Recovery for reinstall, Disk Utility, Terminal, and other recovery tasks.  
- **Use when:** Reinstalling macOS, restoring from Time Machine, or repairing drives.  
- **How to perform:** Hold Power to access Startup Options, choose Options, then Continue.

#### Safe Mode
- **Action:** From Startup Options select the desired startup disk, then hold Shift and click Continue in Safe Mode.  
- **Behavior:** Boots with the minimal set of system extensions and login items disabled.  
- **Use when:** Isolating software conflicts or testing core system behavior.  
- **How to perform:** Access Startup Options via the Power button, select the startup disk, then hold Shift and choose Continue in Safe Mode.

#### Apple Diagnostics
- **Action:** From Startup Options press and hold D.  
- **Behavior:** Runs Apple Diagnostics adapted for Apple Silicon hardware.  
- **Use when:** Verifying hardware integrity or collecting diagnostics codes for support.  
- **How to perform:** Access Startup Options by holding Power, then hold D to launch diagnostics.

#### Target Disk Mode
- **Status:** Not supported on Apple Silicon.  
- **Alternative:** Use Migration Assistant, file sharing, or network based transfers to move data between Macs.

#### NVRAM Behavior
- **Status:** Manual NVRAM reset not required. NVRAM is managed by the system and is automatically refreshed on restarts as needed.

#### SMC Behavior
- **Status:** SMC as a separate controller no longer exists. Low level system management functions are integrated into the Apple Silicon architecture and reset automatically as part of normal shutdown and startup processes.

---

### Common hardware resets NVRAM and SMC
Concise procedures and recommended uses for Intel Mac resets.

#### Reset NVRAM Intel Macs
- **Purpose:** Clear stored parameters such as startup disk, screen resolution, and audio settings.  
- **Procedure:** Hold Command + Option + P + R at startup until hearing the second chime or seeing the Apple logo appear/disappear twice.  
- **Recommended when:** Startup disk selection fails, display or audio settings are incorrect after system updates, or an NVRAM related configuration is corrupted.

#### Reset SMC Intel MacBooks
- **Purpose:** Reset power management and thermal control subsystems.  
- **Procedure for non removable battery MacBooks:** Shut down, press and hold Shift + Control + Option (left side) and the Power button for 10 seconds, release, then press Power to start.  
- **Recommended when:** Experiencing charging, battery recognition, fan, sleep, or power button issues after other software troubleshooting steps.

---

### How to perform startup key combinations correctly
Step by step guidance to ensure reliable results.

1. **Shut down or restart the Mac completely.**  
2. **Identify the correct key or action for the desired mode.**  
3. **Power on and immediately press and hold the required keys or hold the Power button for Apple Silicon.**  
4. **Continue holding until the expected screen, sound, or icon appears.**  
5. **Release the keys and follow on screen instructions.**  

Best practices: use the built in keyboard or a directly connected Apple keyboard, avoid wireless keyboards when timing is critical, and ensure a stable power source and network connection for internet recovery or firmware operations.

---

### Quick reference summary table

| Function | Intel 2012 to 2020 | T2 2018 to 2020 | Apple Silicon 2020 to 2025 |
|---|---:|---:|---:|
| Recovery Mode | **Cmd + R** | **Cmd + R** | **Hold Power → Options → Continue** |
| Internet Recovery | **Cmd + Option + R**; **Shift + Cmd + Option + R** | Same | N A |
| Safe Mode | **Shift** | **Shift** | **Hold Shift in Startup Options** |
| Apple Diagnostics | **D**; **Option + D** | **D**; **Option + D** | **Hold D in Startup Options** |
| Target Disk Mode | **T** | **T** | **Not supported** |
| NVRAM Reset | **Cmd + Option + P + R** | **Cmd + Option + P + R** | **Automatic** |
| SMC Reset | **Shift + Control + Option + Power** | Same | **Not applicable** |
| Firmware Recovery | **Cmd + Option + F + R** (T2 only) | **Cmd + Option + F + R** | **Integrated** |

---

### Notes and recommended workflows
- Use Recovery Mode for OS reinstall and repair tasks that preserve user data when possible.  
- Use Internet Recovery when the local Recovery partition is unavailable or corrupted.  
- Use Safe Mode first when diagnosing software related startup problems.  
- Run Apple Diagnostics prior to opening a hardware service request and collect reference codes provided by the utility.  
- For T2 Mac firmware or secure boot issues use Firmware Recovery only when advised by Apple Support or documented procedures.  
- On Apple Silicon, prefer the Startup Options workflow and Migration Assistant for data transfer tasks that previously used Target Disk Mode.

---

This document is formatted for distribution as a single consolidated GitHub markdown file for technicians and users documenting Mac startup behaviors across Intel, T2, and Apple Silicon platforms.
