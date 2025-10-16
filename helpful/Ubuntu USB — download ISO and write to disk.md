### Ubuntu USB — download ISO and write to disk

Follow these steps to download an Ubuntu ISO and write it to a USB drive from the command line. Double‑check device names before writing to avoid data loss.

---

### 1. Download the Ubuntu ISO

Replace the URL with the release you want.

```bash
wget https://releases.ubuntu.com/jammy/ubuntu-22.04.4-desktop-amd64.iso
```

```bash
https://mirror.umd.edu/ubuntu-iso/24.04.3/ubuntu-24.04.3-desktop-amd64.iso
```

==============================================================================
ALWAYS VERIFY!!!!

Run this command in your terminal in the directory the iso was downloaded to verify the SHA256 checksum:

```bash
echo "faabcf33ae53976d2b8207a001ff32f4e5daae013505ac7188c9ea63988f8328 *ubuntu-24.04.3-desktop-amd64.iso" | shasum -a 256 --check
```

You should get the following output:
```bash
ubuntu-24.04.3-desktop-amd64.iso: OK
```
==============================================================================

---

### 2. Identify the target disk

List disks and identify your USB drive by size and model. Note the device name (example: /dev/sdb or /dev/sdc).

```bash
sudo fdisk -l
# or (Linux)
lsblk --output NAME,SIZE,MODEL,MOUNTPOINT
```

Caution: Writing to the wrong device will destroy its data.

---

### 3. Unmount the USB device (if auto‑mounted)

Replace /dev/sdx1 with any mounted partitions on the USB device.

```bash
sudo umount /dev/sdx1 2>/dev/null || true
```

---

### 4. Write the ISO to the USB drive

Replace ubuntu-22.04.4-desktop-amd64.iso and /dev/sdx with the correct filenames and device (use the whole device, not a partition, e.g., /dev/sdb).

```bash
sudo dd if=ubuntu-22.04.4-desktop-amd64.iso of=/dev/sdx bs=4M status=progress oflag=sync
```

Notes:
- if= specifies the input file (ISO).  
- of= specifies the output device (entire USB device).  
- bs=4M improves throughput.  
- status=progress shows progress.  
- oflag=sync helps ensure data is flushed to the device before completion.

---

### 5. Finalize and eject

Ensure write buffers are flushed, then safely remove the device.

```bash
sync
sudo eject /dev/sdx
```

---

### Quick verification (optional)

On many systems you can confirm the device’s partition table was replaced:

```bash
sudo fdisk -l /dev/sdx
```

Boot from the USB on your target machine (use the machine’s boot menu or BIOS/UEFI options) to start the Ubuntu installer.
