# CyberNova Kernel-Level Antivirus

File access interception drivers for Windows and Linux.
Blocks execution of malicious files by SHA-256 hash before they run.

## Architecture

```
┌──────────┐   poll commands    ┌──────────────┐
│  Backend  │ ◄──────────────►  │    Agent      │
│ blocklist │   GET /blocklist  │               │
│   API     │                   │  command      │
└──────────┘                   │  handler      │
                                    │
                          IOCTL / sysfs write
                                    │
                                    ▼
                          ┌──────────────────┐
                          │ Kernel Driver/LSM │
                          │ (file_open hook)  │
                          │ hash → blocklist  │
                          │ match → DENY      │
                          └──────────────────┘
```

## Components

### Windows — Minifilter Driver (`windows/`)

| File | Purpose |
|------|---------|
| `cybernova.c` | Main driver: entry, IRP_MJ_CREATE callback, IOCTL dispatch |
| `cybernova.h` | Types, IOCTL codes, blocklist entry structure |
| `blocklist.c` | Hash-table backed blocklist (8192 buckets) |
| `cybernova.inf` | Driver package INF |
| `build.bat` | WDK build script |
| `install.ps1` | Install/load driver on target machine |

**Build:**
```
build.bat x64
```

**Install:**
```
# Admin PowerShell
.\install.ps1
```

**Update blocklist:**
```powershell
# Via IOCTL (C#/PowerShell utility)
$bytes = [System.IO.File]::ReadAllBytes("blocklist.bin")
$device = New-Object System.IO.FileStream("\\.\CyberNovaAV", [System.IO.FileAccess]::ReadWrite)
$device.Write($bytes, 0, $bytes.Length)
$device.Close()
```

### Linux — LSM Module (`linux/`)

| File | Purpose |
|------|---------|
| `cybernova_lsm.c` | LSM module: file_open hook, RB-tree blocklist, securityfs interface |
| `Makefile` | Kernel module build |
| `install.sh` | Build, install, load module |

**Prerequisites:**
```bash
apt install linux-headers-$(uname -r) build-essential
```

**Build & Install:**
```bash
sudo ./install.sh
```

**Update blocklist via securityfs:**
```bash
# Mount securityfs (if not already)
mount -t securityfs securityfs /sys/kernel/security

# Add entry: <64-char-hex> <severity> <description>
echo 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 99 Example' \
  > /sys/kernel/security/cybernova/blocklist

# View all entries
cat /sys/kernel/security/cybernova/blocklist

# Clear all entries
echo 'clear' > /sys/kernel/security/cybernova/blocklist

# View stats
cat /sys/kernel/security/cybernova/stats
```

## Blocklist Format

The blocklist is a JSON document stored on the backend:

```json
{
  "version": 1,
  "updated_at": "2026-05-09T10:00:00Z",
  "entries": [
    {
      "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "severity": 99,
      "description": "Mimikatz credential dumper"
    }
  ]
}
```

## Agent Integration

The CyberNova agent polls for commands via `GET /api/v1/devices/commands`.
When an `update_blocklist` command is received:

1. Agent fetches blocklist from `GET /api/v1/blocklist/agent`
2. Writes entries to the kernel driver:
   - **Windows:** IOCTL `IOCTL_CYBERNOVA_UPDATE_BLOCKLIST`
   - **Linux:** Write to `/sys/kernel/security/cybernova/blocklist`
3. Acknowledges the command via `POST /api/v1/devices/commands/{id}/ack`

## Management API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/blocklist` | Get current blocklist |
| `PUT` | `/api/v1/blocklist` | Update blocklist (admin) |
| `DELETE` | `/api/v1/blocklist` | Clear blocklist |
| `GET` | `/api/v1/blocklist/agent` | Agent fetches blocklist |
| `POST` | `/api/v1/agent/{id}/command` | Send command to device |

## Safety

- Drivers only block files with `FMODE_EXEC` / `FILE_EXECUTE` access
- Non-executable files are always allowed
- Pseudo-filesystems (procfs, sysfs, tmpfs) are skipped
- If the driver fails to hash (I/O error, OOM), the file is allowed through
- Blocklist falls back to allow-all if empty
