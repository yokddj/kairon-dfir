# Windows & WSL2 Setup

> Documentation status: technical draft pending maintainer review.

Kairon DFIR is supported on Windows through WSL2 (Windows Subsystem for Linux). Native PowerShell or CMD deployment is not supported in this beta.

## Why WSL2

The Docker containers (PostgreSQL, OpenSearch, Redis) and the backend (Python) require a Linux environment. WSL2 provides a full Linux kernel inside Windows with native Docker support.

## Setup Steps

### 1. Install WSL2

```powershell
# In PowerShell (as Administrator):
wsl --install -d Ubuntu
```

Restart your machine after installation.

### 2. Install Docker Desktop with WSL2 integration

1. Download Docker Desktop from https://www.docker.com/products/docker-desktop/
2. Install it.
3. In Docker Desktop settings, enable WSL2 integration for Ubuntu.
4. Restart Docker Desktop.

### 3. Open Ubuntu and clone the repository

```bash
# Inside Ubuntu/WSL2 terminal:
cd ~
git clone https://github.com/yokddj/kairon-dfir.git
cd kairon-dfir
```

> **Important:** Clone the repository inside the WSL Linux filesystem (`~/`). Do **not** clone under `/mnt/c/` — this causes slow I/O, permission errors, and line-ending issues.

### 4. Run the setup wizard

```bash
./scripts/setup.sh
```

### 5. Open Kairon in your Windows browser

The URL will be displayed at the end of the setup. If you're using LAN mode, use the WSL2 VM's IP address (shown by `ip addr show eth0` or the setup script output).

Navigate to `http://<IP>:5173` from your Windows browser.

## Troubleshooting

### Docker daemon not accessible from WSL2

Make sure Docker Desktop is running and WSL2 integration is enabled:
```
Docker Desktop → Settings → Resources → WSL Integration → Ubuntu → Enable
```

### Port 5173 not reachable from Windows

Check that Windows Firewall is not blocking the port. The WSL2 VM has its own IP address — use that rather than `localhost`.

```bash
# Find the WSL2 IP address
ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1
```

### "Windows native shell detected" error

Make sure you're running the script from inside an Ubuntu/WSL2 terminal, not from PowerShell, CMD, or Git Bash.

### Slow performance

If Docker operations are slow, ensure the repository and Docker data are stored on the WSL Linux filesystem, not on `/mnt/c/`.

Check Docker Desktop resource limits: Settings → Resources → Advanced.
