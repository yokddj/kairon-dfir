# Deployment Modes

Kairon DFIR supports three deployment modes. Choose based on where your browser and server are relative to each other.

## Mode Selection

| Mode | When to use | URL format |
|------|-------------|------------|
| `localhost` | Browser and Kairon on the same machine | `http://localhost:5173` |
| `lan` | Kairon on a server, accessed from other machines on the same trusted network | `http://192.0.2.10:5173` |
| `https` | Public domain with TLS reverse proxy | `https://kairon.example.com` |

## localhost

Use for development, testing, or single-machine deployment.

```bash
./scripts/setup.sh --non-interactive --mode localhost
```

The setup wizard generates:
- `KAIRON_PUBLIC_URL=http://localhost:5173`
- `KAIRON_ALLOWED_ORIGINS=http://localhost:5173`
- Secure cookies: disabled (HTTP only)

No other machines on the network can reach the UI. Backend is accessed via the Nginx `/api` proxy, not directly.

## LAN

Use when Kairon runs on a server and other machines on the same private network need access.

```bash
./scripts/setup.sh --non-interactive --mode lan --url http://192.0.2.10:5173
```

> **Warning:** LAN mode uses HTTP and must not be exposed to untrusted networks. Session cookies are not marked Secure.

The setup wizard generates:
- `KAIRON_PUBLIC_URL=http://192.0.2.10:5173`
- Origins restricted to the exact URL
- Secure cookies: disabled

Replace `192.0.2.10` with your server's actual IP address.

## HTTPS

Use when the deployment has a domain, TLS certificate, and reverse proxy.

```bash
./scripts/setup.sh --non-interactive --mode https --url https://kairon.example.com
```

The setup wizard generates:
- `KAIRON_PUBLIC_URL=https://kairon.example.com`
- Origins restricted to the exact domain
- Secure cookies: enabled
- CORS configured for the exact origin

**Kairon does not manage TLS certificates automatically.** You must configure TLS on your reverse proxy (Nginx, Traefik, Caddy, etc.) before exposing the deployment.

## Changing Mode

To change the deployment mode after initial setup:
1. Edit `KAIRON_PUBLIC_URL` in `.env`.
2. Rebuild and restart:
   ```bash
   docker compose build --pull backend frontend
   docker compose up -d
   ```
