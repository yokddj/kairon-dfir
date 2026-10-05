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

The UI port (5173) is published on all interfaces, so other machines on the network can open it at `http://<this-machine's-address>:5173`. The API port (8000) is published on this machine only (`127.0.0.1`); browsers reach the API through the Nginx `/api` proxy. Set `KAIRON_API_BIND=0.0.0.0` only if something on another machine must call the API directly.

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

## Request Protection

These apply in every mode and need no configuration:

- **Cross-site requests.** A request that changes something (POST, PUT, PATCH, DELETE) sent by a browser is accepted only when the page that sent it is Kairon itself (same address and port as the request) or an origin listed in `KAIRON_ALLOWED_ORIGINS`. A page on another site, or on another port of the same machine, gets `403 Cross-site request refused`. Scripts and the CLI, which send no `Origin`/`Referer`, are not affected; they still need a session or token.
- **CORS.** Only the origins in `KAIRON_ALLOWED_ORIGINS` may read API responses from another origin; there is no catch-all. The UI does not need CORS: it reaches the API through its own `/api` proxy. Opening the UI by IP or by name from other machines works because those requests come from the UI itself.
- **Failed logins.** After 10 failed passwords for the same user from the same address within 5 minutes, that address gets `429 Too many failed sign-in attempts` with a `Retry-After` until the window passes. A correct password clears the count. The user can still sign in from other machines, and other users are never affected: Kairon never locks an account.
- **Addresses.** Behind the bundled Nginx (or any proxy on a private or loopback address), the client address recorded in audit logs and used for the login limit is the real one from `X-Real-IP`; a client cannot fake it.

## Changing Mode

To change the deployment mode after initial setup:
1. Edit `KAIRON_PUBLIC_URL` in `.env`.
2. Rebuild and restart:
   ```bash
   docker compose build --pull backend frontend
   docker compose up -d
   ```
