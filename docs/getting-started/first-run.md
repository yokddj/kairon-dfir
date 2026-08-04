# First-Run Setup

> Documentation status: technical draft pending maintainer review.

When you first start Kairon DFIR with an empty database, you are guided through creating the administrator account via a web wizard. No CLI or manual database changes are required.

## The First-Run Experience

1. Run `./scripts/setup.sh` and follow the prompts to create your `.env` file.
2. Build and start the services:
   ```bash
   docker compose build --pull
   docker compose up -d
   ```
3. Open the URL shown by `setup.sh` (e.g. `http://192.0.2.10:5173`).
4. The browser automatically opens the setup wizard.
5. Create your administrator account (username, email, password).
6. You are automatically logged in.

## What the Wizard Asks

| Field | Required | Notes |
|-------|----------|-------|
| Username | Yes | Unique across the platform |
| Email | No | Administrator contact |
| Password | Yes | Minimum 12 characters |
| Confirm password | Yes | Must match |

## How It Works

On first launch with zero users in the database:
- `GET /api/auth/needs-setup` returns `{"needs_setup": true}`
- The frontend detects this and shows the setup wizard at `/setup`
- After creation, `needs-setup` returns `false` permanently
- The wizard closes and the login page appears for subsequent visits

## After First Login

1. Go to **Admin → Users**.
2. Click **Create user**.
3. Choose **Standard user** as the role.
4. Test the new account by logging in from a private window.

## Troubleshooting

### Login page appears instead of setup wizard

**Likely cause:** A stale Docker image is running.

**Fix:**
```bash
docker compose build --no-cache --pull backend frontend
docker compose up -d backend frontend
```

**Verify:**
```bash
# Check that the database has zero users
docker compose exec postgres psql -U dfir -d dfir -c "SELECT COUNT(*) FROM users;"
# Should return: 0

# Verify the setup endpoint
curl -s http://localhost:5173/api/auth/needs-setup
# Should return: {"needs_setup":true}
```

### "Invalid credentials" appears on first load

The login page should not show an error message before any login attempt. If you see this:
- Ensure you ran `docker compose build --pull` after a code update.
- Clear your browser cookies for the domain.
- Verify the setup wizard is accessible: `curl -s http://localhost:5173/api/auth/needs-setup`

## Recovery

If you lose access to all administrator accounts:
```bash
docker compose exec postgres psql -U dfir -d dfir \
  -c "SELECT username, is_admin, is_active FROM users;"
```

If no active admin remains, reset a password via the backend:
```bash
docker compose exec backend python -m app.cli reset-password --username <username>
```
