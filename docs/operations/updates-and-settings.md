# Updates and instance settings

Two administrator pages of **System** (side menu, administrators only): **Updates** says whether the
branch the instance follows has new commits, and **Instance settings** changes settings that used to
need an edit of `.env`.

## Updates

An instance is a git checkout that follows a branch (`main` by default) and is upgraded with
`./scripts/upgrade.sh`. An update is a commit on that branch newer than the one the running images
were built from.

- **When it checks**: while an administrator has Kairon open, at most every
  `UPDATE_CHECK_INTERVAL_HOURS` (6 by default; one hour after a failed attempt). **Check now** on the
  page checks at once. The answer is kept in the database, so restarts and every backend worker
  share it.
- **What it sends**: one request to GitHub's public API,
  `GET https://api.github.com/repos/<UPDATE_CHECK_REPOSITORY>/compare/<running commit>...<UPDATE_CHECK_BRANCH>`,
  with the user agent `kairon-dfir-update-check`. Nothing else about the instance goes out.
- **What it shows**: when there are new commits, **System** in the side menu carries an **Update**
  mark, and the page lists the new commits (newest first, merge commits left out), links to the full
  comparison on GitHub and gives the commands to run on the server:

  ```bash
  ./scripts/dfir-backup.sh --db-only
  ./scripts/upgrade.sh
  ```

  When there is nothing new the page says the instance is up to date. Nothing is shown anywhere else.
- **Without internet**: the failed attempt is reported only on the Updates page; if an earlier
  check worked, its answer stays.
- **Which commit runs**: `scripts/setup.sh` (and so `upgrade.sh`) passes `git rev-parse HEAD` to the
  image build, and the backend image keeps it in `/app/.kairon-commit`. Images built another way do
  not know their commit; the page then says so, and the next `./scripts/upgrade.sh` records it.
  A running commit that GitHub does not have (local commits not pushed) cannot be compared.
- **Turning it off**: **Instance settings > Check for updates** (applies at once), or
  `UPDATE_CHECK_ENABLED=false` in `.env`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `UPDATE_CHECK_ENABLED` | `true` | Check at all. Also in Instance settings. |
| `UPDATE_CHECK_REPOSITORY` | `yokddj/kairon-dfir` | GitHub repository (`owner/name`) the instance follows. |
| `UPDATE_CHECK_BRANCH` | `main` | Branch the instance follows. |
| `UPDATE_CHECK_INTERVAL_HOURS` | `6` | Hours between checks. |

With the [host agent](#host-agent) enabled, **Update now** on this page does it for you.

## Instance settings

A closed list of settings read when a service starts: log level, wizard advanced options, ingest and
archive limits and timeouts, Windows event log limits (slow mark, stop when stalled, longest time per
file), disk image ingest and export limits, and, when memory analysis is
enabled, the Windows memory engine, memory job limits and the memory switches (automatic
preparation, Run all, MemProcFS crash retry, MemProcFS YARA rules under the Elastic License 2.0,
Linux symbol uploads).

- A value saved on the page is stored in the database and takes precedence over `.env`. It applies
  when the listed services restart (`backend`, `worker`, and `memory-worker` for memory settings);
  the page marks each setting waiting for a restart and gives the command, for example
  `docker compose restart backend worker`. **Check for updates** applies at once.
- **Use .env** removes the saved value; after the restart the value from `.env` (or
  `config/defaults.env`) applies again.
- Values are checked against the setting's type and range before they are saved; one invalid value
  rejects the whole change. Every change is written to the activity log with who made it and the old
  and new values.
- If the database cannot be read when a service starts (first start, a command run on the host), or
  a saved value is no longer valid, the service starts with `.env` alone and logs it.

Not on the page, and changed only in `.env` (then `docker compose up -d`):

- secrets, connection details, ports and URLs, and what docker compose itself reads (OpenSearch
  heap, worker replicas, profiles);
- the switches that let the server reach outside the lab or the host's file system:
  `S3_SOURCE_ENABLED`, `AZURE_BLOB_SOURCE_ENABLED`, `MEMORY_SYMBOL_NETWORK_ACCESS_ENABLED`,
  `MEMORY_AUTO_SYMBOL_ACQUIRE`, `MEMORY_ALLOW_EXTERNAL_TOOL_EXECUTION`, `DFIR_ALLOW_HOST_PATH_IMPORT`,
  and `MEMORY_ANALYSIS_ENABLED` (it needs the memory-worker container). The page shows their values,
  read-only, so that a web session alone cannot turn them on;
- the memory plugin allowlists, which upgrades update in `.env`.

The tuning values of **Performance** (batch sizes, parallelism, page sizes, Sigma limits) were
already set from the UI and stay there.

## Host agent

The containers have no access to Docker on the host, on purpose. To restart or upgrade Kairon from the
web UI, a small optional agent runs on the host (`scripts/kairon-agent.sh`) as the user that owns the
Kairon directory: a launchd agent on macOS, a systemd service on Linux (a user unit, or a system unit
when installed as root).

- **Enabling it**: `scripts/setup.sh` asks "Enable the host agent?" next to the deployment mode and
  memory analysis (`--host-agent` without prompts) and keeps the answer in `.env`
  (`KAIRON_HOST_AGENT`); `upgrade.sh` installs or removes the agent as it says. On an existing
  installation: `./scripts/host-agent.sh enable` (or `disable`, `status`).
- **What it does**: only two actions, chosen in the UI:
  - **Update now** (System > Updates): `./scripts/dfir-backup.sh --db-only`, then
    `./scripts/upgrade.sh`. Kairon is unavailable for a few minutes; the page reconnects and shows
    the result and the log. On macOS the Mac is kept awake meanwhile (`caffeinate`).
  - **Restart now** (System > Instance settings, when saved settings wait for a restart):
    `docker compose restart` of backend, worker and memory-worker as needed.
- **When it refuses**: while any job is queued or running in Kairon's queues (ingest, retries,
  rules, memory, symbols), since a restart or upgrade would kill it; when the running jobs cannot be
  checked; for an upgrade, when the Kairon directory has local changes; and while another request is
  waiting or running. The backend checks before accepting the request and the agent checks again
  before acting.
- **How it talks to Kairon**: through files in `./agent/` (requests, status, logs and a heartbeat),
  mounted by the backend only, at `/app/agent`: the workers, which read untrusted evidence, cannot ask
  for anything. A request names an action and services from fixed lists; the agent rejects anything
  else. Every request is written to the activity log with who made it.
- The buttons appear only while the agent's heartbeat is recent; without the agent the pages show the
  commands to run instead.
- Validated on macOS (launchd). On Linux the systemd units are written by `host-agent.sh`; with a
  user unit, run `sudo loginctl enable-linger <user>` so it keeps running after logout.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/system/update-status` | Stored update status; checks GitHub when the interval has passed. |
| `POST /api/system/update-status/check` | Checks now. |
| `GET /api/admin/instance-settings` | Each setting with its `.env` value, saved value, running value and whether it waits for a restart; the read-only list; the restart command. |
| `PATCH /api/admin/instance-settings` | `{"settings": {"KEY": value}}`; `null` removes the saved value. |
| `GET /api/admin/host-agent` | Whether the host agent is running, the jobs in Kairon's queues and the latest requests with their status and log. |
| `POST /api/admin/host-agent/requests` | `{"action": "upgrade"}` or `{"action": "restart", "services": [...]}`; 409 with the reason when refused. |

All of them are for administrators.
