# Windows notifications (wpndatabase.db)

`%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db` is the SQLite store
behind the Action Center, one per user profile (also under the system profile).

## How it is parsed

- Raw collections: discovery lists each `wpndatabase.db` as a **Windows notifications**
  candidate together with its `-wal` and `-shm`. Disk images and extracted folders
  route it by name.
- `backend/app/ingest/windows_ui/wpndatabase.py` copies the database with its
  `-wal`/`-shm` into a scratch folder and opens the copy, so SQLite replays the WAL
  there and never on the evidence. Recent notifications often exist only in the WAL.
- Rows go through the Windows UI normalizer (`artifact.type = windows_ui`,
  `artifact.parser = windows_notifications`), the same as notification CSV exports.

## What it gives

| `event.type` | Time (`@timestamp`) | Content |
| --- | --- | --- |
| `notification_observed` | arrival (`ArrivalTime`) | App (`app.id`), type (toast, tile, badge, raw), title and body text from the payload XML (`notification.title`, `notification.body_preview`), live-tile lock-screen status lines, launch target, image sources, expiry time. |
| `notification_app_registered` | handler creation | Each app registered to send notifications, with when it was registered. Windows' own `app:system` handlers, all registered when the profile is created, are left out. |

Toasts can hold what is nowhere else on disk: the preview of a mail or chat
message, a website's push message, a security warning. Security and threat
notifications (Defender, firewall turned off...) are scored as high risk. Every
notification is on the timeline (`event.timeline_include`); app registrations are not.

## Limitations

- Only notifications still in the database are there: Windows removes them when they
  expire or are dismissed. Deleted rows in free pages are not recovered.
- A tile's text is whatever the app last pushed to it, not a user action.
