# ShortURL - Secure shortlink service

Minimal secure URL shortener using Express and SQLite with Bootstrap UI.

## Quick start (Windows PowerShell):

```powershell
cd d:/nodejs/shorturl
npm install
npm start
```

Open http://localhost:3000

## Features:
- SQLite storage via sql.js (pure JS, no native builds)
- CSRF protection for the form
- Basic host validation to avoid localhost/internal targets
- Rate limiting (60 requests/minute)
- Expiry rules (minutes/hours/days/months) selectable when creating a shortlink
- Hourly cleanup job to remove expired links
- Modern responsive UI with Bootstrap 5: cards, alerts, icons, better typography
- Admin page for viewing recent links
- Smart URL validation: automatically prepends https:// if protocol is missing

## Security notes:
- For production, add authentication for the admin page, enable HTTPS, and consider running behind a reverse proxy.
- Add logging, analytics, and tests as needed.
- Consider using a proper database server for high traffic.
- URL validation: Accepts URLs with or without protocol; prepends https:// if missing. Rejects invalid URLs and disallowed hostnames.
