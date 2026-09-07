# Veritas 24/7 Cloud Monitor

This runs on **GitHub's servers**, so your Mac can be completely off.

It checks `theveritassearch.com` every 5 minutes and monitors:

- raw bytes of HTML, JS, CSS, JSON/API responses, images, fonts, PDFs, etc.
- hidden HTML
- rendered DOM after JavaScript runs
- full-page rendered screenshot hash
- XHR/fetch/API responses
- external resources loaded by the site
- HTTP status changes and stable response-header changes
- added/removed pages and resources
- rendered links/forms/iframes
- `robots.txt`, sitemaps, manifests, favicon and common metadata files
- WebSocket frames observed during page load
- JavaScript console output and page errors
- localStorage/sessionStorage hashes
- DNS address changes
- TLS certificate changes
- subdomains found through:
  1. certificate-transparency logs,
  2. pages/sitemaps/robots,
  3. URLs and network requests observed during crawling

## Important limits

No external monitor can see a backend/database change that produces **no public
observable effect**.

Likewise, there is no mathematically guaranteed way to enumerate a completely
secret subdomain that has never appeared in DNS/certificate-transparency/public
site content. This monitor deliberately uses several discovery methods to catch
publicly exposed subdomains.

## Free phone alert: ntfy

This is a push notification on your iPhone, not an SMS/iMessage bubble.
It works while your Mac is off.

1. Install the **ntfy** app on your iPhone.
2. Generate a long random topic name locally:

   ```bash
   python3 -c "import secrets; print('veritas-' + secrets.token_hex(24))"
   ```

3. In the ntfy app, subscribe to that exact topic on `ntfy.sh`.
4. On GitHub, open your repository:
   **Settings → Secrets and variables → Actions → New repository secret**
5. Create a secret named:

   `NTFY_TOPIC`

   and paste the random topic name as its value.

Do **not** put the topic directly in the public repo. Anonymous ntfy topics are
effectively public to anyone who can guess the topic name, so use a long random
one.

## Deploy

### 1. Create a GitHub repository

For unlimited standard GitHub-hosted Actions minutes, make the repository
**public**.

The monitor state contains only observations of the public target website.
Your notification topic stays in GitHub Secrets and is not committed.

### 2. Upload this folder

The repository needs to contain:

```text
.github/workflows/monitor.yml
monitor.py
requirements.txt
state/
README.md
```

You can do this in GitHub's web UI or with git.

### 3. Add `NTFY_TOPIC`

Follow the ntfy steps above.

### 4. Start it

Open:

**Actions → Veritas 24/7 monitor → Run workflow**

On the very first successful run, the monitor creates a baseline and sends:

> Veritas monitor is LIVE — Test notification: cloud monitoring is active...

After that it checks automatically every 5 minutes.

## Where to see what is monitored

After each baseline/change, open:

`state/last_report.md`

It lists every `theveritassearch.com` host/subdomain that the monitor discovered
and monitored on that run.

`state/manifest.json` is the machine-readable baseline.

## Real SMS instead of a free push notification

GitHub cannot send Apple iMessages directly. A real carrier SMS requires an SMS
provider.

The script already supports Twilio. Add these GitHub repository secrets:

- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM`
- `TWILIO_TO`

If all four are present, it sends SMS alerts in addition to ntfy.

Twilio is **not fully free** after any trial allowance; there are per-message and
phone-number/carrier costs.

## Strict header mode

The default ignores headers such as `Date`, request IDs, cookies, and CDN timing
metadata. Their values often change on every single request.

The **response body is still hashed byte-for-byte**.

If you truly want alerts for every header change too, edit:

```yaml
STRICT_HEADERS: "0"
```

to:

```yaml
STRICT_HEADERS: "1"
```

Expect an alert essentially every run.

## Polling caveat

GitHub's schedule supports 5-minute cron intervals, but scheduled jobs are not a
hard real-time guarantee and can occasionally start late. A normal website does
not provide a webhook when it changes, so polling is required.
