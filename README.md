# Email Junk Cleaner

Python CLI that connects to your Outlook mailbox via Microsoft Graph API and bulk-cleans junk/inbox.

## What it does

**Junk folder**
- `scan` — categorize everything in your Junk folder (definite spam / probably spam / unknown)
- `delete-spam` — delete definite + probably spam
- `delete-all` — wipe the whole Junk folder

**Inbox cleanup**
- `inbox-stats` — sender census of your Inbox
- `inbox-scan` — classify emails against a whitelist
- `inbox-delete` — batch-delete classified emails (supports `--dry-run`)

## Setup

### 1. Install dependencies

```bash
pip install msal requests python-dotenv
```

### 2. Register an Azure app (each user needs their own)

1. Go to https://portal.azure.com → **App registrations** → **New registration**
2. Name it anything (e.g. "Email Junk Cleaner")
3. **Supported account types:** Personal Microsoft accounts only
4. **Redirect URI:** Public client/native → `http://localhost:8400`
5. Click **Register**
6. From the **Overview** page, copy the **Application (client) ID**
7. Go to **Certificates & secrets** → **New client secret** → copy the **Value** (not the ID)
8. Go to **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated** → add `Mail.ReadWrite`

### 3. Create your config file

The script reads credentials from `~/.config/emailjunkcleaner/.env`:

```bash
mkdir -p ~/.config/emailjunkcleaner
cp .env.example ~/.config/emailjunkcleaner/.env
# then edit ~/.config/emailjunkcleaner/.env and fill in the values from step 2
```

### 4. Run it

```bash
python3 email_junk_cleaner.py scan
```

First run opens a browser for Microsoft consent. Token is cached at `~/.config/emailjunkcleaner/.ms_token_cache.json`.

## Notes

- Tested against personal Microsoft accounts (outlook.com / hotmail.com / live.com). Work/school tenants would need `MS_TENANT_ID` set to the tenant GUID instead of `consumers`.
- `junk_scan_results.json` is written to the current directory and contains email metadata — gitignored by default.
