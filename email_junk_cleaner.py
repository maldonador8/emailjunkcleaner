#!/usr/bin/env python3 -u
"""
Email Junk Cleaner — Microsoft Graph API Tool
Connects to your Outlook mailbox for email cleanup.

Junk Folder Commands:
    python3 email_junk_cleaner.py scan              # Categorize junk folder
    python3 email_junk_cleaner.py delete-spam        # Delete definite + probably spam
    python3 email_junk_cleaner.py delete-all         # Delete everything in junk

Inbox Cleanup Commands:
    python3 email_junk_cleaner.py inbox-stats        # Census of all Inbox senders
    python3 email_junk_cleaner.py inbox-scan         # Classify emails using whitelist
    python3 email_junk_cleaner.py inbox-delete       # Delete classified emails (batch)
    python3 email_junk_cleaner.py inbox-delete --dry-run  # Preview without deleting
"""

import os
import sys
import json
import re
import webbrowser
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from collections import defaultdict

import msal
import requests
from dotenv import load_dotenv

# ── Config ──────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_DIR = Path.home() / ".config" / "emailjunkcleaner"
ENV_PATH = CONFIG_DIR / ".env"
load_dotenv(ENV_PATH)

CLIENT_ID = os.getenv("MS_CLIENT_ID")
CLIENT_SECRET = os.getenv("MS_CLIENT_SECRET")
TENANT_ID = os.getenv("MS_TENANT_ID")
AUTHORITY = f"https://login.microsoftonline.com/consumers"
SCOPES = ["Mail.ReadWrite"]
REDIRECT_URI = "http://localhost:8400"
TOKEN_CACHE_PATH = CONFIG_DIR / ".ms_token_cache.json"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# ── Known spam patterns ─────────────────────────────────────────────────────

SPAM_DOMAIN_KEYWORDS = [
    "promo", "deals", "offer", "marketing", "newsletter", "noreply",
    "bulk", "campaign", "info@", "sales@", "mailer", "notify",
]

SPAM_SUBJECT_PATTERNS = [
    r"(?i)\bfree\b.*\b(gift|money|prize|win|cash|offer)\b",
    r"(?i)\b(act now|limited time|urgent|congratulations|you.?ve been selected)\b",
    r"(?i)\b(unsubscribe|click here|buy now|order now|sign up)\b",
    r"(?i)\b(viagra|cialis|crypto|bitcoin|forex|trading signal)\b",
    r"(?i)\b(weight loss|diet pill|miracle cure)\b",
    r"(?i)^(re|fw):\s*(re|fw):\s*(re|fw):",  # excessive forwarding chains
    r"(?i)\b(invoice|payment|wire transfer|western union)\b.*\b(attach|click)\b",
    r"(?i)(automatic reply|auto.?reply|respuesta autom|r.ponse automatique|balasan otomatis|automatische antwort|automatyczna odpowied|trả lời tự động|自动答复|การตอบกลับอัตโนมัติ|resposta autom)",
    r"(?i)(gelatin|prostate|testosterone|semaglutide|GLP.1|tinnitus|ear ringing|neuropathy)",
    r"(?i)(starbucks.*bearista|hello kitty|yeti.*rambler|riverbend ranch|omaha steaks.*giveaway)",
    r"(?i)(oral.b.*kit|garmin.*dash cam|kobalt.*tool|car emergency kit|health monitoring kit)",
    r"(?i)(grounded.*footwear|polarvisi|signature scent.*gift)",
    r"(?i)(for-U\s*$)",  # common spam subject
    r"(?i)^\s*[A-Z]\.[a-z]+\.[a-z]+",  # obfuscated words like "S.te.ak.s", "St.arbu.cks"
    r"(?i)(claim your|grab your|you qualify for a free)",
    r"(?i)(billing.*error|account.*expired|backup failed.*storage)",
]

# Domains known to send spam from hacked/compromised accounts
SPAM_SENDER_DOMAINS = [
    "smanegeri4kendari.onmicrosoft.com",  # health scam operation
    "onedrive5tb.com",
    "cs365.fun",
    "3658.pro",
    "lwv.me",
    "mya3.me",
]

LEGIT_DOMAINS = [
    "microsoft.com", "outlook.com", "live.com", "hotmail.com",
    "google.com", "gmail.com", "apple.com", "amazon.com",
    "paypal.com", "bank", "chase.com", "wellsfargo.com",
    "linkedin.com", "github.com", "indeed.com", "glassdoor.com",
    "lever.co", "greenhouse.io", "workday.com",  # job search related
    "slack.com", "epiqnotice.com",  # notifications & legal
    "themavengroup.com", "abbtech.com", "kforce.com",  # recruiters
    "obrajobs.com", "gijobs.com",  # job boards
    "wgu.edu", "acilearning.com", "veteransunited.com",  # education/veteran
    "govdelivery.dmv.virginia.gov",  # government
    "alstspecials.com",  # toyota service
    "link.com",  # login notifications
]

RECEIPT_PATTERNS = [
    r"(?i)(order confirm|order receipt|shipping confirm|delivery confirm|"
    r"your order|purchase receipt|payment confirm|transaction confirm)",
]

FINANCIAL_PATTERNS = [
    r"(?i)(bank statement|account statement|tax return|W-2|1099|"
    r"tax document|annual statement|quarterly statement|"
    r"mortgage statement|loan statement)",
]

# ── Auth ────────────────────────────────────────────────────────────────────

auth_code_result = {}

class AuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if "code" in query:
            auth_code_result["code"] = query["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h2>Authenticated! You can close this tab.</h2>")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Authentication failed.")

    def log_message(self, format, *args):
        pass  # suppress logs


def get_msal_app():
    cache = msal.SerializableTokenCache()
    if TOKEN_CACHE_PATH.exists():
        cache.deserialize(TOKEN_CACHE_PATH.read_text())

    app = msal.PublicClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        token_cache=cache,
    )
    return app, cache


def authenticate():
    app, cache = get_msal_app()

    # Try cached token first
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result and "access_token" in result:
            return result["access_token"]

    # Device code flow — more reliable than localhost redirect
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        print(f"ERROR: Could not initiate device flow. {flow.get('error_description', '')}")
        sys.exit(1)

    print(f"\n{flow['message']}\n")
    webbrowser.open(flow["verification_uri"])

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        print(f"ERROR: {result.get('error_description', 'Unknown auth error')}")
        sys.exit(1)

    # Save cache
    if cache.has_state_changed:
        TOKEN_CACHE_PATH.write_text(cache.serialize())

    return result["access_token"]


# ── Graph API helpers ───────────────────────────────────────────────────────

def graph_get(token, endpoint, params=None):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{GRAPH_BASE}{endpoint}", headers=headers, params=params)
    r.raise_for_status()
    return r.json()


def graph_post(token, endpoint, body=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    r = requests.post(f"{GRAPH_BASE}{endpoint}", headers=headers, json=body)
    r.raise_for_status()
    return r


def graph_delete(token, endpoint):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.delete(f"{GRAPH_BASE}{endpoint}", headers=headers)
    r.raise_for_status()


def graph_batch(token, requests_list):
    """Send a batch of up to 20 Graph API operations in one call.

    requests_list: list of dicts with keys: id, method, url, body (optional), headers (optional)
    Returns list of response dicts with keys: id, status, body
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"requests": requests_list}
    r = requests.post(f"{GRAPH_BASE}/$batch", headers=headers, json=payload)
    r.raise_for_status()
    return r.json().get("responses", [])


def get_all_messages(token, folder, fields, max_messages=None):
    """Fetch all messages from a mail folder, paginating automatically.

    folder: 'Inbox', 'SentItems', 'JunkEmail', etc.
    fields: comma-separated string of fields to select
    max_messages: optional cap on total messages to fetch
    Returns list of message dicts.
    """
    messages = []
    endpoint = f"/me/mailFolders/{folder}/messages"
    params = {
        "$top": 250,
        "$select": fields,
        "$orderby": "receivedDateTime desc",
    }
    page = 0

    while endpoint:
        page += 1
        data = graph_get(token, endpoint, params)
        batch = data.get("value", [])
        messages.extend(batch)

        if page % 10 == 0:
            print(f"  Fetched {len(messages)} messages so far...")

        if max_messages and len(messages) >= max_messages:
            messages = messages[:max_messages]
            break

        next_link = data.get("@odata.nextLink")
        if next_link:
            endpoint = next_link.replace(GRAPH_BASE, "")
            params = None  # params baked into nextLink
        else:
            break

    return messages


def get_junk_emails(token, top=200):
    """Fetch emails from the Junk Email folder."""
    emails = []
    endpoint = "/me/mailFolders/JunkEmail/messages"
    params = {
        "$top": min(top, 50),
        "$select": "id,subject,from,receivedDateTime,isRead,body",
        "$orderby": "receivedDateTime desc",
    }

    while endpoint and len(emails) < top:
        data = graph_get(token, endpoint, params)
        emails.extend(data.get("value", []))
        next_link = data.get("@odata.nextLink")
        if next_link:
            endpoint = next_link.replace(GRAPH_BASE, "")
            params = None  # params are in the nextLink
        else:
            break

    return emails[:top]


# ── Classification ──────────────────────────────────────────────────────────

def classify_email(email):
    """Returns: 'definite_spam', 'probably_spam', or 'review'."""
    sender_email = email.get("from", {}).get("emailAddress", {}).get("address", "").lower()
    sender_name = email.get("from", {}).get("emailAddress", {}).get("name", "").lower()
    subject = email.get("subject", "") or ""
    spam_score = 0

    # Check if sender domain is in legit list
    sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    # Known spam sender domains — check BEFORE legit domains
    for spam_domain in SPAM_SENDER_DOMAINS:
        if spam_domain in sender_domain:
            return "definite_spam"

    # Catch SMANEGERI subdomains (e.g. Breaking-News.xxx.SMANEGERI4KENDARI.ONMICROSOFT.COM)
    if "smanegeri4kendari" in sender_domain.lower():
        return "definite_spam"

    # Catch suspicious .onmicrosoft.com auto-reply senders (hacked accounts)
    if sender_domain.lower().endswith(".onmicrosoft.com") and sender_domain.lower() not in [
        "apx365.onmicrosoft.com",  # known recruiter
    ]:
        subject_looks_spammy = bool(re.search(
            r"(?i)(automatic reply|auto.?reply|respuesta autom|balasan otomatis|automatische antwort|automatyczna odpowied|grab your|claim your|starbucks|hello kitty|grounded|footwear|oral.b|garmin|kobalt|S\.te\.ak|St\.arbu|Ha\.rry|Sy\.nGa|for-U)",
            subject
        ))
        if subject_looks_spammy:
            return "definite_spam"

    # Legit domain check
    for legit in LEGIT_DOMAINS:
        if legit in sender_domain:
            return "review"  # Don't auto-delete known domains

    # Hacked .edu/.gov accounts sending auto-replies are spam
    is_edu_gov = any(ext in sender_domain for ext in [".edu", ".gov", ".sch.", ".ac."])
    subject_is_autoreply = bool(re.search(
        r"(?i)(automatic reply|auto.?reply|respuesta autom|r.ponse automatique|balasan otomatis|automatische antwort|automatyczna odpowied|trả lời tự động|自动答复|การตอบกลับอัตโนมัติ|resposta autom)",
        subject
    ))
    if is_edu_gov and subject_is_autoreply:
        return "definite_spam"

    # Spam domain keyword check
    for keyword in SPAM_DOMAIN_KEYWORDS:
        if keyword in sender_email:
            spam_score += 2

    # Subject pattern check
    for pattern in SPAM_SUBJECT_PATTERNS:
        if re.search(pattern, subject):
            spam_score += 3

    # Sender name matches common spam patterns
    if sender_name and any(w in sender_name for w in ["admin", "support", "team", "winner"]):
        spam_score += 1

    # Fake invoice/billing scams from random addresses
    if re.search(r"(?i)(invoice|receipt|billing.*update|payment.*information|signed declaration|placing.*order)", subject):
        spam_score += 3

    # Random .com.tr, weird domains
    if re.search(r"\.(com\.tr|pro|fun|life|net)$", sender_domain) and not any(l in sender_domain for l in LEGIT_DOMAINS):
        spam_score += 2

    # No subject
    if not subject.strip():
        spam_score += 2

    # Classify
    if spam_score >= 5:
        return "definite_spam"
    elif spam_score >= 2:
        return "probably_spam"
    else:
        return "review"


# ── Actions ─────────────────────────────────────────────────────────────────

def scan_junk(token):
    """Scan and categorize junk folder."""
    print("Fetching junk emails...")
    emails = get_junk_emails(token)

    if not emails:
        print("Your junk folder is empty!")
        return

    categories = defaultdict(list)
    for email in emails:
        cat = classify_email(email)
        sender = email.get("from", {}).get("emailAddress", {}).get("address", "unknown")
        subject = email.get("subject", "(no subject)")
        categories[cat].append({
            "id": email["id"],
            "sender": sender,
            "subject": subject[:80],
            "date": email.get("receivedDateTime", "")[:10],
        })

    # Print summary
    print(f"\n{'='*70}")
    print(f"JUNK FOLDER SCAN — {len(emails)} emails analyzed")
    print(f"{'='*70}")

    for cat, label, color in [
        ("definite_spam", "DEFINITE SPAM (safe to auto-delete)", ""),
        ("probably_spam", "PROBABLY SPAM (likely safe to delete)", ""),
        ("review", "NEEDS REVIEW (might be legitimate)", ""),
    ]:
        items = categories[cat]
        print(f"\n--- {label}: {len(items)} emails ---")

        # Group by sender
        by_sender = defaultdict(list)
        for item in items:
            by_sender[item["sender"]].append(item)

        for sender, sender_items in sorted(by_sender.items(), key=lambda x: -len(x[1])):
            print(f"  [{len(sender_items):>3}] {sender}")
            for item in sender_items[:3]:  # Show up to 3 subjects per sender
                print(f"        └─ {item['date']}  {item['subject']}")
            if len(sender_items) > 3:
                print(f"        └─ ... and {len(sender_items) - 3} more")

    # Save full results for delete commands
    results_path = CONFIG_DIR / "junk_scan_results.json"
    results_path.parent.mkdir(exist_ok=True)
    results_path.write_text(json.dumps(categories, indent=2))
    print(f"\nFull results saved to {results_path}")
    print(f"\nNext steps:")
    print(f"  python3 tools/email_junk_cleaner.py delete-spam    # Delete definite + probably spam")
    print(f"  python3 tools/email_junk_cleaner.py delete-all     # Delete everything in junk")


def delete_emails(token, category_filter):
    """Delete emails by category from last scan."""
    results_path = CONFIG_DIR / "junk_scan_results.json"
    if not results_path.exists():
        print("No scan results found. Run 'scan' first.")
        sys.exit(1)

    categories = json.loads(results_path.read_text())

    ids_to_delete = []
    if category_filter == "spam":
        ids_to_delete = [e["id"] for e in categories.get("definite_spam", [])]
        ids_to_delete += [e["id"] for e in categories.get("probably_spam", [])]
        label = "definite + probably spam"
    elif category_filter == "all":
        for cat_items in categories.values():
            ids_to_delete += [e["id"] for e in cat_items]
        label = "all junk"
    else:
        print(f"Unknown filter: {category_filter}")
        sys.exit(1)

    if not ids_to_delete:
        print("No emails to delete.")
        return

    print(f"Deleting {len(ids_to_delete)} emails ({label})...")

    deleted = 0
    errors = 0
    for i, email_id in enumerate(ids_to_delete):
        try:
            graph_delete(token, f"/me/messages/{email_id}")
            deleted += 1
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                deleted += 1  # Already gone
            else:
                errors += 1
                print(f"  Error deleting email: {e}")

        if (i + 1) % 20 == 0:
            print(f"  Progress: {i + 1}/{len(ids_to_delete)}")
            time.sleep(0.5)  # Rate limit courtesy

    print(f"\nDone! Deleted: {deleted}, Errors: {errors}")


def classify_sender(address, count, you_replied):
    """Auto-classify a sender for the whitelist.

    Returns: 'keep', 'delete', or 'undecided'
    """
    domain = address.split("@")[-1] if "@" in address else ""

    # User replied → keep
    if you_replied:
        return "keep"

    # Known legit domain + no reply → undecided
    for legit in LEGIT_DOMAINS:
        if legit in domain:
            return "undecided"

    # Spam domain keywords → delete
    for keyword in SPAM_DOMAIN_KEYWORDS:
        if keyword in address:
            return "delete"

    # High volume, never replied → delete
    if count >= 50 and not you_replied:
        return "delete"

    # Low volume, never replied → undecided
    if count < 5 and not you_replied:
        return "undecided"

    # Everything else → undecided
    return "undecided"


def inbox_stats(token):
    """Scan Inbox, build sender census, generate starter whitelist."""
    print("Step 1/3: Fetching Sent Items conversation IDs for reply detection...")
    sent_messages = get_all_messages(token, "SentItems", "conversationId")
    sent_conversation_ids = set(
        m["conversationId"] for m in sent_messages if m.get("conversationId")
    )
    print(f"  Found {len(sent_conversation_ids)} unique conversations you replied to.\n")

    print("Step 2/3: Fetching all Inbox emails...")
    inbox_messages = get_all_messages(
        token, "Inbox", "id,from,receivedDateTime,subject,conversationId"
    )
    print(f"  Fetched {len(inbox_messages)} Inbox emails.\n")

    print("Step 3/3: Building sender census...")
    from datetime import datetime

    senders = {}
    email_index = []

    for msg in inbox_messages:
        addr = msg.get("from", {}).get("emailAddress", {}).get("address", "unknown").lower()
        name = msg.get("from", {}).get("emailAddress", {}).get("name", "")
        subject = msg.get("subject", "") or "(no subject)"
        date_str = (msg.get("receivedDateTime", "") or "")[:10]
        conv_id = msg.get("conversationId", "")
        replied = conv_id in sent_conversation_ids if conv_id else False

        email_index.append({
            "id": msg["id"],
            "sender": addr,
            "subject": subject[:100],
            "date": date_str,
            "conversationId": conv_id,
            "replied": replied,
        })

        if addr not in senders:
            senders[addr] = {
                "address": addr,
                "name": name,
                "count": 0,
                "oldest": date_str,
                "newest": date_str,
                "you_replied": False,
                "sample_subjects": [],
            }

        s = senders[addr]
        s["count"] += 1
        if date_str and (not s["oldest"] or date_str < s["oldest"]):
            s["oldest"] = date_str
        if date_str and (not s["newest"] or date_str > s["newest"]):
            s["newest"] = date_str
        if replied:
            s["you_replied"] = True
        if len(s["sample_subjects"]) < 3:
            s["sample_subjects"].append(subject[:80])

    # Auto-classify each sender
    for addr, s in senders.items():
        s["classification"] = classify_sender(addr, s["count"], s["you_replied"])

    # Sort by count descending
    sorted_senders = sorted(senders.values(), key=lambda x: -x["count"])

    # Save census
    census = {
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "total_emails": len(inbox_messages),
        "unique_senders": len(senders),
        "senders": sorted_senders,
    }
    census_path = CONFIG_DIR / "inbox_sender_census.json"
    census_path.write_text(json.dumps(census, indent=2))

    # Save email index (needed by inbox-scan)
    index_path = CONFIG_DIR / "inbox_email_index.json"
    index_path.write_text(json.dumps(email_index, indent=2))

    # Generate starter whitelist
    whitelist = {"keep": [], "delete": [], "undecided": []}
    for s in sorted_senders:
        whitelist[s["classification"]].append(s["address"])

    whitelist_path = CONFIG_DIR / "inbox_whitelist.json"
    if whitelist_path.exists():
        print(f"\n  WARNING: {whitelist_path} already exists. Not overwriting.")
        print(f"  Delete it first if you want a fresh whitelist.")
    else:
        whitelist_path.write_text(json.dumps(whitelist, indent=2))
        print(f"\n  Starter whitelist saved to {whitelist_path}")

    # Print ranked table
    print(f"\n{'='*70}")
    print(f"INBOX SENDER CENSUS — {len(inbox_messages):,} emails from {len(senders):,} unique senders")
    print(f"{'='*70}")
    print(f" {'Rank':>5}  {'Count':>6}  {'Replied?':<9}  {'Oldest':<11}  Sender")
    print(f" {'─'*5}  {'─'*6}  {'─'*9}  {'─'*11}  {'─'*30}")

    for i, s in enumerate(sorted_senders[:50], 1):
        replied_str = "Yes" if s["you_replied"] else "No"
        print(f" {i:>5}  {s['count']:>6}  {replied_str:<9}  {s['oldest']:<11}  {s['address']}")

    if len(sorted_senders) > 50:
        print(f"\n  ... and {len(sorted_senders) - 50} more senders (see full list in census file)")

    # Print classification summary
    keep_count = sum(1 for s in sorted_senders if s["classification"] == "keep")
    delete_count = sum(1 for s in sorted_senders if s["classification"] == "delete")
    undecided_count = sum(1 for s in sorted_senders if s["classification"] == "undecided")
    print(f"\n  Auto-classified senders: {keep_count} keep, {delete_count} delete, {undecided_count} undecided")
    print(f"\n  Census saved to {census_path}")
    print(f"  Email index saved to {index_path}")
    print(f"\n  Next: Edit {whitelist_path} to review sender classifications")
    print(f"  Then run: python3 email_junk_cleaner.py inbox-scan")


def inbox_scan(token):
    """Classify Inbox emails using whitelist + per-email rules."""
    from datetime import datetime, timedelta

    whitelist_path = CONFIG_DIR / "inbox_whitelist.json"
    index_path = CONFIG_DIR / "inbox_email_index.json"

    if not whitelist_path.exists():
        print(f"No whitelist found at {whitelist_path}")
        print("Run 'inbox-stats' first, then edit the whitelist.")
        sys.exit(1)

    if not index_path.exists():
        print(f"No email index found at {index_path}")
        print("Run 'inbox-stats' first.")
        sys.exit(1)

    whitelist = json.loads(whitelist_path.read_text())
    email_index = json.loads(index_path.read_text())

    keep_set = set(whitelist.get("keep", []))
    delete_set = set(whitelist.get("delete", []))
    undecided_set = set(whitelist.get("undecided", []))

    scan_date = datetime.now()
    one_year_ago = (scan_date - timedelta(days=365)).strftime("%Y-%m-%d")

    results = []
    counts = {"keep": 0, "delete": 0, "skipped": 0}
    delete_by_sender = defaultdict(int)
    keep_by_sender = defaultdict(int)

    for email in email_index:
        sender = email["sender"]
        subject = email.get("subject", "")
        date = email.get("date", "")
        replied = email.get("replied", False)
        action = None
        reason = None

        # Per-email override rules (checked first)

        # 1. Conversation user replied to → keep
        if replied:
            action = "keep"
            reason = "you replied in this conversation"

        # 2. Financial keywords → keep (any age)
        if not action:
            for pattern in FINANCIAL_PATTERNS:
                if re.search(pattern, subject):
                    action = "keep"
                    reason = "financial document"
                    break

        # 3. Recent receipt/order → keep (last 12 months only)
        if not action and date >= one_year_ago:
            for pattern in RECEIPT_PATTERNS:
                if re.search(pattern, subject):
                    action = "keep"
                    reason = "recent receipt/order"
                    break

        # 4. Sender-based classification from whitelist
        if not action:
            if sender in keep_set:
                action = "keep"
                reason = "sender in keep list"
            elif sender in delete_set:
                action = "delete"
                reason = "sender in delete list"
            else:
                action = "skipped"
                reason = "sender undecided"

        counts[action] += 1
        if action == "delete":
            delete_by_sender[sender] += 1
        elif action == "keep":
            keep_by_sender[sender] += 1

        results.append({
            "id": email["id"],
            "sender": sender,
            "subject": subject[:80],
            "date": date,
            "action": action,
            "reason": reason,
        })

    # Save results
    scan_results = {
        "scan_date": scan_date.strftime("%Y-%m-%d"),
        "summary": {
            "total": len(email_index),
            "delete": counts["delete"],
            "keep": counts["keep"],
            "skipped": counts["skipped"],
        },
        "emails": results,
    }
    results_path = CONFIG_DIR / "inbox_scan_results.json"
    results_path.write_text(json.dumps(scan_results, indent=2))

    # Print summary
    print(f"\n{'='*50}")
    print(f"INBOX SCAN RESULTS")
    print(f"{'='*50}")
    print(f"  Delete:  {counts['delete']:>8,} emails")
    print(f"  Keep:    {counts['keep']:>8,} emails")
    print(f"  Skipped: {counts['skipped']:>8,} emails (undecided senders)")
    print(f"  Total:   {len(email_index):>8,} emails")

    # Top senders being deleted
    sorted_delete = sorted(delete_by_sender.items(), key=lambda x: -x[1])
    if sorted_delete:
        print(f"\nTOP SENDERS BEING DELETED:")
        for sender, count in sorted_delete[:10]:
            print(f"  {count:>6,}  {sender}")

    # Top senders being kept
    sorted_keep = sorted(keep_by_sender.items(), key=lambda x: -x[1])
    if sorted_keep:
        print(f"\nTOP SENDERS BEING KEPT:")
        for sender, count in sorted_keep[:10]:
            print(f"  {count:>6,}  {sender}")

    print(f"\n  Results saved to {results_path}")
    print(f"\n  Next steps:")
    print(f"    python3 email_junk_cleaner.py inbox-delete --dry-run  # Preview")
    print(f"    python3 email_junk_cleaner.py inbox-delete            # Delete")


def inbox_delete(token, dry_run=False):
    """Batch-delete Inbox emails tagged 'delete', moving them to Deleted Items."""
    from datetime import datetime

    results_path = CONFIG_DIR / "inbox_scan_results.json"
    if not results_path.exists():
        print("No scan results found. Run 'inbox-scan' first.")
        sys.exit(1)

    scan_results = json.loads(results_path.read_text())
    to_delete = [e for e in scan_results["emails"] if e["action"] == "delete"]

    if not to_delete:
        print("No emails marked for deletion.")
        return

    # Check for resume — skip already-processed IDs
    log_path = CONFIG_DIR / "inbox_delete_log.json"
    already_deleted = set()
    if log_path.exists():
        log_data = json.loads(log_path.read_text())
        already_deleted = set(log_data.get("deleted_ids", []))
        if already_deleted:
            before = len(to_delete)
            to_delete = [e for e in to_delete if e["id"] not in already_deleted]
            print(f"  Resuming: skipping {before - len(to_delete)} already-processed emails.")

    if not to_delete:
        print("All emails from the scan have already been processed.")
        return

    # Dry run
    if dry_run:
        print(f"\n{'='*50}")
        print(f"DRY RUN — would delete {len(to_delete):,} emails")
        print(f"{'='*50}")
        by_sender = defaultdict(int)
        for e in to_delete:
            by_sender[e["sender"]] += 1
        sorted_senders = sorted(by_sender.items(), key=lambda x: -x[1])
        print(f"\nTop senders:")
        for sender, count in sorted_senders[:20]:
            print(f"  {count:>6,}  {sender}")
        print(f"\nNo emails were touched. Remove --dry-run to execute.")
        return

    # Confirmation
    print(f"\nAbout to move {len(to_delete):,} emails to Deleted Items.")
    confirm = input("Type YES to proceed: ")
    if confirm.strip() != "YES":
        print("Aborted.")
        return

    # Batch delete
    print(f"\nDeleting {len(to_delete):,} emails in batches of 20...")
    deleted_ids = list(already_deleted)
    errors = []
    total_batches = (len(to_delete) + 19) // 20

    batch_num = 0
    while batch_num < total_batches:
        start = batch_num * 20
        end = min(start + 20, len(to_delete))
        batch_emails = to_delete[start:end]

        batch_requests = []
        for i, email in enumerate(batch_emails):
            batch_requests.append({
                "id": str(i),
                "method": "POST",
                "url": f"/me/messages/{email['id']}/move",
                "body": {"destinationId": "DeletedItems"},
                "headers": {"Content-Type": "application/json"},
            })

        try:
            responses = graph_batch(token, batch_requests)
            for resp in responses:
                idx = int(resp["id"])
                email_id = batch_emails[idx]["id"]
                status = resp.get("status", 0)
                if 200 <= status < 300:
                    deleted_ids.append(email_id)
                elif status == 404:
                    deleted_ids.append(email_id)  # already gone
                else:
                    error_body = resp.get("body", {})
                    error_msg = error_body.get("error", {}).get("message", f"HTTP {status}")
                    errors.append({"id": email_id, "error": error_msg})
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                retry_after = int(e.response.headers.get("Retry-After", 30))
                print(f"  Rate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                continue  # retry same batch_num
            else:
                print(f"  Batch error: {e}")
                for email in batch_emails:
                    errors.append({"id": email["id"], "error": str(e)})

        # Progress update
        if (batch_num + 1) % 100 == 0 or batch_num == total_batches - 1:
            print(f"  Progress: {min(end, len(to_delete)):,}/{len(to_delete):,} "
                  f"({len(deleted_ids) - len(already_deleted)} deleted, {len(errors)} errors)")

        batch_num += 1
        time.sleep(0.5)  # rate limit courtesy

    # Save log
    log_data = {
        "started": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_requested": len(to_delete),
        "deleted": len(deleted_ids) - len(already_deleted),
        "errors": len(errors),
        "error_details": errors[:100],  # cap error details
        "deleted_ids": deleted_ids,
    }
    log_path.write_text(json.dumps(log_data, indent=2))

    print(f"\nDone! Moved {len(deleted_ids) - len(already_deleted):,} emails to Deleted Items. "
          f"Errors: {len(errors)}.")
    print(f"  Log saved to {log_path}")
    if errors:
        print(f"  First error: {errors[0]['error']}")


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()
    token = authenticate()

    if command == "scan":
        scan_junk(token)
    elif command == "delete-spam":
        delete_emails(token, "spam")
    elif command == "delete-all":
        delete_emails(token, "all")
    elif command == "inbox-stats":
        inbox_stats(token)
    elif command == "inbox-scan":
        inbox_scan(token)
    elif command == "inbox-delete":
        dry_run = "--dry-run" in sys.argv
        inbox_delete(token, dry_run=dry_run)
    else:
        print(f"Unknown command: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
