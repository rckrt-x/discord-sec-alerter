#!/usr/bin/env python3
import os
import json
import time
import requests
import feedparser
from datetime import datetime, timezone

# Webhook sicher aus den GitHub Secrets laden
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL")
STATE_FILE = "seen_vulns.json"

# Optional: Deine Watchlist für High-Severity Lücken (Critical >= 9.0 wird IMMER gemeldet)
WATCHLIST_KEYWORDS = [
    "php", "debian", "ubuntu", "linux", "kernel", "nginx", "mariadb", 
    "proxmox", "docker", "synology", "ubiquiti", "unifi", "fritz!box", 
    "airwatch", "workspace one", "ios", "wordpress", "mailcow", "openssh"
]
MIN_CVSS_GLOBAL = 9.0

def load_seen():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_seen(seen_set):
    # Nur die letzten 1000 IDs behalten, damit die Datei winzig bleibt
    seen_list = list(seen_set)[-1000:]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(seen_list, f)

def send_discord_embed(title, description, url, severity, cvss_score, source, cve_id="N/A"):
    color = 0xE74C3C if cvss_score >= 9.0 or "kritisch" in severity.lower() else 0xE67E22

    payload = {
        "username": "Security Watchdog",
        "embeds": [{
            "title": f"🚨 {title[:240]}",
            "url": url,
            "description": description[:1500] + ("..." if len(description) > 1500 else ""),
            "color": color,
            "fields": [
                {"name": "Kennung / CVE", "value": f"`{cve_id}`", "inline": True},
                {"name": "Einstufung", "value": f"**{severity.upper()}** (CVSS: {cvss_score})", "inline": True},
                {"name": "Quelle", "value": source, "inline": True}
            ],
            "footer": {"text": f"Erfasst am {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}"}
        }]
    }
    
    resp = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
    if resp.status_code == 429:
        retry_after = resp.json().get("retry_after", 5)
        time.sleep(float(retry_after) + 1)
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=10)
    time.sleep(1.5)

def check_github_advisories(seen, is_first_run):
    url = "https://api.github.com/advisories?per_page=30&sort=published&direction=desc"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    
    # Falls GITHUB_TOKEN vorhanden ist, erhöht das das API-Limit auf 1000 Requests/Stunde
    gh_token = os.environ.get("GITHUB_TOKEN")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    try:
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()
        advisories = r.json()
    except Exception as e:
        print(f"[Fehler] GitHub API: {e}")
        return

    sent_count = 0
    for adv in reversed(advisories):
        ghsa_id = adv.get("ghsa_id")
        if ghsa_id in seen:
            continue

        cve_id = adv.get("cve_id") or ghsa_id
        severity = adv.get("severity", "unknown")
        summary = adv.get("summary", "Keine Zusammenfassung verfügbar.")
        description = adv.get("description", "")
        html_url = adv.get("html_url", "")
        
        cvss_score = float(adv["cvss"]["score"]) if adv.get("cvss") and adv["cvss"].get("score") else 0.0
        text_corpus = f"{summary} {description}".lower()
        matches_keyword = any(kw in text_corpus for kw in WATCHLIST_KEYWORDS)

        if cvss_score >= MIN_CVSS_GLOBAL or (matches_keyword and severity in ["critical", "high"]):
            # Beim allerersten Start max. 3 Meldungen senden, um Discord nicht zu fluten
            if not is_first_run or sent_count < 3:
                send_discord_embed(
                    title=summary,
                    description=description,
                    url=html_url,
                    severity=severity,
                    cvss_score=cvss_score,
                    source="GitHub Advisory (GHSA)",
                    cve_id=f"{cve_id} / {ghsa_id}"
                )
                sent_count += 1
        
        seen.add(ghsa_id)

def check_cert_bund(seen, is_first_run):
    feed_url = "https://wid.cert-bund.de/content/public/securityAdvisory/rss"
    try:
        feed = feedparser.parse(feed_url)
    except Exception as e:
        print(f"[Fehler] CERT-Bund RSS: {e}")
        return

    sent_count = 0
    for entry in reversed(feed.entries[:25]):
        wid_id = entry.get("id", entry.get("link"))
        if wid_id in seen:
            continue

        title = entry.get("title", "")
        summary = entry.get("summary", "")
        link = entry.get("link", "")
        text_corpus = f"{title} {summary}".lower()

        is_critical = "kritisch" in text_corpus
        matches_keyword = any(kw in text_corpus for kw in WATCHLIST_KEYWORDS)

        if is_critical or (matches_keyword and "hoch" in text_corpus):
            if not is_first_run or sent_count < 3:
                sev_label = "Kritisch" if is_critical else "Hoch"
                send_discord_embed(
                    title=title,
                    description=summary,
                    url=link,
                    severity=sev_label,
                    cvss_score=9.0 if is_critical else 7.5,
                    source="BSI CERT-Bund (WID)",
                    cve_id=title.split("]")[0].replace("[", "") if "]" in title else "WID-Advisory"
                )
                sent_count += 1

        seen.add(wid_id)

if __name__ == "__main__":
    if not DISCORD_WEBHOOK_URL:
        raise ValueError("DISCORD_WEBHOOK_URL fehlt! Bitte als GitHub Secret anlegen.")
    
    seen_ids = load_seen()
    first_run = len(seen_ids) == 0
    
    check_github_advisories(seen_ids, first_run)
    check_cert_bund(seen_ids, first_run)
    
    save_seen(seen_ids)
