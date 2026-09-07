#!/usr/bin/env python3
"""
Veritas Cloud Monitor
- Designed for GitHub Actions, so your Mac can be off.
- Crawls theveritassearch.com and discovered subdomains.
- Detects changes to response bytes, rendered DOM, screenshots, APIs/assets,
  stable headers/statuses, DNS, TLS certs, WebSockets, console/errors, etc.
- Discovers subdomains from certificate transparency plus the site itself.
- Sends a test notification when the first baseline is created.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from collections import deque
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urldefrag, urlparse

from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

SCHEMA_VERSION = 3
BASE_DOMAIN = "theveritassearch.com"
ROOT_URLS = [
    "https://theveritassearch.com/",
    "https://www.theveritassearch.com/",
]

STATE_DIR = Path("state")
MANIFEST_FILE = STATE_DIR / "manifest.json"
REPORT_FILE = STATE_DIR / "last_report.md"
HEARTBEAT_FILE = STATE_DIR / "heartbeat.txt"

MAX_PAGES = int(os.getenv("MAX_PAGES", "5000"))
SETTLE_MS = int(os.getenv("SETTLE_MS", "2000"))
NAV_TIMEOUT_MS = int(os.getenv("NAV_TIMEOUT_MS", "30000"))
STRICT_HEADERS = os.getenv("STRICT_HEADERS", "0").lower() in {"1", "true", "yes"}

# These change routinely even when the underlying site has not changed.
# STRICT_HEADERS=1 includes them, but will usually alert on every run.
VOLATILE_HEADERS = {
    "date", "age", "expires", "last-modified",
    "set-cookie", "cookie",
    "cf-ray", "cf-cache-status",
    "x-request-id", "x-amzn-trace-id", "x-vercel-id",
    "x-vercel-cache", "x-fastly-request-id", "x-github-request-id",
    "x-timer", "x-served-by", "x-cache", "x-cache-hits", "source-age",
    "server-timing", "traceparent", "tracestate",
    "nel", "report-to",
}

COMMON_PROBES = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap-index.xml",
    "/wp-sitemap.xml",
    "/manifest.json",
    "/site.webmanifest",
    "/favicon.ico",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
]

TEXT_CONTENT_HINTS = (
    "text/", "json", "javascript", "xml", "svg", "css",
    "graphql", "x-www-form-urlencoded"
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utcnow().isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_json_hash(obj: Any) -> str:
    return sha256_bytes(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    )


def normalize_url(url: str, base: str | None = None) -> str | None:
    if not url:
        return None
    if base:
        url = urljoin(base, url)
    url, _ = urldefrag(url)
    try:
        p = urlparse(url)
    except Exception:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None

    host = p.hostname.lower()
    default_port = (p.scheme == "https" and p.port == 443) or (p.scheme == "http" and p.port == 80)
    netloc = host if (p.port is None or default_port) else f"{host}:{p.port}"
    path = p.path or "/"
    return p._replace(
        scheme=p.scheme.lower(),
        netloc=netloc,
        path=path,
        fragment=""
    ).geturl()


def is_in_scope(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return host == BASE_DOMAIN or host.endswith("." + BASE_DOMAIN)
    except Exception:
        return False


def host_from_url(url: str) -> str | None:
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:
        return None


def filtered_headers(headers: dict[str, str]) -> dict[str, str]:
    normalized = {str(k).lower(): str(v) for k, v in headers.items()}
    if STRICT_HEADERS:
        return dict(sorted(normalized.items()))
    return dict(sorted(
        (k, v) for k, v in normalized.items()
        if k not in VOLATILE_HEADERS
    ))


def normalize_runtime_text(text: str) -> str:
    """Remove browser/runtime IDs that change despite identical site behavior."""
    text = re.sub(r"0x[0-9a-fA-F]+", "0x<RUNTIME>", text)
    text = re.sub(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        "<UUID>",
        text,
    )
    text = re.sub(r"blob:https?://[^/]+/[0-9a-fA-F-]+", "blob:<RUNTIME>", text)
    return text


async def stable_screenshot_record(page) -> dict[str, Any]:
    """
    Take two screenshots. If the pixels are identical, keep the exact hash.
    If the page is actively animated/WebGL-dynamic, record only that fact so
    random frames do not create a false alarm every five minutes.
    """
    shot1 = await page.screenshot(full_page=True, animations="disabled")
    await page.wait_for_timeout(300)
    shot2 = await page.screenshot(full_page=True, animations="disabled")
    h1, h2 = sha256_bytes(shot1), sha256_bytes(shot2)
    if h1 == h2:
        return {"stable": True, "sha256": h1, "bytes": len(shot1)}
    return {"stable": False, "dynamic_pixels": True}


def body_record(body: bytes, content_type: str = "") -> dict[str, Any]:
    # The full body is always hashed. We only store a tiny preview for text
    # so reports/state do not balloon with images/video/bundles.
    record: dict[str, Any] = {
        "sha256": sha256_bytes(body),
        "bytes": len(body),
    }
    low = (content_type or "").lower()
    if any(hint in low for hint in TEXT_CONTENT_HINTS) and len(body) <= 100_000:
        try:
            text = body.decode("utf-8", "replace")
            record["text_preview"] = text[:4000]
        except Exception:
            pass
    return record


def request_identity(method: str, url: str, post_data: str | bytes | None = None) -> str:
    suffix = ""
    if post_data:
        raw = post_data if isinstance(post_data, bytes) else str(post_data).encode()
        suffix = f" body={sha256_bytes(raw)[:16]}"
    return f"{method.upper()} {url}{suffix}"


def discover_certificate_transparency_hosts() -> set[str]:
    """
    Public certificate-transparency discovery.
    This finds many public TLS subdomains, but no technique can guarantee every
    secret/non-public DNS name.
    """
    hosts = {BASE_DOMAIN, "www." + BASE_DOMAIN}
    q = urllib.parse.quote(f"%.{BASE_DOMAIN}", safe="")
    url = f"https://crt.sh/?q={q}&output=json"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "VeritasChangeMonitor/3.0"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            rows = json.loads(r.read().decode("utf-8", "replace"))
        for row in rows:
            for field in ("name_value", "common_name"):
                value = row.get(field, "")
                for name in str(value).splitlines():
                    name = name.strip().lower().rstrip(".")
                    if name.startswith("*."):
                        name = name[2:]
                    if name == BASE_DOMAIN or name.endswith("." + BASE_DOMAIN):
                        # Reject obviously malformed wildcard fragments.
                        if "*" not in name and "/" not in name and " " not in name:
                            hosts.add(name)
    except Exception as e:
        print(f"[ct] certificate-transparency lookup failed: {e!r}")
    return hosts


def dns_snapshot(host: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        rows = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        out["addresses"] = sorted({r[4][0] for r in rows})
    except Exception as e:
        out["dns_error"] = repr(e)
    return out


def tls_snapshot(host: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                out["certificate_sha256"] = sha256_bytes(der)
                out["subject"] = cert.get("subject")
                out["issuer"] = cert.get("issuer")
                out["notBefore"] = cert.get("notBefore")
                out["notAfter"] = cert.get("notAfter")
    except Exception as e:
        out["tls_error"] = repr(e)
    return out


def infra_snapshot(hosts: set[str]) -> dict[str, Any]:
    result = {}
    for host in sorted(hosts):
        result[host] = {
            "dns": dns_snapshot(host),
            "tls": tls_snapshot(host),
        }
    return result


def parse_sitemap_urls(data: bytes) -> list[str]:
    # Regex is deliberately forgiving of malformed namespace/XML formatting.
    text = data.decode("utf-8", "replace")
    return [
        m.strip()
        for m in re.findall(r"<loc>\s*(.*?)\s*</loc>", text, flags=re.I | re.S)
        if m.strip()
    ]


def parse_robots_sitemaps(data: bytes) -> list[str]:
    text = data.decode("utf-8", "replace")
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*Sitemap\s*:\s*(\S+)", line, flags=re.I)
        if m:
            out.append(m.group(1))
    return out


async def autoscroll(page) -> None:
    # Helps trigger lazy-loaded images/resources.
    try:
        await page.evaluate(
            """
            async () => {
              const step = Math.max(400, Math.floor(window.innerHeight * 0.8));
              for (let y = 0; y < document.body.scrollHeight; y += step) {
                window.scrollTo(0, y);
                await new Promise(r => setTimeout(r, 80));
              }
              window.scrollTo(0, document.body.scrollHeight);
              await new Promise(r => setTimeout(r, 250));
              window.scrollTo(0, 0);
            }
            """
        )
    except Exception:
        pass


def add_discovered_url(
    raw: str,
    base: str,
    queue: deque[str],
    queued: set[str],
    discovered_hosts: set[str],
) -> None:
    u = normalize_url(raw, base)
    if not u:
        return
    host = host_from_url(u)
    if host and (host == BASE_DOMAIN or host.endswith("." + BASE_DOMAIN)):
        discovered_hosts.add(host)
    if is_in_scope(u) and u not in queued:
        queued.add(u)
        queue.append(u)


async def crawl() -> dict[str, Any]:
    initial_hosts = discover_certificate_transparency_hosts()
    discovered_hosts = set(initial_hosts)

    queue: deque[str] = deque()
    queued: set[str] = set()

    for root in ROOT_URLS:
        u = normalize_url(root)
        if u and u not in queued:
            queue.append(u)
            queued.add(u)

    # Also probe the root of each CT-discovered host.
    for host in sorted(initial_hosts):
        u = normalize_url(f"https://{host}/")
        if u and u not in queued:
            queue.append(u)
            queued.add(u)

    manifest: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "base_domain": BASE_DOMAIN,
        "strict_headers": STRICT_HEADERS,
        "hosts": {},
        "pages": {},
        "resources": {},
    }

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-background-networking",
                "--disable-component-update",
                "--no-default-browser-check",
            ],
        )
        context = await browser.new_context(
            ignore_https_errors=False,
            viewport={"width": 1440, "height": 1000},
            color_scheme="light",
            reduced_motion="reduce",
            locale="en-US",
            timezone_id="America/New_York",
            user_agent="Mozilla/5.0 (compatible; VeritasChangeMonitor/3.0; public-site change monitor)",
        )

        # Fetch known metadata endpoints for every already-known host.
        for host in sorted(initial_hosts):
            for path in COMMON_PROBES:
                url = normalize_url(f"https://{host}{path}")
                if not url:
                    continue
                key = request_identity("GET", url)
                try:
                    resp = await context.request.get(
                        url,
                        timeout=20_000,
                        fail_on_status_code=False,
                    )
                    body = await resp.body()
                    hdrs = resp.headers
                    ctype = hdrs.get("content-type", "")
                    manifest["resources"][key] = {
                        "url": url,
                        "method": "GET",
                        "resource_type": "well-known-probe",
                        "status": resp.status,
                        "headers": filtered_headers(hdrs),
                        "body": body_record(body, ctype),
                    }

                    if "xml" in ctype.lower() or url.endswith(".xml"):
                        for raw in parse_sitemap_urls(body):
                            add_discovered_url(
                                raw, url, queue, queued, discovered_hosts
                            )
                    if url.endswith("/robots.txt"):
                        for raw in parse_robots_sitemaps(body):
                            add_discovered_url(
                                raw, url, queue, queued, discovered_hosts
                            )
                except Exception as e:
                    manifest["resources"][key] = {
                        "url": url,
                        "method": "GET",
                        "resource_type": "well-known-probe",
                        "error": repr(e),
                    }

        visited: set[str] = set()

        while queue and len(visited) < MAX_PAGES:
            requested_url = normalize_url(queue.popleft())
            if not requested_url or requested_url in visited or not is_in_scope(requested_url):
                continue

            visited.add(requested_url)
            print(f"[page {len(visited)}] {requested_url}", flush=True)

            page = await context.new_page()
            pending: set[asyncio.Task] = set()
            console_messages: list[dict[str, str]] = []
            page_errors: list[str] = []
            websocket_events: list[dict[str, Any]] = []

            async def capture_response(response):
                try:
                    raw_url = response.url
                    # blob:/data: URLs are runtime-local identities (often random UUIDs),
                    # not stable public resources. Their source bytes/JS/DOM are tracked
                    # elsewhere; keeping their random URL would alert every run.
                    if raw_url.startswith(("blob:", "data:")):
                        return
                    url = normalize_url(raw_url) or raw_url
                    req = response.request
                    method = req.method
                    post_data = req.post_data
                    key = request_identity(method, url, post_data)

                    try:
                        body = await response.body()
                    except Exception:
                        body = b""

                    try:
                        headers = await response.all_headers()
                    except Exception:
                        headers = {}

                    ctype = headers.get("content-type", "")
                    entry = {
                        "url": url,
                        "method": method,
                        "resource_type": req.resource_type,
                        "status": response.status,
                        "headers": filtered_headers(headers),
                        "body": body_record(body, ctype),
                    }

                    if post_data:
                        entry["request_body_sha256"] = sha256_bytes(post_data.encode())

                    manifest["resources"][key] = entry

                    host = host_from_url(url)
                    if host and (host == BASE_DOMAIN or host.endswith("." + BASE_DOMAIN)):
                        discovered_hosts.add(host)

                    # Network responses can themselves be sitemaps.
                    if is_in_scope(url) and (
                        "xml" in ctype.lower()
                        or url.endswith(".xml")
                        or "sitemap" in url.lower()
                    ):
                        for raw in parse_sitemap_urls(body):
                            add_discovered_url(
                                raw, url, queue, queued, discovered_hosts
                            )
                except Exception as e:
                    print(f"[response capture error] {response.url}: {e!r}", flush=True)

            def on_response(response):
                task = asyncio.create_task(capture_response(response))
                pending.add(task)
                task.add_done_callback(pending.discard)

            def on_console(msg):
                try:
                    console_messages.append({
                        "type": msg.type,
                        "text": normalize_runtime_text(msg.text[:2000]),
                    })
                except Exception:
                    pass

            def on_page_error(exc):
                page_errors.append(normalize_runtime_text(str(exc)[:4000]))

            def on_websocket(ws):
                item = {"url": ws.url, "received": [], "sent": []}
                websocket_events.append(item)

                def received(payload):
                    try:
                        raw = payload if isinstance(payload, bytes) else str(payload).encode()
                        item["received"].append({
                            "sha256": sha256_bytes(raw),
                            "bytes": len(raw),
                        })
                    except Exception:
                        pass

                def sent(payload):
                    try:
                        raw = payload if isinstance(payload, bytes) else str(payload).encode()
                        item["sent"].append({
                            "sha256": sha256_bytes(raw),
                            "bytes": len(raw),
                        })
                    except Exception:
                        pass

                ws.on("framereceived", received)
                ws.on("framesent", sent)

            page.on("response", on_response)
            page.on("console", on_console)
            page.on("pageerror", on_page_error)
            page.on("websocket", on_websocket)

            page_entry: dict[str, Any] = {"requested_url": requested_url}

            try:
                response = await page.goto(
                    requested_url,
                    wait_until="domcontentloaded",
                    timeout=NAV_TIMEOUT_MS,
                )
                await page.wait_for_timeout(500)
                await autoscroll(page)
                await page.wait_for_timeout(SETTLE_MS)

                if pending:
                    await asyncio.gather(*list(pending), return_exceptions=True)

                final_url = normalize_url(page.url) or page.url
                page_entry["final_url"] = final_url
                page_entry["status"] = response.status if response else None

                try:
                    page_entry["title"] = await page.title()
                except Exception:
                    pass

                # Rendered DOM catches client-side and hidden DOM changes.
                try:
                    dom = (await page.content()).encode("utf-8", "replace")
                    page_entry["rendered_dom"] = body_record(dom, "text/html")
                except Exception as e:
                    page_entry["dom_error"] = repr(e)

                # Exact pixel monitoring when the page is visually stable. If it is
                # actively animated/WebGL-dynamic, avoid random-frame false alarms.
                try:
                    page_entry["screenshot"] = await stable_screenshot_record(page)
                except Exception as e:
                    page_entry["screenshot_error"] = repr(e)

                # Client storage.
                try:
                    storage = await page.evaluate(
                        """
                        () => ({
                          localStorage: Object.fromEntries(
                            Object.keys(localStorage).sort().map(k => [k, localStorage.getItem(k)])
                          ),
                          sessionStorage: Object.fromEntries(
                            Object.keys(sessionStorage).sort().map(k => [k, sessionStorage.getItem(k)])
                          )
                        })
                        """
                    )
                    page_entry["client_storage_sha256"] = stable_json_hash(storage)
                except Exception:
                    pass

                # Console output and JS errors are externally observable too.
                if console_messages:
                    page_entry["console_sha256"] = stable_json_hash(console_messages)
                    page_entry["console"] = console_messages[:100]
                if page_errors:
                    page_entry["page_errors_sha256"] = stable_json_hash(page_errors)
                    page_entry["page_errors"] = page_errors[:50]
                if websocket_events:
                    page_entry["websockets_sha256"] = stable_json_hash(websocket_events)
                    page_entry["websockets"] = websocket_events[:50]

                # Discover navigational/internal URLs from rendered DOM.
                try:
                    urls = await page.locator(
                        "a[href], area[href], form[action], iframe[src], frame[src]"
                    ).evaluate_all(
                        """
                        els => els.map(e =>
                          e.href || e.action || e.src || null
                        ).filter(Boolean)
                        """
                    )
                    for raw in urls:
                        add_discovered_url(
                            raw, final_url, queue, queued, discovered_hosts
                        )
                except Exception:
                    pass

                # This site is a React single-page app. Its main navigation is made
                # of <button> elements rather than <a href=...> links, so a normal crawler
                # sees only "/". Explore every HEADER button as a separate SPA view.
                # Restricting this to the header avoids clicking submit/purchase/form buttons.
                try:
                    nav_labels = await page.locator("header button").all_text_contents()
                    nav_labels = [x.strip() for x in nav_labels if x and x.strip()]
                    nav_labels = list(dict.fromkeys(nav_labels))
                    page_entry["spa_navigation_labels"] = nav_labels
                    spa_views: dict[str, Any] = {}

                    async def discover_links_from_current_view(base_url: str):
                        try:
                            view_urls = await page.locator(
                                "a[href], area[href], form[action], iframe[src], frame[src]"
                            ).evaluate_all(
                                """
                                els => els.map(e => e.href || e.action || e.src || null).filter(Boolean)
                                """
                            )
                            for raw in view_urls:
                                add_discovered_url(raw, base_url, queue, queued, discovered_hosts)
                        except Exception:
                            pass

                    # Home is already captured above. Click each other top-level nav view.
                    for label in nav_labels:
                        if label.lower() == "home":
                            continue
                        try:
                            locator = page.get_by_role("button", name=label, exact=True)
                            if await locator.count() < 1:
                                continue
                            await locator.first.click(timeout=5000)
                            await page.wait_for_timeout(400)
                            await autoscroll(page)
                            await page.wait_for_timeout(SETTLE_MS)
                            if pending:
                                await asyncio.gather(*list(pending), return_exceptions=True)

                            view_url = normalize_url(page.url) or page.url
                            # Do not crawl an external destination as part of this domain.
                            # We still preserve the destination URL as observable behavior.
                            view: dict[str, Any] = {"url": view_url}
                            if is_in_scope(view_url):
                                vdom = (await page.content()).encode("utf-8", "replace")
                                view["rendered_dom"] = body_record(vdom, "text/html")
                                try:
                                    view["screenshot"] = await stable_screenshot_record(page)
                                except Exception as e:
                                    view["screenshot_error"] = repr(e)
                                try:
                                    view["title"] = await page.title()
                                except Exception:
                                    pass
                                await discover_links_from_current_view(view_url)
                                if view_url not in queued:
                                    add_discovered_url(view_url, view_url, queue, queued, discovered_hosts)
                            spa_views[label] = view

                            # Return to Home using the site's own navigation before the next view.
                            home = page.get_by_role("button", name="Home", exact=True)
                            if await home.count() > 0:
                                await home.first.click(timeout=5000)
                                await page.wait_for_timeout(300)
                            else:
                                await page.goto(final_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                                await page.wait_for_timeout(500)
                        except Exception as e:
                            spa_views[label] = {"error": normalize_runtime_text(repr(e))}
                            try:
                                await page.goto(final_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                                await page.wait_for_timeout(500)
                            except Exception:
                                pass

                    page_entry["spa_views"] = spa_views
                except Exception as e:
                    page_entry["spa_exploration_error"] = normalize_runtime_text(repr(e))

                # Discover absolute in-scope URLs embedded anywhere in the rendered HTML.
                try:
                    html = await page.content()
                    pattern = rf'https?://[^"\'<>\s]*{re.escape(BASE_DOMAIN)}[^"\'<>\s]*'
                    for raw in re.findall(pattern, html, flags=re.I):
                        add_discovered_url(
                            raw, final_url, queue, queued, discovered_hosts
                        )
                except Exception:
                    pass

            except PlaywrightTimeoutError as e:
                page_entry["error"] = "navigation timeout: " + repr(e)
            except Exception as e:
                page_entry["error"] = repr(e)
            finally:
                if pending:
                    await asyncio.gather(*list(pending), return_exceptions=True)
                await page.close()

            manifest["pages"][requested_url] = page_entry

        if queue:
            manifest["crawl_warning"] = (
                f"MAX_PAGES={MAX_PAGES} reached with {len(queue)} URL(s) still queued."
            )

        await browser.close()

    # DNS/TLS snapshot after crawling so newly discovered subdomains are included.
    manifest["hosts"] = infra_snapshot(discovered_hosts)
    manifest["discovered_subdomains"] = sorted(
        h for h in discovered_hosts if h != BASE_DOMAIN
    )
    manifest["counts"] = {
        "hosts": len(manifest["hosts"]),
        "pages": len(manifest["pages"]),
        "resources": len(manifest["resources"]),
    }
    return manifest


def meaningful_diff(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    changes: list[str] = []

    old_hosts = old.get("hosts", {})
    new_hosts = new.get("hosts", {})
    for host in sorted(set(new_hosts) - set(old_hosts)):
        changes.append(f"HOST ADDED: {host}")
    for host in sorted(set(old_hosts) - set(new_hosts)):
        changes.append(f"HOST REMOVED: {host}")
    for host in sorted(set(old_hosts) & set(new_hosts)):
        if old_hosts[host] != new_hosts[host]:
            changes.append(f"HOST INFRA CHANGED: {host} (DNS/TLS)")

    old_pages = old.get("pages", {})
    new_pages = new.get("pages", {})
    for url in sorted(set(new_pages) - set(old_pages)):
        changes.append(f"PAGE ADDED: {url}")
    for url in sorted(set(old_pages) - set(new_pages)):
        changes.append(f"PAGE REMOVED/UNREACHABLE: {url}")
    for url in sorted(set(old_pages) & set(new_pages)):
        a, b = old_pages[url], new_pages[url]
        watched_fields = [
            "final_url", "status", "title",
            "rendered_dom", "screenshot",
            "spa_navigation_labels", "spa_views", "spa_exploration_error",
            "client_storage_sha256", "console_sha256",
            "page_errors_sha256", "websockets_sha256",
            "error",
        ]
        for field in watched_fields:
            if a.get(field) != b.get(field):
                changes.append(f"PAGE CHANGED: {url} [{field}]")

    old_res = old.get("resources", {})
    new_res = new.get("resources", {})
    for key in sorted(set(new_res) - set(old_res)):
        changes.append(f"RESOURCE ADDED: {key}")
    for key in sorted(set(old_res) - set(new_res)):
        changes.append(f"RESOURCE REMOVED: {key}")
    for key in sorted(set(old_res) & set(new_res)):
        a, b = old_res[key], new_res[key]
        for field in ("status", "headers", "body", "error"):
            if a.get(field) != b.get(field):
                changes.append(f"RESOURCE CHANGED: {key} [{field}]")

    if old.get("crawl_warning") != new.get("crawl_warning"):
        changes.append("CRAWL WARNING STATUS CHANGED")

    return changes


def send_ntfy(title: str, message: str) -> bool:
    topic = os.getenv("NTFY_TOPIC", "").strip()
    if not topic:
        return False

    # Topic should be a long random secret because anonymous ntfy.sh topics
    # are otherwise readable by anyone who guesses the topic name.
    url = "https://ntfy.sh/" + urllib.parse.quote(topic, safe="")
    body = message.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Title": title,
            "Priority": "urgent",
            "Tags": "rotating_light",
            "User-Agent": "VeritasChangeMonitor/3.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        print("[notify] ntfy push sent", flush=True)
        return True
    except Exception as e:
        print(f"[notify] ntfy failed: {e!r}", flush=True)
        return False


def send_twilio_sms(message: str) -> bool:
    """
    Optional real SMS. Requires repository secrets:
      TWILIO_ACCOUNT_SID
      TWILIO_AUTH_TOKEN
      TWILIO_FROM
      TWILIO_TO

    This is NOT free after any trial allowance.
    """
    sid = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
    token = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    from_num = os.getenv("TWILIO_FROM", "").strip()
    to_num = os.getenv("TWILIO_TO", "").strip()
    if not all([sid, token, from_num, to_num]):
        return False

    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    payload = urllib.parse.urlencode({
        "From": from_num,
        "To": to_num,
        "Body": message,
    }).encode()

    auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "VeritasChangeMonitor/3.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
        print("[notify] Twilio SMS sent", flush=True)
        return True
    except Exception as e:
        print(f"[notify] Twilio SMS failed: {e!r}", flush=True)
        return False


def send_alert(title: str, message: str) -> None:
    sent = False
    sent |= send_ntfy(title, message)
    sent |= send_twilio_sms(f"{title}: {message}")
    if not sent:
        print("[notify] no notification channel configured", flush=True)


def load_old_manifest() -> dict[str, Any] | None:
    try:
        if MANIFEST_FILE.exists():
            return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[state] failed to read old manifest: {e!r}")
    return None


def write_report(manifest: dict[str, Any], changes: list[str], baseline: bool) -> None:
    lines = [
        "# Veritas Monitor Report",
        "",
        f"- Run: `{iso_now()}`",
        f"- Hosts monitored this run: **{manifest.get('counts', {}).get('hosts', 0)}**",
        f"- Pages crawled: **{manifest.get('counts', {}).get('pages', 0)}**",
        f"- Network resources observed: **{manifest.get('counts', {}).get('resources', 0)}**",
        f"- SPA views exercised: **{sum(len(p.get('spa_views', {})) for p in manifest.get('pages', {}).values())}**",
        f"- Change events: **{len(changes)}**",
        "",
        "## Subdomains/hosts monitored",
        "",
    ]
    for host in sorted(manifest.get("hosts", {})):
        lines.append(f"- `{host}`")

    lines += ["", "## SPA navigation views exercised", ""]
    seen_views = set()
    for page in manifest.get("pages", {}).values():
        seen_views.update(page.get("spa_navigation_labels", []))
    if seen_views:
        for label in sorted(seen_views):
            lines.append(f"- `{label}`")
    else:
        lines.append("- None discovered")

    lines += ["", "## Result", ""]
    if baseline:
        lines.append("Baseline created. Future runs are compared against this snapshot.")
    elif not changes:
        lines.append("No observable changes detected.")
    else:
        for change in changes:
            lines.append(f"- {change}")

    if manifest.get("crawl_warning"):
        lines += ["", "## Warning", "", manifest["crawl_warning"]]

    REPORT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def maybe_update_heartbeat() -> None:
    # Keeps a public GitHub repo "active" so scheduled workflows do not get
    # disabled after long periods with no target-site changes.
    should_update = True
    if HEARTBEAT_FILE.exists():
        try:
            last = datetime.fromisoformat(HEARTBEAT_FILE.read_text().strip())
            should_update = utcnow() - last > timedelta(days=30)
        except Exception:
            should_update = True
    if should_update:
        HEARTBEAT_FILE.write_text(iso_now(), encoding="utf-8")


async def main() -> int:
    STATE_DIR.mkdir(exist_ok=True)

    print(f"Monitoring {BASE_DOMAIN}")
    print(f"MAX_PAGES={MAX_PAGES} STRICT_HEADERS={STRICT_HEADERS}")
    print("Discovering certificate-transparency subdomains and crawling...", flush=True)

    old = load_old_manifest()
    new = await crawl()
    baseline = old is None or old.get("schema") != SCHEMA_VERSION

    if baseline:
        changes: list[str] = []
        print("\nBASELINE CREATED/REFRESHED", flush=True)
        send_alert(
            "Veritas monitor is LIVE",
            (
                f"Test notification: cloud monitoring is active. "
                f"Baseline has {new['counts']['hosts']} host(s), "
                f"{new['counts']['pages']} page(s), "
                f"{new['counts']['resources']} resource(s)."
            ),
        )
    else:
        changes = meaningful_diff(old, new)
        if changes:
            print(f"\n*** {len(changes)} CHANGE EVENT(S) DETECTED ***", flush=True)
            for item in changes[:100]:
                print(item, flush=True)

            preview = "; ".join(changes[:4])
            if len(preview) > 700:
                preview = preview[:697] + "..."
            if len(changes) > 4:
                preview += f"; +{len(changes)-4} more"

            send_alert(
                "VERITAS CHANGE DETECTED",
                f"{len(changes)} change event(s). {preview}",
            )
        else:
            print("\nNo observable changes detected.", flush=True)

    # Keep the repository quiet when nothing changed. Updating last_report.md
    # every five minutes would create hundreds of pointless Git commits/day.
    if baseline or changes:
        write_report(new, changes, baseline)
    else:
        print("[state] no meaningful change; preserving last_report.md", flush=True)

    MANIFEST_FILE.write_text(
        json.dumps(new, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    maybe_update_heartbeat()

    # Make a human-readable GitHub Actions summary.
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as f:
                f.write(REPORT_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except KeyboardInterrupt:
        raise SystemExit(130)
