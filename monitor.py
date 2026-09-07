#!/usr/bin/env python3
from __future__ import annotations
import asyncio, hashlib, json, os, re, socket, ssl, urllib.parse, urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from playwright.async_api import async_playwright

SCHEMA_VERSION = 5
BASE_DOMAIN = "theveritassearch.com"
ROOTS = ["https://www.theveritassearch.com/", "https://theveritassearch.com/"]
SPA_LABELS = ["Home", "Rewards", "Guidelines", "Tracker", "Hints", "Archive", "Support Us"]

STATE_DIR = Path("state")
MANIFEST_FILE = STATE_DIR / "manifest.json"
REPORT_FILE = STATE_DIR / "last_report.md"
HEARTBEAT_FILE = STATE_DIR / "heartbeat.txt"

VOLATILE_HEADERS = {
    "date","age","expires","last-modified","set-cookie","cookie","cf-ray",
    "cf-cache-status","x-request-id","x-amzn-trace-id","x-vercel-id",
    "x-vercel-cache","x-fastly-request-id","x-github-request-id","x-timer",
    "x-served-by","x-cache","x-cache-hits","source-age","server-timing",
    "traceparent","tracestate","nel","report-to",
}

def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def jhash(x: Any) -> str:
    return sha(json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())

def stable_headers(h):
    h2 = {str(k).lower(): str(v) for k,v in h.items()}
    return dict(sorted((k,v) for k,v in h2.items() if k not in VOLATILE_HEADERS))

def normalize_runtime_text(text: str) -> str:
    text = re.sub(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", "<UUID>", text)
    text = re.sub(r"blob:https?://[^/]+/[0-9a-fA-F-]+", "blob:<RUNTIME>", text)
    text = re.sub(r"0x[0-9a-fA-F]+", "0x<RUNTIME>", text)
    return text

def host_in_scope(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host == BASE_DOMAIN or host.endswith("." + BASE_DOMAIN)

def _http_get(url: str, timeout: float = 5.0):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VeritasMonitor/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return getattr(r, "status", 200), dict(r.headers.items()), r.read(), None
    except Exception as e:
        return None, {}, b"", repr(e)

async def fetch_url(url: str, timeout: float = 5.0):
    return await asyncio.wait_for(asyncio.to_thread(_http_get, url, timeout), timeout=timeout+1)

async def discover_ct_hosts() -> set[str]:
    hosts = {BASE_DOMAIN, "www."+BASE_DOMAIN}
    q = urllib.parse.quote(f"%.{BASE_DOMAIN}", safe="")
    _,_,body,err = await fetch_url(f"https://crt.sh/?q={q}&output=json", 5)
    if err or not body:
        return hosts
    try:
        for row in json.loads(body.decode("utf-8","replace")):
            for field in ("name_value","common_name"):
                for name in str(row.get(field,"")).splitlines():
                    name = name.strip().lower().rstrip(".")
                    if name.startswith("*."): name = name[2:]
                    if host_in_scope(name) and "*" not in name and "/" not in name and " " not in name:
                        hosts.add(name)
    except Exception:
        pass
    return hosts

async def dns_tls(host: str):
    def work():
        out = {}
        try:
            rows = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            out["dns"] = sorted({r[4][0] for r in rows})
        except Exception as e:
            out["dns_error"] = repr(e)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host,443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    out["tls_cert_sha256"] = sha(s.getpeercert(binary_form=True))
        except Exception as e:
            out["tls_error"] = repr(e)
        return out
    try:
        return await asyncio.wait_for(asyncio.to_thread(work), timeout=6)
    except asyncio.TimeoutError:
        return {"error":"dns/tls timeout"}

async def stable_screenshot(page):
    try:
        a = await asyncio.wait_for(page.screenshot(full_page=True, animations="disabled"), 8)
        await page.wait_for_timeout(250)
        b = await asyncio.wait_for(page.screenshot(full_page=True, animations="disabled"), 8)
        if sha(a) == sha(b):
            return {"stable":True,"sha256":sha(a),"bytes":len(a)}
        return {"stable":False}
    except Exception as e:
        return {"error":repr(e)}

def resource_key(method,url,post):
    return f"{method} {url}" + (f" body={sha(post.encode())[:16]}" if post else "")

async def crawl_browser(hosts: set[str]):
    pages, resources = {}, {}
    observed_hosts = set(hosts)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--disable-background-networking","--disable-component-update"])
        context = await browser.new_context(
            viewport={"width":1440,"height":1000},
            color_scheme="light", reduced_motion="reduce",
            locale="en-US", timezone_id="America/New_York",
            user_agent="Mozilla/5.0 (compatible; VeritasMonitor/5.0)"
        )

        probe_paths = ["/","/robots.txt","/sitemap.xml","/sitemap_index.xml","/sitemap-index.xml","/wp-sitemap.xml","/manifest.json","/site.webmanifest","/favicon.ico","/.well-known/security.txt"]
        sem = asyncio.Semaphore(12)

        async def probe(host,path):
            url=f"https://{host}{path}"
            async with sem:
                try:
                    resp=await context.request.get(url, timeout=5000, fail_on_status_code=False)
                    try: body=await asyncio.wait_for(resp.body(),5)
                    except Exception: body=b""
                    resources[f"GET {url}"]={
                        "url":url,"method":"GET","kind":"probe","status":resp.status,
                        "headers":stable_headers(resp.headers),"body_sha256":sha(body),"bytes":len(body)
                    }
                except Exception as e:
                    resources[f"GET {url}"]={"url":url,"error":repr(e)}

        await asyncio.wait_for(
            asyncio.gather(*(probe(h,pth) for h in sorted(hosts) for pth in probe_paths)),
            timeout=25
        )

        for host in sorted(hosts):
            root=f"https://{host}/"
            page=await context.new_page()
            pending=set()
            console=[]; page_errors=[]

            async def capture(response):
                try:
                    raw_url=response.url
                    if raw_url.startswith(("blob:","data:")): return
                    req=response.request
                    post=req.post_data
                    key=resource_key(req.method,raw_url,post)
                    try: body=await asyncio.wait_for(response.body(),4)
                    except Exception: body=b""
                    try: hdrs=await asyncio.wait_for(response.all_headers(),3)
                    except Exception: hdrs={}
                    resources[key]={
                        "url":raw_url,"method":req.method,"kind":req.resource_type,
                        "status":response.status,"headers":stable_headers(hdrs),
                        "body_sha256":sha(body),"bytes":len(body)
                    }
                    try:
                        rh=urllib.parse.urlparse(raw_url).hostname or ""
                        if host_in_scope(rh): observed_hosts.add(rh.lower())
                    except Exception: pass
                except Exception:
                    pass

            def on_response(resp):
                t=asyncio.create_task(capture(resp))
                pending.add(t); t.add_done_callback(pending.discard)

            page.on("response",on_response)
            page.on("console",lambda m: console.append({"type":m.type,"text":normalize_runtime_text(m.text[:1500])}))
            page.on("pageerror",lambda e: page_errors.append(normalize_runtime_text(str(e)[:2000])))

            entry={"root":root,"views":{}}
            try:
                resp=await page.goto(root,wait_until="domcontentloaded",timeout=15000)
                entry["status"]=resp.status if resp else None
                await page.wait_for_timeout(1000)

                dom=normalize_runtime_text(await page.content()).encode()
                entry["base_dom_sha256"]=sha(dom)
                entry["base_screenshot"]=await stable_screenshot(page)

                for label in SPA_LABELS:
                    view={}
                    try:
                        loc=page.get_by_role("button",name=label,exact=True)
                        if await loc.count()==0:
                            loc=page.get_by_text(label,exact=True)
                        if await loc.count():
                            await loc.first.click(timeout=3000)
                            await page.wait_for_timeout(600)
                            vdom=normalize_runtime_text(await page.content()).encode()
                            view["dom_sha256"]=sha(vdom)
                            view["screenshot"]=await stable_screenshot(page)
                            view["url"]=page.url
                        else:
                            view["missing"]=True
                    except Exception as e:
                        view["error"]=repr(e)
                    entry["views"][label]=view

                if pending:
                    _,not_done=await asyncio.wait(list(pending),timeout=8)
                    for t in not_done: t.cancel()
                    if not_done: await asyncio.gather(*not_done,return_exceptions=True)

                if console: entry["console_sha256"]=jhash(console)
                if page_errors: entry["page_errors_sha256"]=jhash(page_errors)
            except Exception as e:
                entry["error"]=repr(e)
            finally:
                for t in list(pending):
                    if not t.done(): t.cancel()
                await page.close()

            pages[root]=entry

        await browser.close()

    return {"pages":pages,"resources":resources,"observed_hosts":sorted(observed_hosts)}

def diff(old,new):
    changes=[]
    for sec in ("hosts","pages","resources"):
        a,b=old.get(sec,{}),new.get(sec,{})
        for k in sorted(set(b)-set(a)): changes.append(f"{sec.upper()} ADDED: {k}")
        for k in sorted(set(a)-set(b)): changes.append(f"{sec.upper()} REMOVED: {k}")
        for k in sorted(set(a)&set(b)):
            if a[k]!=b[k]: changes.append(f"{sec.upper()} CHANGED: {k}")
    return changes

def send_ntfy(title,msg):
    topic=os.getenv("NTFY_TOPIC","").strip()
    if not topic:
        print("[notify] NTFY_TOPIC missing"); return
    try:
        url="https://ntfy.sh/"+urllib.parse.quote(topic,safe="")
        req=urllib.request.Request(url,data=msg.encode(),method="POST",headers={"Title":title,"Priority":"urgent","Tags":"rotating_light"})
        with urllib.request.urlopen(req,timeout=8) as r: r.read()
        print("[notify] sent")
    except Exception as e:
        print("[notify] failed",repr(e))

def maybe_heartbeat():
    now=datetime.now(timezone.utc); due=True
    if HEARTBEAT_FILE.exists():
        try: due=now-datetime.fromisoformat(HEARTBEAT_FILE.read_text().strip())>timedelta(days=30)
        except Exception: pass
    if due: HEARTBEAT_FILE.write_text(now.isoformat())

async def monitor_once():
    STATE_DIR.mkdir(exist_ok=True)
    ct_hosts=await discover_ct_hosts()
    print("[hosts]",sorted(ct_hosts),flush=True)

    browser=await crawl_browser(ct_hosts)
    all_hosts=set(browser["observed_hosts"])|ct_hosts
    infra=await asyncio.gather(*(dns_tls(h) for h in sorted(all_hosts)))
    hosts=dict(zip(sorted(all_hosts),infra))

    manifest={"schema":SCHEMA_VERSION,"hosts":hosts,"pages":browser["pages"],"resources":browser["resources"]}

    old=None
    if MANIFEST_FILE.exists():
        try: old=json.loads(MANIFEST_FILE.read_text())
        except Exception: pass

    baseline=old is None or old.get("schema")!=SCHEMA_VERSION
    changes=[] if baseline else diff(old,manifest)

    if baseline:
        send_ntfy("Veritas monitor is LIVE",f"Reliable v5 baseline created: {len(hosts)} host(s), {len(manifest['pages'])} root page(s), {len(manifest['resources'])} resources.")
    elif changes:
        preview="; ".join(changes[:5]) + (f"; +{len(changes)-5} more" if len(changes)>5 else "")
        send_ntfy("VERITAS CHANGE DETECTED",preview[:900])

    MANIFEST_FILE.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    maybe_heartbeat()

    lines=[
        "# Veritas Monitor Report","",
        f"- Schema: **{SCHEMA_VERSION}**",
        f"- Hosts monitored: **{len(hosts)}**",
        f"- Root pages exercised: **{len(manifest['pages'])}**",
        f"- Network resources observed: **{len(manifest['resources'])}**",
        f"- Change events: **{len(changes)}**","",
        "## Hosts","",
        *[f"- `{h}`" for h in sorted(hosts)],"",
        "## SPA views attempted","",
        *[f"- {x}" for x in SPA_LABELS],"",
        "## Result","",
        ("Fresh v5 baseline created." if baseline else ("No observable changes." if not changes else "\n".join(f"- {c}" for c in changes[:200])))
    ]
    REPORT_FILE.write_text("\n".join(lines)+"\n")
    print(f"[done] hosts={len(hosts)} resources={len(manifest['resources'])} changes={len(changes)}",flush=True)

async def main():
    try:
        await asyncio.wait_for(monitor_once(),timeout=165)
    except asyncio.TimeoutError:
        print("FATAL: monitor exceeded 165-second global limit",flush=True)
        raise SystemExit(2)

if __name__=="__main__":
    asyncio.run(main())
