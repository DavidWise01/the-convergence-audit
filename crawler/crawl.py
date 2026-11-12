#!/usr/bin/env python3
"""ROOT0: bounded, observation-only external convergence scanner (stdlib only)."""
import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urldefrag
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.robotparser import RobotFileParser

BASE=Path(__file__).resolve().parent
AGENT="ROOT0-ConvergenceScout/0.1 (+https://github.com/DavidWise01/the-convergence-audit)"
MAX_BYTES=512000

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.words=[]
        self.links=[]
        self.skip=0
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag in ("script","style","noscript","svg"): self.skip+=1
        if tag=="a" and attrs.get("href"): self.links.append(attrs["href"])
    def handle_endtag(self,tag):
        if tag in ("script","style","noscript","svg") and self.skip: self.skip-=1
    def handle_data(self,value):
        if not self.skip: self.words.append(value)
    def text(self):
        return re.sub(r"\s+"," "," ".join(self.words)).strip()

def safe_url(url, hosts):
    try:
        p=urlparse(url)
        h=(p.hostname or "").lower()
        if p.scheme not in ("https","http") or h not in hosts or p.username or p.password: return None
        if p.port not in (None,80,443): return None
        return urldefrag(url)[0]
    except ValueError:
        return None

def read_public(url, hosts, robots, timeout=10):
    url=safe_url(url,hosts)
    if not url: return None,"not_allowlisted"
    host=urlparse(url).hostname
    if host not in robots:
        rp=RobotFileParser()
        rp.set_url("https://"+host+"/robots.txt")
        try:
            rp.read()
            robots[host]=rp
        except Exception:
            robots[host]=False
    rp=robots[host]
    if rp is False or not rp.can_fetch(AGENT,url): return None,"robots_disallowed"
    try:
        req=Request(url,headers={"User-Agent":AGENT,"Accept":"text/html"})
        with build_opener(NoRedirect()).open(req,timeout=timeout) as response:
            if not safe_url(response.geturl(),hosts): return None,"bad_final_url"
            typ=response.headers.get("Content-Type","")
            if "text/html" not in typ and "application/xhtml+xml" not in typ: return None,"not_html"
            length=response.headers.get("Content-Length")
            if length and int(length)>MAX_BYTES: return None,"too_large"
            body=response.read(MAX_BYTES+1)
            if len(body)>MAX_BYTES: return None,"too_large"
            return body.decode("utf-8","replace"),None
    except Exception as e:
        return None,"fetch_error:"+type(e).__name__

def scan(config,ledger,max_pages=None,reader=read_public,sleeper=time.sleep):
    hosts={h.lower() for h in config["allowed_hosts"]}
    phrases=[p.strip() for p in config["patterns"] if len(p.strip())>=7]
    limit=min(60,max(1,int(max_pages or config.get("max_pages",20))))
    depth_limit=min(2,max(0,int(config.get("max_depth",1))))
    delay=max(1.,float(config.get("host_delay_seconds",2)))
    queue=[(x,0) for x in config["seeds"] if safe_url(x,hosts)]
    visited=set()
    existing=set()
    if ledger.exists():
        for line in ledger.read_text(encoding="utf-8").splitlines():
            try: existing.add(json.loads(line)["id"])
            except (ValueError,KeyError): raise ValueError("Malformed ledger: refusing modification")
    added=[]
    robots={}
    host_last={}
    errors={}
    while queue and len(visited)<limit:
        url,depth=queue.pop(0)
        if url in visited: continue
        visited.add(url)
        host=urlparse(url).hostname
        if host in host_last: sleeper(max(0,delay-(time.monotonic()-host_last[host])))
        data,error=reader(url,hosts,robots)
        host_last[host]=time.monotonic()
        if error:
            errors[error]=errors.get(error,0)+1
            continue
        page=Page()
        page.feed(data)
        content=page.text()
        digest=hashlib.sha256(content.encode("utf-8")).hexdigest()
        normalized=re.sub(r"\s+"," ",content).casefold()
        for phrase in phrases:
            if phrase.casefold() not in normalized: continue
            key=hashlib.sha256((url+"\n"+phrase+"\n"+digest).encode()).hexdigest()
            if key in existing: continue
            record={"id":key,"observed_utc":datetime.now(timezone.utc).isoformat(),
                "url":url,"host":host,"matched_phrase":phrase,"page_sha256":digest,
                "status":"UNREVIEWED_CONVERGENCE_CANDIDATE",
                "ancestry":"UNKNOWN","copying_claim":False,"influence_claim":False}
            added.append(record)
            existing.add(key)
        if depth<depth_limit:
            for link in page.links[:150]:
                candidate=safe_url(urljoin(url,link),hosts)
                if candidate and candidate not in visited and len(queue)<limit*10:
                    queue.append((candidate,depth+1))
    if added:
        ledger.parent.mkdir(parents=True,exist_ok=True)
        with ledger.open("a",encoding="utf-8") as f:
            for record in added: f.write(json.dumps(record,sort_keys=True,ensure_ascii=False)+"\n")
    return {"checked":len(visited),"added":len(added),"errors":errors}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--config",default=str(BASE/"config.json"))
    p.add_argument("--ledger",default=str(BASE/"observations.jsonl"))
    p.add_argument("--max-pages",type=int)
    args=p.parse_args()
    config=json.loads(Path(args.config).read_text(encoding="utf-8"))
    print(json.dumps(scan(config,Path(args.ledger),args.max_pages),indent=2))

if __name__=="__main__":main()
