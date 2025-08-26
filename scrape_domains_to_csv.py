#!/usr/bin/env python3
"""
scrape_domains_to_csv.py

Discover websites automatically, then generate a CSV of DNS-based features
that matches the schema of your training data (minus the label).

WHAT THIS DOES
--------------
1) **Crawl & Discover Domains**
   - Starts from one or more SEED URLs (default list provided)
   - BFS crawl up to --depth and --max-pages
   - Extracts links from HTML pages
   - Deduplicates and collects unique *registrable* domains (example.com, rvce.edu.in)
   - Respects robots.txt (disallow rules) for fetching

2) **Extract DNS Features** for each discovered registrable domain:
   - 'DNSRecordType'          (categorical: "A", "CNAME", "MX" - in that priority)
   - 'MXDnsResponse'          (bool)
   - 'TXTDnsResponse'         (bool)
   - 'HasSPFInfo'             (bool, TXT contains "v=spf1")
   - 'HasDkimInfo'            (bool, TXT contains "v=DKIM1")
   - 'HasDmarcInfo'           (bool, TXT at _dmarc.<domain> contains "v=DMARC1")
   - 'SubdomainNumber'        (int, from the scanned hostname label count before SLD.TLD)
   - 'Entropy'                (float, Shannon entropy of domain (dots removed))
   - 'EntropyOfSubDomains'    (float, Shannon entropy of subdomain part only)
   - 'StrangeCharacters'      (int, count of non-alphanumeric chars excluding dots)
   - 'ConsoantRatio'          (float)  # (kept spelling to match your CSV)
   - 'NumericRatio'           (float)
   - 'SpecialCharRatio'       (float)
   - 'VowelRatio'             (float)
   - 'ConsoantSequence'       (int, max consecutive consonants)
   - 'VowelSequence'          (int, max consecutive vowels)
   - 'NumericSequence'        (int, max consecutive digits)
   - 'SpecialCharSequence'    (int, max consecutive non-alphanumeric chars)
   - 'DomainLength'           (int, length with dots removed)

3) **Write CSV** with the above columns. By default we also include a leading 'Domain'
   column for traceability. If you need a CSV that is *exactly* the same columns as
   your training file, pass --include-class-column to add a blank 'Class' column and
   --no-domain-col to drop the Domain column.

WHY NOT "CRAWL THE ENTIRE INTERNET"?
------------------------------------
That is infeasible for one script. This tool provides a *controlled* crawler you can run
with reasonable limits, or point it at a large seed list (e.g., a text file of popular
sites) and it will auto-generate the features CSV.

USAGE
-----
Install deps:
    pip install -U aiohttp beautifulsoup4 tldextract dnspython pandas

Run with defaults (small polite crawl):
    python scrape_domains_to_csv.py

Custom run:
    python scrape_domains_to_csv.py \
      --seeds https://wikipedia.org https://github.com \
      --depth 2 \
      --max-pages 300 \
      --max-domains 200 \
      --output discovered_domains_features.csv

From a seed file (one URL per line; lines starting with # are ignored):
    python scrape_domains_to_csv.py --seed-file seeds.txt

Match your training CSV columns exactly (adds empty 'Class', drops 'Domain'):
    python scrape_domains_to_csv.py --include-class-column --no-domain-col

NOTES
-----
- Robots: We fetch and respect robots.txt for each host. We only fetch URLs allowed
  for the configured User-Agent. We do not attempt to bypass disallow rules.
- Politeness: Use --concurrency and --fetch-delay to avoid stressing servers.
- DNS lookups: Use your system's resolver. Add --dns-sleep to slow down large runs.
"""

import argparse
import asyncio
import math
import re
import sys
import time
from collections import deque
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urljoin, urldefrag, urlparse

import aiohttp
from bs4 import BeautifulSoup
import pandas as pd
import tldextract
import dns.resolver
import dns.exception
import urllib.robotparser as robotparser

# -----------------------------
# Domain / feature utilities
# -----------------------------

VOWELS = set("aeiou")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent

def max_run_length(s: str, pred) -> int:
    best = 0
    cur = 0
    for ch in s:
        if pred(ch):
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best

def split_domain(domain: str):
    ext = tldextract.extract(domain)
    return ext.subdomain.lower(), ext.domain.lower(), ext.suffix.lower()

def list_txt(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        out = []
        for rdata in answers:
            parts = [p.decode('utf-8', errors='ignore') if isinstance(p, (bytes, bytearray)) else str(p)
                     for p in getattr(rdata, "strings", [])]
            if parts:
                out.append("".join(parts))
            else:
                out.append(rdata.to_text().strip('"'))
        return out
    except dns.exception.DNSException:
        return []

def has_spf(txt_records: List[str]) -> bool:
    for txt in txt_records:
        if 'v=spf1' in txt.lower():
            return True
    return False

def has_dkim(txt_records: List[str]) -> bool:
    for txt in txt_records:
        if 'v=dkim1' in txt.lower():
            return True
    return False

def has_dmarc(domain: str) -> bool:
    dmarc_domain = f"_dmarc.{domain}"
    txts = list_txt(dmarc_domain)
    for txt in txts:
        if 'v=dmarc1' in txt.lower():
            return True
    return False

def dns_record_type(domain: str) -> str:
    try:
        try:
            if dns.resolver.resolve(domain, 'CNAME'):
                return "CNAME"
        except dns.exception.DNSException:
            pass
        try:
            if dns.resolver.resolve(domain, 'MX'):
                return "MX"
        except dns.exception.DNSException:
            pass
        try:
            if dns.resolver.resolve(domain, 'A'):
                return "A"
        except dns.exception.DNSException:
            pass
        return "A"
    except Exception:
        return "A"

def bool_dns(domain: str, rtype: str) -> bool:
    try:
        dns.resolver.resolve(domain, rtype)
        return True
    except dns.exception.DNSException:
        return False

def extract_features_for_domain(domain: str) -> Dict[str, Any]:
    d = domain.strip().lower().rstrip('.')
    if not d:
        raise ValueError("Empty domain string.")

    sub, sld, tld = split_domain(d)
    root = f"{sld}.{tld}" if tld else sld

    label_str = "".join(ch for ch in d if ch != '.')

    def is_letter(ch): return ch.isalpha()
    def is_digit(ch):  return ch.isdigit()
    def is_vowel(ch):  return ch in VOWELS
    def is_consonant(ch): return ch.isalpha() and ch not in VOWELS
    def is_special(ch): return not ch.isalnum()

    total_chars = len(label_str)
    digits = sum(1 for c in label_str if is_digit(c))
    specials = sum(1 for c in label_str if is_special(c))
    vowels = sum(1 for c in label_str if is_vowel(c))
    consonants = sum(1 for c in label_str if is_consonant(c))

    def safe_ratio(num): return (num / total_chars) if total_chars > 0 else 0.0

    mx_resp = bool_dns(root, 'MX')
    txt_resp = bool_dns(root, 'TXT')
    txts_root = list_txt(root)
    spf = has_spf(txts_root)
    dkim = has_dkim(txts_root)
    dmarc = has_dmarc(root)
    rtype = dns_record_type(root)

    subdomain_number = 0 if not sub else len(sub.split('.'))
    full_no_dots = "".join(ch for ch in d if ch != '.')
    entropy_full = shannon_entropy(full_no_dots)
    sub_no_dots = "".join(ch for ch in sub if ch != '.')
    entropy_sub = shannon_entropy(sub_no_dots) if sub else 0.0

    strange_chars = specials
    cons_seq = max_run_length(label_str, is_consonant)
    vowel_seq = max_run_length(label_str, is_vowel)
    digit_seq = max_run_length(label_str, is_digit)
    special_seq = max_run_length(label_str, is_special)
    domain_length = total_chars

    return {
        'DNSRecordType': rtype,
        'MXDnsResponse': bool(mx_resp),
        'TXTDnsResponse': bool(txt_resp),
        'HasSPFInfo': bool(spf),
        'HasDkimInfo': bool(dkim),
        'HasDmarcInfo': bool(dmarc),
        'SubdomainNumber': int(subdomain_number),
        'Entropy': float(entropy_full),
        'EntropyOfSubDomains': float(entropy_sub),
        'StrangeCharacters': int(strange_chars),
        'ConsoantRatio': float(safe_ratio(consonants)),
        'NumericRatio': float(safe_ratio(digits)),
        'SpecialCharRatio': float(safe_ratio(specials)),
        'VowelRatio': float(safe_ratio(vowels)),
        'ConsoantSequence': int(cons_seq),
        'VowelSequence': int(vowel_seq),
        'NumericSequence': int(digit_seq),
        'SpecialCharSequence': int(special_seq),
        'DomainLength': int(domain_length),
    }

# -----------------------------
# Crawler
# -----------------------------

DEFAULT_SEEDS = [
    "https://www.wikipedia.org/",
    "https://www.github.com/",
    "https://www.openai.com/",
    "https://www.python.org/",
    "https://www.rvc.edu",  # example seed; replace if needed
]

class RobotsCache:
    """Cache robots.txt per host and expose allow(path) check for a given UA."""
    def __init__(self, session: aiohttp.ClientSession, user_agent: str, timeout: int = 10):
        self.session = session
        self.user_agent = user_agent
        self.timeout = timeout
        self.cache: Dict[str, Optional[robotparser.RobotFileParser]] = {}

    async def is_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        scheme = parsed.scheme
        if scheme not in ("http", "https"):
            return False
        rp = await self._get_rp(host, scheme)
        if rp is None:
            # If robots cannot be fetched, default to allowing to avoid false negatives
            return True
        return rp.can_fetch(self.user_agent, url)

    async def _get_rp(self, host: str, scheme: str):
        if host in self.cache:
            return self.cache[host]
        robots_url = f"{scheme}://{host}/robots.txt"
        rp = robotparser.RobotFileParser()
        try:
            async with self.session.get(robots_url, timeout=self.timeout) as resp:
                if resp.status == 200:
                    text = await resp.text(errors='ignore')
                    rp.parse(text.splitlines())
                    self.cache[host] = rp
                    return rp
                else:
                    # Treat non-200 as missing robots
                    self.cache[host] = None
                    return None
        except Exception:
            self.cache[host] = None
            return None

def normalize_url(base: str, href: str) -> Optional[str]:
    if not href:
        return None
    href = href.strip()
    if href.startswith("#"):
        return None
    # Resolve relative
    url = urljoin(base, href)
    url, _frag = urldefrag(url)
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    return url

def registrable_domain_from_url(url: str) -> Optional[str]:
    try:
        netloc = urlparse(url).netloc
        # strip port if any
        host = netloc.split("@")[-1].split(":")[0]
        ext = tldextract.extract(host)
        if not ext.suffix or not ext.domain:
            return None
        return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        return None

async def fetch_html(url: str, session: aiohttp.ClientSession, timeout: int) -> Optional[str]:
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            ctype = resp.headers.get("Content-Type", "").lower()
            if "text/html" not in ctype and "application/xhtml+xml" not in ctype:
                return None
            return await resp.text(errors='ignore')
    except Exception:
        return None

async def crawl_and_collect_domains(
    seeds: List[str],
    depth: int,
    max_pages: int,
    max_domains: int,
    concurrency: int,
    fetch_delay: float,
    user_agent: str,
    timeout: int,
) -> Set[str]:
    queue = deque([(s, 0) for s in seeds])
    visited_urls: Set[str] = set()
    discovered_domains: Set[str] = set()

    conn = aiohttp.TCPConnector(limit=concurrency)
    headers = {"User-Agent": user_agent}
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=conn, headers=headers) as session:
        robots = RobotsCache(session, user_agent, timeout=timeout)

        async def worker(url: str, d: int):
            nonlocal max_pages
            if len(visited_urls) >= max_pages:
                return
            async with sem:
                if not await robots.is_allowed(url):
                    return
                html = await fetch_html(url, session, timeout)
                if html is None:
                    return

                # Parse links
                soup = BeautifulSoup(html, "html.parser")
                for a in soup.find_all("a", href=True):
                    norm = normalize_url(url, a["href"])
                    if not norm:
                        continue
                    dom = registrable_domain_from_url(norm)
                    if dom:
                        discovered_domains.add(dom)
                        if len(discovered_domains) >= max_domains:
                            return
                    if d + 1 <= depth and len(visited_urls) + len(queue) < max_pages:
                        queue.append((norm, d + 1))
                await asyncio.sleep(fetch_delay)

        tasks = []
        while queue and len(visited_urls) < max_pages and len(discovered_domains) < max_domains:
            url, d = queue.popleft()
            if url in visited_urls:
                continue
            visited_urls.add(url)
            tasks.append(asyncio.create_task(worker(url, d)))
            # Occasionally let tasks run
            if len(tasks) >= concurrency * 2:
                await asyncio.gather(*tasks, return_exceptions=True)
                tasks = []
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    return discovered_domains

# -----------------------------
# Main
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="Crawl the web to discover domains and export DNS-feature CSV.")
    parser.add_argument("--seeds", nargs="*", default=DEFAULT_SEEDS, help="Seed URLs to start crawling from.")
    parser.add_argument("--seed-file", type=str, default=None, help="File with one seed URL per line.")
    parser.add_argument("--depth", type=int, default=1, help="BFS crawl depth from seeds.")
    parser.add_argument("--max-pages", type=int, default=200, help="Max pages to fetch (global).")
    parser.add_argument("--max-domains", type=int, default=150, help="Max unique registrable domains to collect.")
    parser.add_argument("--concurrency", type=int, default=8, help="Concurrent HTTP requests.")
    parser.add_argument("--fetch-delay", type=float, default=0.2, help="Delay between page fetches per task (seconds).")
    parser.add_argument("--timeout", type=int, default=12, help="HTTP request timeout (seconds).")
    parser.add_argument("--user-agent", type=str, default="DomainDiscoveryBot/1.0 (+https://example.com/bot)",
                        help="User-Agent for crawling.")
    parser.add_argument("--dns-sleep", type=float, default=0.0, help="Sleep between DNS lookups (seconds).")
    parser.add_argument("--output", type=str, default="discovered_domains_features.csv", help="Output CSV path.")
    parser.add_argument("--include-class-column", action="store_true", help="Add an empty 'Class' column to match training schema.")
    parser.add_argument("--no-domain-col", action="store_true", help="Omit the 'Domain' column in the CSV.")
    args = parser.parse_args()

    # Load seed file if provided
    seeds = list(args.seeds) if args.seeds else []
    if args.seed_file:
        try:
            with open(args.seed_file, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    seeds.append(s)
        except FileNotFoundError:
            print(f"Seed file not found: {args.seed_file}", file=sys.stderr)
            sys.exit(1)

    if not seeds:
        print("No seeds provided; exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"[1/3] Crawling with {len(seeds)} seed(s); depth={args.depth}, max-pages={args.max_pages}, max-domains={args.max_domains}")
    discovered = asyncio.run(crawl_and_collect_domains(
        seeds=seeds,
        depth=args.depth,
        max_pages=args.max_pages,
        max_domains=args.max_domains,
        concurrency=args.concurrency,
        fetch_delay=args.fetch_delay,
        user_agent=args.user_agent,
        timeout=args.timeout,
    ))
    if not discovered:
        print("No domains discovered. Try increasing --depth/--max-pages or change seeds.", file=sys.stderr)
        sys.exit(0)

    print(f"[2/3] Discovered {len(discovered)} unique registrable domains. Extracting DNS features...")
    rows = []
    feature_cols = [
        'DNSRecordType',
        'MXDnsResponse',
        'TXTDnsResponse',
        'HasSPFInfo',
        'HasDkimInfo',
        'HasDmarcInfo',
        'SubdomainNumber',
        'Entropy',
        'EntropyOfSubDomains',
        'StrangeCharacters',
        'ConsoantRatio',
        'NumericRatio',
        'SpecialCharRatio',
        'VowelRatio',
        'ConsoantSequence',
        'VowelSequence',
        'NumericSequence',
        'SpecialCharSequence',
        'DomainLength',
    ]

    # We extract features for the registrable root (sld.suffix)
    for i, dom in enumerate(sorted(discovered)):
        try:
            feats = extract_features_for_domain(dom)
            if args.dns_sleep > 0:
                time.sleep(args.dns_sleep)
        except Exception as e:
            print(f"[WARN] DNS feature extraction failed for {dom}: {e}", file=sys.stderr)
            continue
        row = {'Domain': dom}
        row.update(feats)
        rows.append(row)

    if not rows:
        print("No features extracted. Exiting.", file=sys.stderr)
        sys.exit(0)

    df = pd.DataFrame(rows)
    # Order columns
    ordered_cols = (['Domain'] if not args.no_domain_col else []) + feature_cols
    df = df[ordered_cols]

    if args.include_class_column:
        df['Class'] = ""  # blank label to match your training schema

    df.to_csv(args.output, index=False, encoding="utf-8")
    print(f"[3/3] Wrote {len(df)} rows to {args.output}")
    print("Done.")

if __name__ == "__main__":
    main()
