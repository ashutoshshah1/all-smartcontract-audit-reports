#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Set, Tuple
from urllib.parse import urlsplit, urlunsplit

import pandas as pd
import requests


MEDIUM_TAGS = [
    "smart-contract-audit",
    "smart-contract-security",
    "web3-security",
    "defi-security",
    "solidity",
]

MEDIUM_KEEP_KEYWORDS = (
    "audit",
    "finding",
    "vulnerability",
    "exploit",
    "hack",
    "security",
    "post-mortem",
    "postmortem",
    "incident",
)

ARTICLE_LINK_RE = re.compile(r'href="(/[^"#]+)"')
TWITTER_STATUS_RE = re.compile(r"https?://(?:x|twitter)\.com/[^/\s\"')]+/status/\d+")


def canonicalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def fetch_text(url: str, timeout: int = 25) -> str:
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()
    return resp.text


def collect_medium(base: Path) -> Tuple[pd.DataFrame, List[str]]:
    rows = []
    links: Set[str] = set()
    for tag in MEDIUM_TAGS:
        feed_url = f"https://medium.com/feed/tag/{tag}"
        try:
            xml_data = fetch_text(feed_url)
            root = ET.fromstring(xml_data)
        except Exception:
            continue

        for item in root.findall(".//item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or "").strip()
            if not link:
                continue
            c_link = canonicalize_url(link)
            lower_title = title.lower()
            if not any(k in lower_title for k in MEDIUM_KEEP_KEYWORDS):
                continue
            links.add(c_link)
            rows.append(
                {
                    "source": "medium",
                    "tag": tag,
                    "title": title,
                    "url": c_link,
                    "pub_date_raw": pub_date,
                }
            )

    df = pd.DataFrame(rows).drop_duplicates(subset=["url", "title"]).sort_values(by=["pub_date_raw", "title"], ascending=False)
    out_txt = sorted(links)
    (base / "medium_audit_writeups.txt").write_text("\n".join(out_txt) + ("\n" if out_txt else ""), encoding="utf-8")
    df.to_csv(base / "medium_audit_writeups.csv", index=False)
    return df, out_txt


def collect_rekt_article_urls() -> List[str]:
    article_urls: Set[str] = set()
    for page in range(0, 40):
        url = f"https://rekt.news/?page={page}"
        try:
            html = fetch_text(url, timeout=20)
        except Exception:
            continue
        for rel in ARTICLE_LINK_RE.findall(html):
            if rel.startswith("/?") or rel.startswith("/tag") or rel.startswith("/author") or rel.startswith("/page"):
                continue
            # Prefer security incident and writeup style pages.
            if rel.count("/") > 1:
                continue
            article_urls.add(f"https://rekt.news{rel}")
    return sorted(article_urls)


def extract_twitter_links_from_article(url: str) -> Tuple[str, Set[str]]:
    try:
        html = fetch_text(url, timeout=20)
    except Exception:
        return url, set()
    links = {m.group(0).rstrip("),.]\"'") for m in TWITTER_STATUS_RE.finditer(html)}
    return url, links


def collect_twitter_from_rekt(base: Path) -> Tuple[pd.DataFrame, List[str]]:
    articles = collect_rekt_article_urls()
    rows = []
    all_links: Set[str] = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(extract_twitter_links_from_article, u) for u in articles]
        for fut in concurrent.futures.as_completed(futures):
            article_url, links = fut.result()
            if not links:
                continue
            slug = article_url.rstrip("/").split("/")[-1]
            for link in sorted(links):
                all_links.add(link)
                rows.append(
                    {
                        "source": "rekt_news",
                        "article_url": article_url,
                        "article_slug": slug,
                        "twitter_url": link,
                    }
                )

    df = pd.DataFrame(rows).drop_duplicates(subset=["twitter_url", "article_slug"]).sort_values(
        by=["article_slug", "twitter_url"]
    )
    out_txt = sorted(all_links)
    (base / "twitter_security_writeups_from_rekt.txt").write_text(
        "\n".join(out_txt) + ("\n" if out_txt else ""),
        encoding="utf-8",
    )
    df.to_csv(base / "twitter_security_writeups_from_rekt.csv", index=False)
    return df, out_txt


def write_curated_handles(base: Path) -> None:
    handles = [
        "https://x.com/code4rena",
        "https://x.com/sherlockdefi",
        "https://x.com/cantinaxyz",
        "https://x.com/solodit",
        "https://x.com/ConsensysAudits",
        "https://x.com/openzeppelin",
        "https://x.com/TrailOfBits",
        "https://x.com/NethermindEth",
        "https://x.com/QuillAudits_AI",
        "https://x.com/HalbornSecurity",
        "https://x.com/CertiKAlert",
        "https://x.com/BlockSecTeam",
        "https://x.com/peckshield",
        "https://x.com/RektHQ",
    ]
    (base / "twitter_audit_and_incident_handles.txt").write_text("\n".join(handles) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect Medium and Twitter writeups related to smart contract security")
    parser.add_argument("--base-dir", default="research_output", help="Base research output directory")
    args = parser.parse_args()

    base = Path(args.base_dir).resolve()
    base.mkdir(parents=True, exist_ok=True)

    medium_df, medium_links = collect_medium(base)
    twitter_df, twitter_links = collect_twitter_from_rekt(base)
    write_curated_handles(base)

    manifest = [
        f"medium_audit_writeups.txt {len(medium_links)}",
        f"medium_audit_writeups.csv {len(medium_df)}",
        f"twitter_security_writeups_from_rekt.txt {len(twitter_links)}",
        f"twitter_security_writeups_from_rekt.csv {len(twitter_df)}",
        "twitter_audit_and_incident_handles.txt 14",
    ]
    (base / "external_writeups_manifest.txt").write_text("\n".join(manifest) + "\n", encoding="utf-8")

    print("\n".join(manifest))


if __name__ == "__main__":
    main()
