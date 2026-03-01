#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd
import requests


SEVERITY_PATTERNS = {
    "high": re.compile(r"High Risk Findings \((\d+)\)", re.IGNORECASE),
    "medium": re.compile(r"Medium Risk Findings \((\d+)\)", re.IGNORECASE),
    "low": re.compile(r"Low Risk Findings \((\d+)\)", re.IGNORECASE),
    "non_critical": re.compile(r"Non-?Critical (?:Findings|Issues) \((\d+)\)", re.IGNORECASE),
    "gas": re.compile(r"Gas (?:Findings|Optimizations) \((\d+)\)", re.IGNORECASE),
}


def normalize_slug_name(value: str) -> str:
    value = value.strip("/").split("/")[-1]
    value = re.sub(r"^\d{4}-\d{2}-", "", value)
    value = re.sub(r"-judging$", "", value)
    value = value.replace("-", " ").strip()
    return re.sub(r"\s+", " ", value).title()


def parse_date_from_text(value: str) -> Optional[str]:
    match = re.search(r"(20\d{2})-(\d{2})", value)
    if not match:
        return None
    year, month = int(match.group(1)), int(match.group(2))
    try:
        return dt.date(year, month, 1).isoformat()
    except ValueError:
        return None


def infer_chain_and_language(text: str, source_platform: str) -> Tuple[str, str]:
    t = text.lower()
    if any(k in t for k in ("solana", "anchor", "serum", "spl-token", "meteora")):
        return "Solana", "Rust"
    if any(k in t for k in ("sui", "aptos", "move", "initia-move")):
        return "MoveVM", "Move"
    if any(k in t for k in ("starknet", "cairo")):
        return "Starknet", "Cairo"
    if any(k in t for k in ("cosmos", "cosmwasm", "ibc", "osmosis")):
        return "Cosmos", "Rust"
    if any(k in t for k in ("substrate", "polkadot", "ink!")):
        return "Substrate", "Rust"
    if any(k in t for k in ("vyper",)):
        return "EVM", "Vyper"
    if any(k in t for k in ("tezos", "michelson")):
        return "Tezos", "Michelson"
    if source_platform in {
        "code4rena",
        "sherlock",
        "cantina",
        "consensys_diligence",
        "nethermind_reports",
        "quillhash_reports",
        "techrate_reports",
        "trailofbits_publications",
    }:
        return "EVM", "Solidity"
    return "", ""


def row_template() -> Dict[str, str]:
    return {
        "source_platform": "",
        "source_url": "",
        "project_name": "",
        "chain_or_vm": "",
        "language": "",
        "finding_id_or_title": "",
        "severity_raw": "",
        "severity_normalized": "",
        "bug_family": "",
        "attack_chain_stage": "",
        "root_cause_type": "",
        "exploit_prerequisites": "",
        "fix_pattern": "",
        "report_date": "",
        "public_disclosure_date": "",
    }


def derive_row(url: str, source_platform: str) -> Dict[str, str]:
    row = row_template()
    row["source_platform"] = source_platform
    row["source_url"] = url

    if source_platform in {"code4rena", "code4rena_submissions"}:
        slug = url.rstrip("/").split("/")[-1]
        if source_platform == "code4rena_submissions":
            slug = url.rstrip("/").split("/")[-2]
        row["project_name"] = normalize_slug_name(slug)
        d = parse_date_from_text(slug)
        if d:
            row["report_date"] = d
            row["public_disclosure_date"] = d
    elif source_platform in {"sherlock", "sherlock_judging"}:
        repo = url.rstrip("/").split("/")[-1]
        row["project_name"] = normalize_slug_name(repo)
        d = parse_date_from_text(repo)
        if d:
            row["report_date"] = d
            row["public_disclosure_date"] = d
    elif source_platform == "cantina":
        comp_id = url.rstrip("/").split("/")[-1]
        row["project_name"] = comp_id
    elif source_platform == "consensys_diligence":
        parts = url.rstrip("/").split("/")
        row["project_name"] = normalize_slug_name(parts[-1])
        if len(parts) >= 2 and re.match(r"20\d{2}", parts[-3]) and re.match(r"\d{2}", parts[-2]):
            row["report_date"] = f"{parts[-3]}-{parts[-2]}-01"
            row["public_disclosure_date"] = f"{parts[-3]}-{parts[-2]}-01"
    else:
        # GitHub file URL
        filename = url.rstrip("/").split("/")[-1]
        name = re.sub(r"\.(pdf|md|txt)$", "", filename, flags=re.IGNORECASE)
        row["project_name"] = normalize_slug_name(name)
        d = parse_date_from_text(filename)
        if d:
            row["report_date"] = d
            row["public_disclosure_date"] = d

    chain, language = infer_chain_and_language(
        " ".join([row["project_name"], row["source_url"], row["source_platform"]]),
        source_platform,
    )
    row["chain_or_vm"] = chain
    row["language"] = language
    return row


def read_urls(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def parse_c4_severity_page(html: str) -> Dict[str, int]:
    out = {"high": 0, "medium": 0, "low": 0, "non_critical": 0, "gas": 0}
    for key, pattern in SEVERITY_PATTERNS.items():
        matches = pattern.findall(html)
        if matches:
            out[key] = sum(int(x) for x in matches)
    return out


def fetch_c4_severity(url: str, timeout: int = 12) -> Dict[str, int]:
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        if resp.status_code != 200:
            return {"high": 0, "medium": 0, "low": 0, "non_critical": 0, "gas": 0}
        return parse_c4_severity_page(resp.text)
    except requests.RequestException:
        return {"high": 0, "medium": 0, "low": 0, "non_critical": 0, "gas": 0}


def attach_c4_severity(
    rows: List[Dict[str, str]],
    max_workers: int = 10,
) -> Tuple[List[Dict[str, str]], pd.DataFrame]:
    c4_rows = [r for r in rows if r["source_platform"] == "code4rena"]
    if not c4_rows:
        return rows, pd.DataFrame(columns=["source_url", "high", "medium", "low", "non_critical", "gas"])

    sev_by_url: Dict[str, Dict[str, int]] = {}
    completed = 0
    total = len(c4_rows)
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fetch_c4_severity, r["source_url"]): r["source_url"] for r in c4_rows}
        for fut in as_completed(futures):
            url = futures[fut]
            sev_by_url[url] = fut.result()
            completed += 1
            if completed % 50 == 0 or completed == total:
                print(f"c4_severity_progress={completed}/{total}")

    for row in rows:
        if row["source_platform"] != "code4rena":
            continue
        sev = sev_by_url.get(row["source_url"], {"high": 0, "medium": 0, "low": 0, "non_critical": 0, "gas": 0})
        row["severity_raw"] = f"H={sev['high']};M={sev['medium']};L={sev['low']};NC={sev['non_critical']};G={sev['gas']}"
        if sev["high"] > 0:
            row["severity_normalized"] = "high"
        elif sev["medium"] > 0:
            row["severity_normalized"] = "medium"
        elif sev["low"] > 0 or sev["non_critical"] > 0:
            row["severity_normalized"] = "low"
        elif sev["gas"] > 0:
            row["severity_normalized"] = "info"
        else:
            row["severity_normalized"] = ""

    c4_df = pd.DataFrame(
        [
            {"source_url": url, **vals}
            for url, vals in sorted(sev_by_url.items(), key=lambda x: x[0])
        ]
    )
    return rows, c4_df


def collect_rows(base: Path) -> List[Dict[str, str]]:
    mapping = {
        "code4rena_reports.txt": "code4rena",
        "code4rena_submissions.txt": "code4rena_submissions",
        "sherlock_contests.txt": "sherlock",
        "sherlock_judging.txt": "sherlock_judging",
        "cantina_competitions.txt": "cantina",
        "consensys_diligence_audits.txt": "consensys_diligence",
        "nethermind_pdf_reports.txt": "nethermind_reports",
        "quillhash_pdf_reports.txt": "quillhash_reports",
        "trailofbits_pdf_reports.txt": "trailofbits_publications",
        "techrate_report_files.txt": "techrate_reports",
    }
    rows: List[Dict[str, str]] = []
    for file_name, source_platform in mapping.items():
        for url in read_urls(base / file_name):
            rows.append(derive_row(url, source_platform))
    return rows


def write_csv(path: Path, rows: Iterable[Dict[str, str]]) -> None:
    rows = list(rows)
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build normalized public audit dataset")
    parser.add_argument("--base-dir", default="research_output", help="Base research output directory")
    parser.add_argument("--workers", type=int, default=10, help="Parallel workers for Code4rena severity fetch")
    parser.add_argument("--skip-c4-severity", action="store_true", help="Skip network fetch for Code4rena severity counts")
    args = parser.parse_args()

    base = Path(args.base_dir).resolve()
    rows = collect_rows(base)
    c4_df = pd.DataFrame(columns=["source_url", "high", "medium", "low", "non_critical", "gas"])
    if not args.skip_c4_severity:
        rows, c4_df = attach_c4_severity(rows, max_workers=args.workers)

    out_csv = base / "normalized_reports_index.csv"
    write_csv(out_csv, rows)

    if not c4_df.empty:
        c4_df.sort_values("source_url").to_csv(base / "code4rena_severity_counts.csv", index=False)

    df = pd.DataFrame(rows)
    source_summary = (
        df.groupby("source_platform", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    source_summary.to_csv(base / "source_summary.csv", index=False)

    language_summary = (
        df.assign(language=df["language"].replace("", "unknown"))
        .groupby("language", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    language_summary.to_csv(base / "language_summary.csv", index=False)

    chain_summary = (
        df.assign(chain_or_vm=df["chain_or_vm"].replace("", "unknown"))
        .groupby("chain_or_vm", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    chain_summary.to_csv(base / "chain_summary.csv", index=False)

    print(f"rows={len(rows)}")
    print(f"output={out_csv}")
    print(f"source_summary={base / 'source_summary.csv'}")
    if (base / "code4rena_severity_counts.csv").exists():
        print(f"code4rena_severity_counts={base / 'code4rena_severity_counts.csv'}")


if __name__ == "__main__":
    main()
