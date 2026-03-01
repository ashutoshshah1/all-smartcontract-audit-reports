#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import pandas as pd
import requests


USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"


@dataclass(frozen=True)
class BugChecklistItem:
    program_type: str
    bug_family: str
    checklist_item: str
    keywords: Tuple[str, ...]


CHECKLIST_ITEMS: List[BugChecklistItem] = [
    # Governance program checklist
    BugChecklistItem(
        "Governance Program",
        "Vote Power Manipulation",
        "Validate vote snapshots and anti-flashloan voting controls.",
        ("snapshot", "vote power", "voting power", "flash loan governance", "governance attack"),
    ),
    BugChecklistItem(
        "Governance Program",
        "Timelock/Execution Bypass",
        "Enforce timelock delay and execution authorization invariants.",
        ("timelock", "delay bypass", "queue bypass", "execute proposal"),
    ),
    BugChecklistItem(
        "Governance Program",
        "Proposal Replay/ID Collision",
        "Prevent proposal replay and execution of stale payloads.",
        ("proposal replay", "replay", "proposal id", "duplicate proposal"),
    ),
    BugChecklistItem(
        "Governance Program",
        "Privilege Escalation",
        "Ensure emergency/admin roles cannot bypass governance unexpectedly.",
        ("onlyowner", "admin", "access control", "privilege", "role"),
    ),
    BugChecklistItem(
        "Governance Program",
        "Parameter Risk Controls",
        "Constrain governance-updated risk parameters with bounded ranges.",
        ("parameter", "risk parameter", "collateral factor", "liquidation threshold"),
    ),
    # EVM checklist
    BugChecklistItem(
        "EVM Program",
        "Reentrancy",
        "Apply CEI pattern, reentrancy guards, and callback hardening.",
        ("reentrancy", "re-entrancy", "callback"),
    ),
    BugChecklistItem(
        "EVM Program",
        "Signature Replay/Auth",
        "Use strict nonce/domain separation and signer checks.",
        ("signature replay", "permit", "eip-712", "nonce", "ecrecover"),
    ),
    BugChecklistItem(
        "EVM Program",
        "Upgradeable Storage Safety",
        "Protect proxy initialization and storage layout compatibility.",
        ("proxy", "initializer", "storage collision", "delegatecall", "upgrade"),
    ),
    BugChecklistItem(
        "EVM Program",
        "Math/Precision",
        "Audit fixed-point math, decimal normalization, and rounding direction.",
        ("rounding", "precision", "decimal", "overflow", "underflow"),
    ),
    BugChecklistItem(
        "EVM Program",
        "External Call Safety",
        "Handle non-standard token behavior and failed low-level calls.",
        ("low-level call", "safeerc20", "return value", "external call"),
    ),
    # Protocol checklist
    BugChecklistItem(
        "Protocol Bugs",
        "Oracle Manipulation",
        "Harden price sources against thin-liquidity and short-window manipulation.",
        ("oracle", "price manipulation", "twap", "spot price"),
    ),
    BugChecklistItem(
        "Protocol Bugs",
        "Liquidation/Accounting Invariants",
        "Validate health factor, debt accounting, and share conversion invariants.",
        ("liquidation", "health factor", "accounting", "share", "insolvency"),
    ),
    BugChecklistItem(
        "Protocol Bugs",
        "Flash-Loan Amplification",
        "Model one-block adversarial capital scenarios in core flows.",
        ("flash loan", "one block", "amplified"),
    ),
    BugChecklistItem(
        "Protocol Bugs",
        "Bridge/Cross-Chain Validation",
        "Verify message proofs, signer quorum, and replay protection cross-chain.",
        ("bridge", "cross-chain", "message validation", "proof verification"),
    ),
    BugChecklistItem(
        "Protocol Bugs",
        "MEV/Ordering Dependence",
        "Ensure protocol safety under adversarial transaction ordering.",
        ("mev", "front-run", "back-run", "sandwich", "ordering"),
    ),
    # Solidity-specific checklist
    BugChecklistItem(
        "Solidity Problems",
        "Access Control Gaps",
        "Check role boundaries and internal function reachability.",
        ("access control", "onlyowner", "role", "auth"),
    ),
    BugChecklistItem(
        "Solidity Problems",
        "State-Update Order",
        "Update state before external interaction in value-sensitive flows.",
        ("checks-effects-interactions", "state update", "external call", "reentrancy"),
    ),
    BugChecklistItem(
        "Solidity Problems",
        "Unsafe Delegatecall",
        "Restrict delegatecall targets and sanitize calldata context.",
        ("delegatecall", "implementation", "proxy"),
    ),
    BugChecklistItem(
        "Solidity Problems",
        "Permit/Approval Abuse",
        "Constrain approvals and verify permit signing context.",
        ("permit", "approval", "allowance", "signature"),
    ),
    BugChecklistItem(
        "Solidity Problems",
        "Invariant Drift via Rounding",
        "Test long-run precision behavior with adversarial pathing.",
        ("rounding", "precision", "invariant"),
    ),
    # Rust-specific checklist (extra useful split)
    BugChecklistItem(
        "Rust-Based Programs",
        "Signer/Authority Validation",
        "Enforce signer and authority constraints on every state transition.",
        ("signer", "authority", "constraint", "owner check"),
    ),
    BugChecklistItem(
        "Rust-Based Programs",
        "PDA/Seed Validation",
        "Validate PDA seeds, bump values, and deterministic address assumptions.",
        ("pda", "seed", "bump", "derived address"),
    ),
    BugChecklistItem(
        "Rust-Based Programs",
        "CPI Trust Boundaries",
        "Assume CPI targets may be adversarial unless explicitly verified.",
        ("cpi", "cross-program", "invoke"),
    ),
    BugChecklistItem(
        "Rust-Based Programs",
        "Serialization/Type Safety",
        "Protect against deserialization confusion and account type mismatch.",
        ("deserialize", "serialization", "type confusion", "borsh"),
    ),
    BugChecklistItem(
        "Rust-Based Programs",
        "Account Lifecycle",
        "Test init/reinit/close flows for unauthorized state reset paths.",
        ("reinit", "close account", "initialize", "rent exempt"),
    ),
]


def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def get_cache_path(cache_dir: Path, url: str) -> Path:
    slug = url.rstrip("/").split("/")[-1]
    slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", slug)
    return cache_dir / f"{slug}.html"


def fetch_with_cache(url: str, cache_dir: Path, timeout: int = 18) -> str:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = get_cache_path(cache_dir, url)
    if cache_path.exists():
        return cache_path.read_text(encoding="utf-8", errors="ignore")
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            return ""
        html = resp.text
        cache_path.write_text(html, encoding="utf-8")
        return html
    except requests.RequestException:
        return ""


def extract_hm_sections(html: str) -> str:
    if not html:
        return ""
    low = html.lower()
    # Common anchors in C4 report pages
    starts = []
    for marker in ('id="high-risk-findings', "high risk findings", "id=\"medium-risk-findings", "medium risk findings"):
        pos = low.find(marker)
        if pos != -1:
            starts.append(pos)
    if not starts:
        return ""
    start = min(starts)

    end_candidates = []
    for marker in (
        'id="low-risk',
        "low risk and non-critical",
        "gas optimizations",
        'id="summary',
        "<footer",
    ):
        pos = low.find(marker, start + 1)
        if pos != -1:
            end_candidates.append(pos)
    end = min(end_candidates) if end_candidates else len(low)
    return low[start:end]


def has_kw(text: str, keywords: Iterable[str]) -> bool:
    return any(k in text for k in keywords)


def compute_checklist(rows: List[Tuple[str, str]], items: List[BugChecklistItem]) -> pd.DataFrame:
    records = []
    total_reports = len(rows)
    for item in items:
        total_signal = 0
        hm_signal = 0
        for full_text, hm_text in rows:
            if has_kw(full_text, item.keywords):
                total_signal += 1
            if hm_text and has_kw(hm_text, item.keywords):
                hm_signal += 1
        rate = (hm_signal / total_signal * 100.0) if total_signal > 0 else 0.0
        if rate >= 60:
            band = "High"
        elif rate >= 30:
            band = "Medium"
        elif rate > 0:
            band = "Low"
        else:
            band = "None"
        records.append(
            {
                "program_type": item.program_type,
                "bug_family": item.bug_family,
                "checklist_item": item.checklist_item,
                "reports_scanned": total_reports,
                "reports_with_bug_signal": total_signal,
                "reports_with_HM_signal": hm_signal,
                "acceptance_rate_proxy_pct": round(rate, 2),
                "acceptance_signal_band": band,
                "keywords": ", ".join(item.keywords),
            }
        )
    df = pd.DataFrame(records).sort_values(["program_type", "acceptance_rate_proxy_pct"], ascending=[True, False])
    return df


def to_markdown(df: pd.DataFrame, out_path: Path, scan_scope_note: str) -> None:
    lines: List[str] = []
    lines.append("# Program-Wise Bug Checklist and Acceptance-Rate Proxy")
    lines.append("")
    lines.append(scan_scope_note)
    lines.append("")
    lines.append("Acceptance rate here is a **proxy**: `reports_with_HM_signal / reports_with_bug_signal` from public Code4rena report pages.")
    lines.append("")

    for program_type, gdf in df.groupby("program_type", sort=True):
        lines.append(f"## {program_type}")
        lines.append("")
        lines.append("| Checklist Item | Bug Family | HM Signal | Bug Signal | Acceptance Proxy | Band |")
        lines.append("|---|---|---:|---:|---:|---|")
        for _, row in gdf.iterrows():
            lines.append(
                f"| [ ] {row['checklist_item']} | {row['bug_family']} | "
                f"{int(row['reports_with_HM_signal'])} | {int(row['reports_with_bug_signal'])} | "
                f"{row['acceptance_rate_proxy_pct']:.2f}% | {row['acceptance_signal_band']} |"
            )
        lines.append("")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build per-program bug checklist with acceptance-rate proxy")
    parser.add_argument("--base-dir", default="research_output", help="Base research directory")
    parser.add_argument("--workers", type=int, default=12, help="Fetch concurrency for report HTML")
    args = parser.parse_args()

    base = Path(args.base_dir).resolve()
    cache_dir = base / "cache" / "c4_reports"
    report_urls = read_lines(base / "code4rena_reports.txt")

    rows: List[Tuple[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(fetch_with_cache, url, cache_dir): url for url in report_urls}
        completed = 0
        total = len(futures)
        for fut in concurrent.futures.as_completed(futures):
            html = fut.result()
            low = html.lower() if html else ""
            hm = extract_hm_sections(html)
            rows.append((low, hm))
            completed += 1
            if completed % 50 == 0 or completed == total:
                print(f"scan_progress={completed}/{total}")

    df = compute_checklist(rows, CHECKLIST_ITEMS)
    csv_path = base / "checklist_bug_acceptance_by_program.csv"
    md_path = base / "checklist_bug_acceptance_by_program.md"
    df.to_csv(csv_path, index=False)

    scan_note = (
        f"Scanned source set: `{len(report_urls)}` Code4rena report pages "
        f"(cached in `{cache_dir}`)."
    )
    to_markdown(df, md_path, scan_note)

    # Also emit a compact summary by program type
    summary = (
        df.groupby("program_type", dropna=False)[["reports_with_bug_signal", "reports_with_HM_signal"]]
        .sum()
        .reset_index()
    )
    summary["acceptance_rate_proxy_pct"] = (
        summary["reports_with_HM_signal"] / summary["reports_with_bug_signal"].replace(0, pd.NA) * 100.0
    ).fillna(0).round(2)
    summary.to_csv(base / "checklist_program_acceptance_summary.csv", index=False)

    print(f"csv={csv_path}")
    print(f"md={md_path}")
    print(f"summary={base / 'checklist_program_acceptance_summary.csv'}")


if __name__ == "__main__":
    main()
