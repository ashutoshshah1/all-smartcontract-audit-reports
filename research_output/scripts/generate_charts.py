#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def save_bar(df: pd.DataFrame, x_col: str, y_col: str, title: str, out_path: Path) -> None:
    plt.figure(figsize=(12, 6))
    plt.bar(df[x_col], df[y_col])
    plt.title(title)
    plt.xlabel(x_col)
    plt.ylabel(y_col)
    plt.xticks(rotation=40, ha="right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate audit dataset charts")
    parser.add_argument("--base-dir", default="research_output", help="Base research output directory")
    args = parser.parse_args()

    base = Path(args.base_dir).resolve()
    charts = base / "charts"
    charts.mkdir(parents=True, exist_ok=True)

    dataset_path = base / "normalized_reports_index.csv"
    if not dataset_path.exists():
        raise SystemExit(f"missing dataset: {dataset_path}")

    df = pd.read_csv(dataset_path)
    if df.empty:
        raise SystemExit("dataset is empty")

    # Source/platform distribution
    src = (
        df.groupby("source_platform", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    save_bar(src, "source_platform", "report_count", "Report Count by Source Platform", charts / "source_platform_counts.png")

    # Language distribution
    lang = (
        df.assign(language=df["language"].fillna("").replace("", "unknown"))
        .groupby("language", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    save_bar(lang, "language", "report_count", "Report Count by Language", charts / "language_counts.png")

    # Chain distribution
    chain = (
        df.assign(chain_or_vm=df["chain_or_vm"].fillna("").replace("", "unknown"))
        .groupby("chain_or_vm", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    save_bar(chain, "chain_or_vm", "report_count", "Report Count by Chain/VM", charts / "chain_counts.png")

    # Severity distribution (falls back to unknown when unlabeled)
    sev = (
        df.assign(severity_normalized=df["severity_normalized"].fillna("").replace("", "unknown"))
        .groupby("severity_normalized", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    save_bar(sev, "severity_normalized", "report_count", "Report Count by Severity (Normalized)", charts / "severity_counts.png")

    # Bug family distribution (falls back to unknown when unlabeled)
    bug = (
        df.assign(bug_family=df["bug_family"].fillna("").replace("", "unknown"))
        .groupby("bug_family", dropna=False)
        .size()
        .reset_index(name="report_count")
        .sort_values("report_count", ascending=False)
    )
    save_bar(bug, "bug_family", "report_count", "Report Count by Bug Family", charts / "bug_family_counts.png")

    # Code4rena severity totals chart (if file exists)
    c4_path = base / "code4rena_severity_counts.csv"
    if c4_path.exists():
        c4 = pd.read_csv(c4_path)
        if not c4.empty:
            totals = c4[["high", "medium", "low", "non_critical", "gas"]].sum().reset_index()
            totals.columns = ["severity_bucket", "count"]
            save_bar(
                totals,
                "severity_bucket",
                "count",
                "Code4rena Aggregate Findings Buckets",
                charts / "code4rena_severity_totals.png",
            )

    print(f"charts_dir={charts}")
    for p in sorted(charts.glob("*.png")):
        print(p.name)


if __name__ == "__main__":
    main()
