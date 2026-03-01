# Public Smart Contract Audit Corpus and Attack Taxonomy
Date: 2026-02-28 (America/New_York)

## 1. Scope and output
This document provides:
1. A large public-audit corpus index for AI training.
2. A source map showing where reports are publicly available.
3. Attack-chain examples from public incidents.
4. Bug hunting taxonomy split into `Solidity`, `Rust-based`, and `Protocol/Economic`.

## 2. Collected corpus files
All files are in this folder:
`/home/bratwork/Desktop/Hacking attacks/research_output`

| File | Links | Source type | Notes |
|---|---:|---|---|
| `code4rena_reports.txt` | 402 | Competitive audit final report pages | `https://code4rena.com/reports/<slug>` |
| `code4rena_submissions.txt` | 402 | Competitive findings/submissions pages | `https://code4rena.com/audits/<slug>/submissions` |
| `sherlock_contests.txt` | 230 | Sherlock contest report repos | Non-judging repos in `sherlock-audit` org |
| `sherlock_judging.txt` | 229 | Sherlock judging repos | Judging-phase repos in `sherlock-audit` org |
| `cantina_competitions.txt` | 166 | Cantina competition pages | UUID-based competition URLs |
| `consensys_diligence_audits.txt` | 140 | Consensys Diligence public audit archive | `diligence.security/audits/...` |
| `nethermind_pdf_reports.txt` | 164 | PDF reports | `NethermindEth/PublicAuditReports` |
| `quillhash_pdf_reports.txt` | 855 | PDF reports | `Quillhash/QuillAudit_smart_contract_audit_Reports` |
| `trailofbits_pdf_reports.txt` | 579 | PDF reports | `trailofbits/publications` |
| `techrate_report_files.txt` | 2191 | Report files (`.pdf/.md/.txt`) | `TechRate/Smart-Contract-Audits` |
| `all_public_audit_links_dedup.txt` | 5358 | Combined deduplicated index | Union of all files above |
| `normalized_reports_index.csv` | 5358 rows | Normalized training index | Unified schema across all sources |
| `source_summary.csv` | 10 rows | Source-level distribution | Report counts per source platform |
| `language_summary.csv` | 6 rows | Language distribution | Inferred from URL/project metadata |
| `chain_summary.csv` | 6 rows | Chain/VM distribution | Inferred from URL/project metadata |
| `code4rena_severity_counts.csv` | 402 rows | C4 per-report severity buckets | Parsed from public C4 report pages |
| `bug_taxonomy_separated.csv` | 33 rows | Bug separation taxonomy | Solidity, Rust-based, Protocol/Economic |
| `checklist_bug_acceptance_by_program.csv` | 25 rows | Program-wise bug checklist | Governance, EVM, Protocol, Solidity, Rust |
| `checklist_bug_acceptance_by_program.md` | Checklist doc | Human-readable checklist | Includes acceptance-rate proxy per program type |
| `checklist_program_acceptance_summary.csv` | 5 rows | Program acceptance summary | HM-rate proxy by program type |

Total indexed links across these files: **5358** (deduplicated union)

## 2.1 Extra writeup sources (Medium + Twitter/X)
| File | Links/Rows | Scope |
|---|---:|---|
| `medium_audit_writeups.txt` | 17 links | Medium writeups from security/audit tags |
| `medium_audit_writeups.csv` | 17 rows | Medium title/link/date/tag capture |
| `twitter_security_writeups_from_rekt.txt` | 147 links | Twitter/X status links cited in Rekt incident writeups |
| `twitter_security_writeups_from_rekt.csv` | 148 rows | Mapping between Rekt article and status links |
| `twitter_audit_and_incident_handles.txt` | 14 handles | Curated accounts for ongoing monitoring |

Note:
1. Medium tag feeds contain noise/spam and should be quality-filtered before model training.
2. Twitter/X direct search scraping is unreliable without API access; current set is sourced from public incident writeups plus curated handles.

## 3. Primary public sources used
1. Code4rena reports: https://code4rena.com/reports
2. Code4rena GitHub org: https://github.com/code-423n4
3. Sherlock contests portal: https://audits.sherlock.xyz/contests
4. Sherlock audit repos: https://github.com/sherlock-audit
5. Cantina competitions: https://cantina.xyz/opportunities/competitions
6. Consensys Diligence audits archive: https://diligence.security/audits/
7. Nethermind public audit reports: https://github.com/NethermindEth/PublicAuditReports
8. Quillhash public report repo: https://github.com/Quillhash/QuillAudit_smart_contract_audit_Reports
9. Trail of Bits publications repo: https://github.com/trailofbits/publications
10. TechRate audit repo: https://github.com/TechRate/Smart-Contract-Audits

## 4. Public attack-chain examples (for training labels)
| Incident | Typical attack chain | Main class | Bucket |
|---|---|---|---|
| bZx | Flash loan -> oracle price distortion -> bad collateralization/liquidation path -> drain | Oracle manipulation | Protocol/Economic |
| Wormhole | Forged/invalid verification path -> bridge mint without valid guardian proof | Message/auth validation failure | Protocol + Contract |
| Nomad | Incorrect trusted root/init state -> arbitrary message replay/acceptance -> bridge drain | Initialization/auth bug | Protocol + Contract |
| Mango Markets | Capital amplification -> low-liquidity oracle manipulation -> over-borrow -> bad debt | Economic/oracle exploit | Protocol/Economic |
| Euler | State-manipulation sequence (donation/liquidation mechanics) -> insolvency extraction | Liquidation/accounting logic | Protocol + Contract |
| Curve (Vyper incident) | Compiler/runtime bug condition -> reentrancy window -> pool drain | Compiler-level reentrancy risk | Language/Compiler |
| KyberSwap Elastic | Precision/rounding path abuse -> accounting mismatch -> value extraction | Math/rounding exploit | Contract + Protocol |
| Ronin Bridge | Validator key compromise -> fraudulent approvals -> bridge withdrawal | Key/control-plane compromise | Protocol/Operational |
| Poly Network | Cross-chain privileged call abuse -> unauthorized fund transfer | Cross-chain auth failure | Protocol |
| Cream (AMP incident) | Reentrancy via token callback behavior -> repeated borrow/update imbalance | Reentrancy | Solidity/Contract |

Reference incident links:
1. https://rekt.news/bzx-rekt
2. https://rekt.news/wormhole-rekt
3. https://rekt.news/nomad-rekt
4. https://rekt.news/mango-markets-rekt
5. https://rekt.news/euler-rekt
6. https://rekt.news/curve-finance-rekt
7. https://rekt.news/kyberswap-rekt
8. https://rekt.news/ronin-rekt
9. https://rekt.news/polynetwork-rekt
10. https://rekt.news/cream-rekt

## 5. Bug taxonomy for hunting
### 5.1 Solidity-focused bug classes
1. Access control mistakes (`onlyOwner` gaps, role escalation, initializer abuse).
2. Reentrancy (`external call before state update`, callback-based reentry).
3. Signature/auth bugs (`ecrecover` misuse, missing domain separator, replay).
4. Arithmetic/precision issues (`rounding`, unit mismatch, decimal conversion).
5. Upgradeability/storage hazards (`delegatecall`, storage collisions, uninitialized proxies).
6. Oracle integration bugs (stale price, manipulable TWAP windows, bad decimals).
7. Accounting and share math bugs (incorrect mint/burn/share conversions).
8. Liquidation/borrow logic flaws (health factor miscalc, bad close-factor rules).
9. Unsafe external call assumptions (token behavior assumptions, return-value handling).
10. Invariant breaks across multi-step state transitions.

### 5.2 Rust-based smart contract bug classes (Solana/CosmWasm/Substrate style)
1. Missing signer/authority checks.
2. Account constraint validation gaps (owner, seeds, bump, executable flags).
3. PDA seed collisions or incorrect derivation assumptions.
4. Cross-program invocation trust errors.
5. Serialization/deserialization confusion and type-casting bugs.
6. Arithmetic overflow/underflow and precision loss in fixed-point math.
7. Account lifecycle issues (init/reinit/close/rent-exempt edge cases).
8. State versioning/migration bugs in upgrade paths.
9. Privilege escalation through improper account mutability checks.
10. Non-atomic multi-instruction flow assumptions.

### 5.3 Protocol/economic bug classes
1. Oracle manipulation and liquidity spoofing.
2. Flash-loan amplified state attacks.
3. Governance takeover and parameter hijacking.
4. Cross-chain message validation failures.
5. Bridge trust-model/key-management breakdowns.
6. Incentive exploits (reward abuse, recursive farming loops).
7. MEV-aware path abuse (sandwich/liquidation/front-run dependency).
8. Insolvency design flaws (bad collateral assumptions, unbounded debt paths).
9. Fee/rounding value leakage at scale.
10. Sequencing and liveness assumptions that break under adversarial ordering.

## 6. Suggested labeling schema for AI dataset build
Use one row per finding/report and normalize:

1. `source_platform` (`code4rena`, `sherlock`, `cantina`, `firm_repo`, etc.)
2. `source_url`
3. `project_name`
4. `chain_or_vm` (`EVM`, `Solana`, `Cosmos`, `Move`, etc.)
5. `language` (`Solidity`, `Rust`, `Vyper`, `Move`, mixed)
6. `finding_id_or_title`
7. `severity_raw`
8. `severity_normalized` (`critical/high/medium/low/info`)
9. `bug_family` (from taxonomy above)
10. `attack_chain_stage` (`entry`, `auth bypass`, `state corruption`, `extraction`)
11. `root_cause_type` (`logic`, `math`, `auth`, `oracle`, `ops`, `compiler`)
12. `exploit_prerequisites`
13. `fix_pattern`
14. `report_date`
15. `public_disclosure_date`

CSV header file created:
`/home/bratwork/Desktop/Hacking attacks/research_output/training_schema.csv`

## 7. Practical next step for charting
The corpus is now ready for parsing and charting from the files in `research_output/`.
Recommended first charts:
1. Findings by `bug_family` and `severity_normalized`.
2. Findings split by `Solidity` vs `Rust` vs `Protocol/Economic`.
3. Time trend of high/critical findings by platform.

Generated chart outputs:
1. `/home/bratwork/Desktop/Hacking attacks/research_output/charts/source_platform_counts.png`
2. `/home/bratwork/Desktop/Hacking attacks/research_output/charts/language_counts.png`
3. `/home/bratwork/Desktop/Hacking attacks/research_output/charts/chain_counts.png`
4. `/home/bratwork/Desktop/Hacking attacks/research_output/charts/severity_counts.png`
5. `/home/bratwork/Desktop/Hacking attacks/research_output/charts/bug_family_counts.png`
6. `/home/bratwork/Desktop/Hacking attacks/research_output/charts/code4rena_severity_totals.png`

Coverage caveat:
1. `severity_counts.png` currently contains rich severity labels for Code4rena and `unknown` for most non-C4 sources.
2. `bug_family_counts.png` is mostly `unknown` until finding-level bug labels are added to `normalized_reports_index.csv`.

## 8. Program-wise Checklist Outputs
Created files:
1. `/home/bratwork/Desktop/Hacking attacks/research_output/checklist_bug_acceptance_by_program.md`
2. `/home/bratwork/Desktop/Hacking attacks/research_output/checklist_bug_acceptance_by_program.csv`
3. `/home/bratwork/Desktop/Hacking attacks/research_output/checklist_program_acceptance_summary.csv`

These separate checklist tracks for:
1. Governance Program
2. EVM Program
3. Protocol Bugs
4. Solidity Problems
5. Rust-Based Programs
