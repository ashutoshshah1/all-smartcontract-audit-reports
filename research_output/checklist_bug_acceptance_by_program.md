# Program-Wise Bug Checklist and Acceptance-Rate Proxy

Scanned source set: `402` Code4rena report pages (cached in `/home/bratwork/Desktop/Hacking attacks/research_output/cache/c4_reports`).

Acceptance rate here is a **proxy**: `reports_with_HM_signal / reports_with_bug_signal` from public Code4rena report pages.

## EVM Program

| Checklist Item | Bug Family | HM Signal | Bug Signal | Acceptance Proxy | Band |
|---|---|---:|---:|---:|---|
| [ ] Audit fixed-point math, decimal normalization, and rounding direction. | Math/Precision | 132 | 402 | 32.84% | Medium |
| [ ] Apply CEI pattern, reentrancy guards, and callback hardening. | Reentrancy | 69 | 245 | 28.16% | Low |
| [ ] Use strict nonce/domain separation and signer checks. | Signature Replay/Auth | 39 | 214 | 18.22% | Low |
| [ ] Handle non-standard token behavior and failed low-level calls. | External Call Safety | 43 | 281 | 15.30% | Low |
| [ ] Protect proxy initialization and storage layout compatibility. | Upgradeable Storage Safety | 46 | 307 | 14.98% | Low |

## Governance Program

| Checklist Item | Bug Family | HM Signal | Bug Signal | Acceptance Proxy | Band |
|---|---|---:|---:|---:|---|
| [ ] Prevent proposal replay and execution of stale payloads. | Proposal Replay/ID Collision | 23 | 82 | 28.05% | Low |
| [ ] Ensure emergency/admin roles cannot bypass governance unexpectedly. | Privilege Escalation | 88 | 399 | 22.06% | Low |
| [ ] Validate vote snapshots and anti-flashloan voting controls. | Vote Power Manipulation | 22 | 116 | 18.97% | Low |
| [ ] Enforce timelock delay and execution authorization invariants. | Timelock/Execution Bypass | 28 | 148 | 18.92% | Low |
| [ ] Constrain governance-updated risk parameters with bounded ranges. | Parameter Risk Controls | 54 | 356 | 15.17% | Low |

## Protocol Bugs

| Checklist Item | Bug Family | HM Signal | Bug Signal | Acceptance Proxy | Band |
|---|---|---:|---:|---:|---|
| [ ] Verify message proofs, signer quorum, and replay protection cross-chain. | Bridge/Cross-Chain Validation | 35 | 86 | 40.70% | Medium |
| [ ] Validate health factor, debt accounting, and share conversion invariants. | Liquidation/Accounting Invariants | 122 | 309 | 39.48% | Medium |
| [ ] Harden price sources against thin-liquidity and short-window manipulation. | Oracle Manipulation | 66 | 192 | 34.38% | Medium |
| [ ] Ensure protocol safety under adversarial transaction ordering. | MEV/Ordering Dependence | 73 | 266 | 27.44% | Low |
| [ ] Model one-block adversarial capital scenarios in core flows. | Flash-Loan Amplification | 19 | 108 | 17.59% | Low |

## Rust-Based Programs

| Checklist Item | Bug Family | HM Signal | Bug Signal | Acceptance Proxy | Band |
|---|---|---:|---:|---:|---|
| [ ] Validate PDA seeds, bump values, and deterministic address assumptions. | PDA/Seed Validation | 144 | 402 | 35.82% | Medium |
| [ ] Test init/reinit/close flows for unauthorized state reset paths. | Account Lifecycle | 32 | 273 | 11.72% | Low |
| [ ] Protect against deserialization confusion and account type mismatch. | Serialization/Type Safety | 1 | 9 | 11.11% | Low |
| [ ] Enforce signer and authority constraints on every state transition. | Signer/Authority Validation | 14 | 176 | 7.95% | Low |
| [ ] Assume CPI targets may be adversarial unless explicitly verified. | CPI Trust Boundaries | 6 | 153 | 3.92% | Low |

## Solidity Problems

| Checklist Item | Bug Family | HM Signal | Bug Signal | Acceptance Proxy | Band |
|---|---|---:|---:|---:|---|
| [ ] Constrain approvals and verify permit signing context. | Permit/Approval Abuse | 88 | 324 | 27.16% | Low |
| [ ] Restrict delegatecall targets and sanitize calldata context. | Unsafe Delegatecall | 91 | 365 | 24.93% | Low |
| [ ] Check role boundaries and internal function reachability. | Access Control Gaps | 77 | 350 | 22.00% | Low |
| [ ] Test long-run precision behavior with adversarial pathing. | Invariant Drift via Rounding | 62 | 283 | 21.91% | Low |
| [ ] Update state before external interaction in value-sensitive flows. | State-Update Order | 56 | 265 | 21.13% | Low |

