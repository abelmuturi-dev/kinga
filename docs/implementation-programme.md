# Kinga implementation programme: 1:6 module system

This programme follows the requested ratio: one cohesive new module for each six related improvements. The two module groups below cover the twelve requested capabilities.

## Group 1 — Security intelligence module

New module: `src/intelligence/`

1. Live OSV vulnerability intelligence with optional online updates and local cache.
2. AST and data-flow analysis adapters; keep existing regex rules as fallback.
3. Authenticated web-scan credential handling with scoped, redacted, opt-in sessions.
4. Safe remediation patch generation with explicit approval and verification.
5. Developer workflow adapters for GitHub Actions, pre-commit, editor and watch mode.
6. Git history secret scanning; credential verification remains separately opt-in.

## Group 2 — Assurance and evidence module

New module: `src/benchmark/`

7. Expanded dependency ecosystems and CycloneDX SBOM output.
8. Advanced web checks: DNS/email posture, subdomain takeover signals and JS bundle/source-map review.
9. Repeatable vulnerable-app benchmark fixtures and precision/recall reporting.
10. Compliance mappings for ASVS, PCI DSS, SOC 2 and ISO 27001, with evidence links.
11. Local scan history, comparison and security trend tracking.
12. Optional local-model advisor adapter. The curated rules and evidence remain authoritative.

## Delivery rules

- Preserve existing commands, report formats, configuration compatibility and offline scanning.
- Never send credentials to unrelated origins; never put secrets in logs or reports.
- Do not execute project code as part of static analysis.
- Auto-fixes are previews until the user approves application.
- Network intelligence updates are optional; cached and offline operation remain supported.
- A feature is complete only when its implementation, tests, documentation and CI checks pass.
- Do not describe pattern matches as proven exploitability. Report the evidence and confidence honestly.

## Initial module APIs

- `src/intelligence/osv.ts`: bounded OSV batch query, schema-checked cache read/write and exact-version cache lookup.
- `src/benchmark/metrics.ts`: deterministic confusion-matrix, precision, recall, F1 and per-rule metrics.

These are foundational implementations. The remaining capabilities require integration into the scanner lifecycle and will be delivered as tested increments rather than empty command stubs.
