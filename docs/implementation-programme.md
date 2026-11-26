# Kinga implementation programme: 1:6 module system

This programme follows the requested ratio: one cohesive module for each six related improvements. The groups organize the twelve capabilities; they do not imply that every capability is already complete.

## Group 1 — Security intelligence module

Module area: `src/intelligence/`

1. Live OSV vulnerability intelligence with optional online updates and a local cache. **Initial implementation exists.**
2. AST and data-flow analysis adapters, retaining existing pattern rules as a fallback. **Planned; current code scanning remains pattern-based.**
3. Authenticated web-scan credential handling with scoped, redacted, opt-in sessions. **Planned.**
4. Safe remediation patch generation with explicit approval and verification. **Planned.**
5. Developer workflow adapters for GitHub Actions, pre-commit, editor and watch mode. **Partial: CI and self-scanning exist; editor, pre-commit, watch mode and PR annotations remain planned.**
6. Git history secret scanning with credential verification separately opt-in. **Initial implementation now exists in `src/assurance/git-history.ts`; it scans bounded local history and never validates or prints credentials.**

## Group 2 — Assurance and evidence module

Module area: `src/assurance/`; benchmark support lives in `src/benchmark/`.

7. Expanded dependency ecosystems and CycloneDX SBOM output. **Initial SBOM support exists for npm, Python, Go, Rust, Ruby, Composer, Maven and NuGet lock/manifest formats.**
8. Advanced web checks: DNS/email posture, subdomain takeover signals and JavaScript bundle/source-map review. **Partial: passive DNS/email signals and local JavaScript inspection exist; takeover indicators are not proof, and deeper web checks remain planned.**
9. Repeatable vulnerable-app benchmarks and precision/recall reporting. **Initial fixtures and metric calculations exist; a full OWASP Juice Shop/DVWA benchmark campaign and published measured results remain planned.**
10. Compliance mappings for ASVS, PCI DSS, SOC 2 and ISO 27001, with evidence links. **Indicative mappings exist; they are not audit conclusions or certifications.**
11. Local scan history, comparison and security trend tracking. **Initial local snapshot and comparison support exists.**
12. Optional local-model advisor adapter. **Initial Ollama loopback adapter exists; curated rules and evidence remain authoritative.**

## Additional assurance capability

Kinga now includes a static OpenAPI 3.0/3.1 and Swagger 2.0 JSON contract audit. It checks cleartext non-local servers, embedded URL credentials, missing or anonymous security requirements, undefined security schemes, query-string API keys, Basic authentication and operation IDs. It does not probe endpoints or prove runtime authorization. See [API contract audit](api-contract.md).

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
- `src/assurance/api-contract.ts`: static OpenAPI/Swagger JSON security-contract inspection.
- `src/assurance/git-history.ts`: bounded local Git patch inspection with secret-value redaction.
- `src/benchmark/metrics.ts`: deterministic confusion-matrix, precision, recall, F1 and per-rule metrics.

The modules are delivered incrementally. Remaining capabilities require integration into the scanner lifecycle and will be delivered as tested increments rather than empty command stubs.
