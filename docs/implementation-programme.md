# Kinga implementation programme: 1:6 module system

This programme follows the requested ratio: one cohesive module for each six related improvements. The groups organize the twelve capabilities; they do not imply that every capability is complete.

## Group 1 — Security intelligence module

Module area: `src/intelligence/`, `src/scanners/code/` and `src/assurance/`.

1. Live OSV vulnerability intelligence with optional online updates and a local cache. **Initial implementation exists.**
2. AST and data-flow analysis adapters, retaining existing pattern rules as a fallback. **Initial implementation: TypeScript compiler AST pass for JavaScript/TypeScript, with variable propagation to selected command, SQL and DOM sinks. It is intraprocedural and heuristic; interprocedural, path-sensitive and other-language analysis remain planned.**
3. Authenticated web scanning with scoped credentials. **Initial implementation: opt-in Authorization/Cookie headers, exact-origin scoping, explicit authorization, HTTPS for non-loopback targets and no credential forwarding across redirects. Login scripts, refresh-token flows and identity-provider automation remain planned.**
4. Safe remediation patch generation. **Initial implementation: review-only patch preview for the `target="_blank"`/noopener rule. No source files are changed. More rule-specific patches, verification and approval workflows remain planned.**
5. Developer workflow integration. **Initial implementation: command-triggered VS Code diagnostics, opt-in Git pre-commit hook and recursive watch mode. GitHub PR annotations, editor code actions and marketplace packaging remain planned.**
6. Git history secret scanning. **Initial implementation exists in `src/assurance/git-history.ts`; it scans bounded local history and never validates or prints credentials.**

## Group 2 — Assurance and evidence module

Module area: `src/assurance/` and `src/benchmark/`.

7. Expanded dependency ecosystems and CycloneDX SBOM output. **Initial SBOM support exists for npm, Python, Go, Rust, Ruby, Composer, Maven and NuGet lock/manifest formats.**
8. Advanced web checks: DNS/email posture, subdomain takeover signals and JavaScript bundle/source-map review. **Partial: passive DNS/email signals and local JavaScript inspection exist; takeover indicators are not proof, and deeper web checks remain planned.**
9. Repeatable vulnerable-app benchmarks and precision/recall reporting. **Initial synthetic regression fixtures and a runnable metrics command exist. A held-out OWASP Juice Shop/DVWA campaign, manual adjudication and published independent measurements remain planned.**
10. Compliance mappings for ASVS, PCI DSS, SOC 2 and ISO 27001, with evidence links. **Indicative mappings exist; they are not audit conclusions or certifications.**
11. Local scan history, comparison and security trend tracking. **Initial local snapshot and comparison support exists.**
12. Optional local-model advisor adapter. **Initial Ollama loopback adapter exists; curated rules and evidence remain authoritative.**

## Additional API assurance

- Static OpenAPI 3.0/3.1 and Swagger 2.0 JSON contract auditing checks transport, credentials in server URLs, authentication declarations, anonymous alternatives, undefined schemes, query-string API keys, Basic authentication and operation IDs. See [API contract audit](api-contract.md).
- `kinga assurance api-probe` makes bounded, authorized GET-only probes from a contract. It does not follow redirects or send mutation methods. Success on a declared protected route is a review signal, not proof of broken authorization. See [API probe documentation](api-probe.md).
- `kinga assurance graphql` sends one authorized read-only introspection query and does not follow redirects or send mutations. Schema exposure is informational. See [GraphQL audit](graphql-audit.md).

## Delivery rules

- Preserve existing commands, report formats, configuration compatibility and offline scanning.
- Never send credentials to unrelated origins; never put secrets in logs or reports.
- Do not execute project code as part of static analysis.
- Auto-fixes are previews until the user approves application.
- Network intelligence updates and dynamic probes are explicit; cached and offline operation remain supported.
- A feature is complete only when its implementation, tests, documentation and CI checks pass.
- Do not describe pattern matches or heuristic taint flows as proven exploitability. Report the evidence and confidence honestly.

## Initial module APIs

- `src/intelligence/osv.ts`: bounded OSV batch query, schema-checked cache read/write and exact-version cache lookup.
- `src/scanners/code/taint.ts`: AST-based intraprocedural JavaScript/TypeScript taint candidates.
- `src/assurance/api-contract.ts`: static OpenAPI/Swagger JSON security-contract inspection.
- `src/assurance/api-probe.ts`: bounded, authorized GET-only API runtime checks.
- `src/assurance/graphql.ts`: one read-only GraphQL introspection request.
- `src/assurance/remediation.ts`: review-only patch preview for a narrowly supported safe fix.
- `src/assurance/git-history.ts`: bounded local Git patch inspection with secret-value redaction.
- `src/benchmark/metrics.ts` and `src/benchmark/fixtures.ts`: deterministic confusion-matrix, precision, recall, F1 and per-rule regression metrics.

These are incremental foundations, not a claim that the full roadmap is complete. The remaining work should be delivered as tested increments rather than empty command stubs.
