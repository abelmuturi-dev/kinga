# Assurance module

Kinga's assurance module adds CycloneDX 1.5 SBOM generation, OSV dependency checks, DNS/email
posture checks, JavaScript bundle indicators, OpenAPI/Swagger contract auditing, Git history secret
inspection, compliance mapping, scan comparison and optional local-only advisor rephrasing.

## Commands

- `kinga assurance sbom [project] [output.json]`: generate CycloneDX 1.5 from recognized manifests and lockfiles.
- `kinga assurance osv <bom.json> [--offline|--refresh] [cache.json]`: check exact SBOM package
  versions against OSV. Network use is explicit; offline mode reads the local cache only.
- `kinga assurance dns <domain>`: inspect MX, SPF, DMARC, common DKIM selectors and common subdomain CNAME signals.
- `kinga assurance js <asset.js>`: inspect a local JavaScript bundle for token-shaped values and
  source-map references. Values are not printed.
- `kinga assurance api <openapi.json> [output.json]`: statically audit OpenAPI 3.0/3.1 and Swagger
  2.0 JSON contracts for transport, authentication and operation-documentation issues. See [API
  contract audit](api-contract.md).
- `kinga assurance git-secrets [directory] [--max-commits <1-5000>]`: inspect recent local Git
  history for common credential patterns without printing secret values or contacting remotes. See
  [Git history secret scan](git-history.md).
- `kinga assurance compare <previous.json> <current.json>`: compare findings by fingerprint.
- `kinga assurance compliance <scan.json> [output.json]`: generate indicative control mappings.
- `kinga assurance history <scan.json>`: save a scan snapshot under `~/.kinga/history`; use
  `history list` or `history compare` to review trends.
- `kinga assurance rephrase <scan.json> <finding-index> <ollama-model>`: optionally rephrase curated advice through Ollama on loopback.

## Scope and limitations

SBOM generation reads files only and never executes package managers. It recognizes npm package-lock,
pinned Python requirements, Go modules, Cargo.lock, Gemfile.lock, composer.lock, Maven pom.xml and
NuGet packages.lock.json/packages.config. Unknown formats are skipped rather than guessed. OSV
queries use exact versions from CycloneDX package URLs; unknown formats are not claimed as covered.

DNS checks are passive. DKIM lookup checks common selectors only. Unresolved CNAME targets are
takeover signals, not proof of claimability; no provider claim or exploit attempt is performed.
JavaScript analysis is bounded pattern inspection, not full deobfuscation or secret validation. The JavaScript/TypeScript taint pass is AST-based but intraprocedural and heuristic; it does not prove exploitability. Git history scanning examines bounded added-line patches from reachable local commits, does not fetch remotes or validate tokens, and may miss secrets that do not match its patterns. API contract auditing is static JSON analysis; optional API probes request GET operations only and require explicit authorization. GraphQL checks send one read-only introspection query and require explicit authorization. Safe remediation previews support only a narrow set of mechanical fixes and never modify source files.

Compliance mappings are indicative evidence pointers, not audit conclusions, certifications or legal
advice. Organizations must validate applicability and control versions with their auditor.

Scan comparison depends on fingerprint stability. It is a trend aid, not a replacement for review.
The optional local advisor uses Ollama at the fixed loopback endpoint
`http://127.0.0.1:11434`, receives curated advice only, and cannot change the finding or original fix.


## Additional upgrade modules

- [Authenticated web scanning](authenticated-scanning.md): explicit Authorization/Cookie headers scoped to one exact origin.
- [API contract auditing](api-contract.md) and [authorized API probes](api-probe.md): static checks plus bounded GET-only runtime review.
- [GraphQL endpoint audit](graphql-audit.md): one read-only introspection query, no mutations or redirects.
- [Benchmark methodology](benchmark-methodology.md): reproducible synthetic rule fixtures; not an independent OWASP evaluation.
- [Developer integrations](developer-integrations.md): watch mode, an opt-in pre-commit hook and a minimal VS Code extension.
