# Assurance module

Kinga's assurance module adds CycloneDX 1.5 SBOM generation, OSV dependency checks, DNS/email
posture checks, JavaScript bundle indicators, OpenAPI/Swagger contract auditing, Git history secret
inspection, compliance mapping, scan comparison and optional local-only advisor rephrasing.

## Commands

- `kinga assurance sbom [project] [output.json]`: generate CycloneDX 1.5 from recognized manifests and lockfiles.
- `kinga assurance osv <bom.json> [--offline|--refresh] [cache.json]`: check exact SBOM package versions against OSV. Network use is explicit; offline mode reads the local cache only.
- `kinga assurance dns <domain>`: inspect MX, SPF, DMARC, common DKIM selectors and common subdomain CNAME signals.
- `kinga assurance js <asset.js>`: inspect a local JavaScript bundle for token-shaped values and source-map references. Values are not printed.
- `kinga assurance api <openapi.json> [output.json]`: statically audit OpenAPI 3.0/3.1 and Swagger 2.0 JSON contracts for transport, authentication and operation-documentation issues. See [API contract audit](api-contract.md).\n- `kinga assurance git-secrets [directory] [--max-commits <1-5000>]`: inspect recent local Git history for common credential patterns without printing secret values or contacting remotes. See [Git history secret scan](git-history.md).\n- `kinga assurance compare <previous.json> <current.json>`: compare findings by fingerprint.
- `kinga assurance compliance <scan.json> [output.json]`: generate indicative control mappings.
- `kinga assurance history <scan.json>`: save a scan snapshot under `~/.kinga/history`; use `history list` or `history compare` to review trends.
- `kinga assurance rephrase <scan.json> <finding-index> <ollama-model>`: optionally rephrase curated advice through Ollama on loopback.

## Scope and limitations

SBOM generation reads files only and never executes package managers. It recognizes npm package-lock,
pinned Python requirements, Go modules, Cargo.lock, Gemfile.lock, composer.lock, Maven pom.xml and
NuGet packages.lock.json/packages.config. Unknown formats are skipped rather than guessed. OSV
queries use exact versions from CycloneDX package URLs; unknown formats are not claimed as covered.

DNS checks are passive. DKIM lookup checks common selectors only. Unresolved CNAME targets are
takeover signals, not proof of claimability; no provider claim or exploit attempt is performed.
JavaScript analysis is bounded pattern inspection, not full deobfuscation or secret validation. API contract analysis accepts JSON only and is static; it does not probe endpoints or prove runtime authorization. Git history scanning examines bounded added-line patches from reachable local commits, does not fetch remotes or validate tokens, and may miss secrets that do not match its patterns.

Compliance mappings are indicative evidence pointers, not audit conclusions, certifications or legal
advice. Organizations must validate applicability and control versions with their auditor.

Scan comparison depends on fingerprint stability. It is a trend aid, not a replacement for review.
The optional local advisor uses Ollama at the fixed loopback endpoint
`http://127.0.0.1:11434`, receives curated advice only, and cannot change the finding or original fix.
