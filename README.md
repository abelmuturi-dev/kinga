# Kinga

**A security framework for developers.** Point it at a live website, a dev server, or a project
under development. It finds security problems and tells you, for your stack, exactly how to fix them.

_"Kinga" is Swahili for protection / defence._

```bash
kinga web https://staging.example.com        # scan a live site
kinga web http://localhost:3000 --level active   # scan your dev server
kinga code .                                  # scan the project you are working on
kinga scan . https://example.com -f html -o report.html   # both, as a shareable report
kinga ask "how do I stop SQL injection in Django?"        # ask the built-in advisor
```

Kinga has **no external AI service, no API keys and no account**. Everything, including the
advisor, runs on your machine. Code scans never touch the network.

## What it finds

| Area                        | Examples                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Live websites**           | Missing/weak CSP, HSTS, clickjacking protection; insecure cookies; TLS (expired, self-signed, weak key, TLS 1.0/1.1, no TLS 1.3); HTTP→HTTPS gaps; mixed content; third-party scripts without SRI; vulnerable jQuery/Bootstrap/etc; stack traces and debug pages; reflective CORS with credentials; exposed `/.env`, `/.git`, backups, `phpinfo`, Actuator; outdated/EOL server software |
| **Code under development**  | SQL/NoSQL/command/template injection, XSS sinks, weak hashes and ciphers, insecure randomness, JWT misuse, hard-coded secrets and keys, disabled CSRF/TLS verification, unsafe deserialization, XXE, SSRF, path traversal, open redirects, unsafe uploads, sensitive logging, debug mode                                                                                                 |
| **Config & infrastructure** | Dockerfile / Compose (root, privileged, published DB ports, baked-in secrets), Kubernetes manifests, Terraform (open ingress, public buckets, `*` IAM), GitHub Actions (script injection, unpinned actions, `pull_request_target`)                                                                                                                                                       |
| **Dependencies**            | Known-vulnerable versions (npm, PyPI, Maven) from lockfiles, missing/duplicate lockfiles, unpinned versions, suspicious install scripts                                                                                                                                                                                                                                                  |

Languages with dedicated rules: JavaScript/TypeScript, Python, Java/Kotlin, PHP, Ruby, Go, C#, plus
shell, Terraform and templates.

## Kinga Advisor: the built-in "brain"

Instead of calling an outside model, Kinga ships its own analysis engine. For every finding it:

1. **Explains** why it matters in plain language, mapped to **CWE** and **OWASP Top 10**.
2. **Fixes it for your stack.** It detects nginx / Apache / Express / Django / Spring / Docker /
   Terraform and so on (from response headers, cookies, manifests, files) and shows the matching
   code first.
3. **Correlates findings** into attack paths ("exposed `.env` + hard-coded keys → credentials are
   probably already compromised").
4. **Prioritises** with a risk score (severity × certainty × observed-fact × context) and a **fix
   plan** that puts serious _and_ quick changes first.
5. **Generates paste-ready fix bundles**, e.g. one nginx block that fixes six header findings.
6. Is honest about certainty: each finding says whether it was an **observed fact** or a **pattern
   match**, and what was _not_ assessed.

```text
$ kinga ask "csrf in express"
Tailoring examples for: express
csrf-token-missing  (CWE-352)
  Fix: Protect state-changing forms with anti-CSRF tokens and SameSite cookies.
  ...
  Example (Express (csrf-csrf)):
      | import { doubleCsrf } from 'csrf-csrf';
  Answered offline from the built-in knowledge base (no external AI service).
```

> **What the Advisor is and is not.** It is a curated expert system (about 100 topics, 40+
> technology-specific examples) plus reasoning rules. It is **not a neural language model**: it
> answers questions it has topics for and says so when it does not. See
> [docs/advisor.md](docs/advisor.md) for how it works and how to extend it.

## Install

Requires Node.js 20+.

```bash
npm install
npm run build
npm link          # provides the `kinga` command
kinga --version
```

## Web scanning

| Level               | What is sent                                                                                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `passive` (default) | The target page, `/robots.txt`, `/.well-known/security.txt`, one TLS handshake, the plain-HTTP variant                          |
| `active`            | Plus: CORS/`OPTIONS` probes, a small same-origin crawl, ~18 requests for well-known sensitive paths, TLS 1.0/1.1/1.3 handshakes |

Requests identify themselves (`Kinga-Security-Scanner/…`), are rate limited (`--delay`), capped
(`--max-requests`, default 80), send no bodies, never log in and never exploit anything.
**Active scans of non-local hosts require `--authorized`**, your confirmation that you own the
target or have written permission. Localhost and private-network addresses (dev servers) need no
flag. Contents of exposed files are checked in memory and never written to a report.

## Code scanning

```bash
kinga code [dir] [--fail-on high] [-f sarif -o kinga.sarif]
```

Reads source, config, IaC, workflows and manifests. Honours `.gitignore`, skips dependencies, build
output and binaries, and never runs your code. Secret values are masked in all output.

Suppress a reviewed line with a comment: `// kinga-ignore` on the line, or
`// kinga-ignore-next-line` above it.

## Reports and CI

`-f text` (default) · `markdown` · `html` (self-contained, light/dark) · `json` · `sarif`
(GitHub code scanning and most dashboards).

```yaml
- run: npx kinga code . --fail-on high -f sarif -o kinga.sarif
```

Exit code is `1` when a finding meets `--fail-on`, `2` for usage errors.

## Configuration: `kinga.config.json`

```json
{
  "failOn": "high",
  "ignoreRules": ["WEB-HDR-004"],
  "ignorePaths": ["vendor/", "**/*.generated.*"],
  "baseline": ".kinga/baseline.json",
  "advisoriesFile": "advisories.json",
  "customRules": [
    {
      "id": "CUSTOM-001",
      "title": "Internal URL hard-coded",
      "pattern": "https?://admin\\.internal",
      "severity": "low",
      "files": "\\.(js|ts|py)$"
    }
  ]
}
```

`kinga init` writes a starter file. `kinga baseline` records current findings so later scans show
only **new** ones, useful for adopting Kinga on an existing project.

## Commands

| Command                                                 | Purpose                             |
| ------------------------------------------------------- | ----------------------------------- |
| `kinga scan [target…]`                                  | URLs and/or folders (auto-detected) |
| `kinga web <url>` / `kinga code [dir]`                  | Web-only / code-only                |
| `kinga ask "<question>"` · `explain <topic>` · `topics` | Offline advisor                     |
| `kinga baseline [dir]` · `init`                         | Adoption helpers                    |

## Limits: please read

- **Not a penetration test.** Web scans see only what an anonymous visitor sees and do not exploit
  anything. Business-logic and access-control bugs between users are out of reach.
- **Code findings are pattern matches** with no data-flow analysis. Each is labelled _pattern
  match, not proven_; confirm that attacker-controlled data reaches the line.
- **The advisory database is a curated snapshot** (~60 high-impact CVEs), not a full feed. Use
  `npm audit`, `pip-audit` or OSV-Scanner as well, or add entries via `advisoriesFile`.
- Version-based findings (server banners, library names in URLs) can be wrong when software is
  patched without changing its version string.
- A clean report does not mean a secure system. Every report lists what was not assessed.

## Documentation

[Architecture](docs/architecture.md) · [Advisor](docs/advisor.md) · [Rules & knowledge base](docs/rules.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

## License

Apache-2.0. Kinga is derived from [Mia Code](https://github.com/MiaCodeAI/Mia-Code); see
[NOTICE](NOTICE).
