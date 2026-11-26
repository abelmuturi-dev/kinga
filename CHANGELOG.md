# Changelog

## 0.1.0

First release. Kinga is a security framework derived from the Mia Code code base.

- Web scanner (passive and active): headers, CSP, HSTS, cookies, TLS, redirects, forms, mixed
  content, SRI, vulnerable front-end libraries, error leakage, CORS, HTTP methods, exposed files.
- Code scanner: 45+ pattern rules (injection, XSS, crypto, auth, deserialization, SSRF, path
  traversal, secrets, CI), Docker/Compose/Kubernetes/Terraform checks, dependency advisories for
  npm, PyPI and Maven (bundled snapshot, extensible).
- Kinga Advisor: built-in offline knowledge base with stack-tailored fixes, cross-finding insights,
  a prioritised fix plan and paste-ready fix bundles.
- Reports: text, Markdown, HTML, JSON, SARIF. Baselines, config file, custom rules, `--fail-on`.
- Removed: external AI-provider integration, API-key storage, chat and coding-agent features.
