# Architecture

```
CLI (src/cli.ts, src/commands/*)
  -> framework.scan()            src/framework.ts
       web scanner               src/scanners/web   (http, tls, html, checks/*)
       code scanner              src/scanners/code  (rules, config/IaC, secrets)
       dependency scanner        src/scanners/deps  (lockfiles + advisory snapshot)
     RawFinding[]  (what a scanner observed, plus a `kb` topic key)
  -> Kinga Advisor               src/engine
       stack detection, risk score, advice, insights, fix plan, fix bundles
     Finding[]  (CWE/OWASP, risk, tailored advice, fingerprint)
  -> reports                     src/report (text, markdown, html, json, sarif)
```

Scanners only observe and never give advice. The advisor never touches the network or the target.
Shared identity (name, command, config file, User-Agent) lives in `src/brand.ts`.
Suppressions (`kinga-ignore`), config ignores and baselines are applied in `framework.ts`.
