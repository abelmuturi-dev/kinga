# Rules and knowledge base

Rule ids: `WEB-*` web checks, `CODE-*` source patterns, `CFG-*` config/IaC, `DEP-*` dependencies,
`SEC-*` secrets. Each finding is numbered per rule (`CODE-INJ-001#2`) and carries a stable fingerprint
used by baselines.

Code rule fields: `id`, `title`, `severity`, `confidence`, `kb`, `appliesTo` (file regex), `pattern`,
optional `accept(match, line)` to reject false positives, and a `verification` note. Use
`confidence: 'low'` for pattern-only matches.

Custom rules can be added without code via `customRules` in `kinga.config.json`.
List topics with `kinga topics`; read one with `kinga explain <topic>`.
