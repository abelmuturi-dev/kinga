# Security policy

## Reporting a vulnerability in Kinga

Please report privately to the maintainers (open a private security advisory on the repository
host, or email the address in `package.json` once published). Do not open a public issue for
vulnerabilities. Include the version (`kinga --version`), what you did, and what happened.

## What Kinga does and does not do

- **Code scans** read files only. They never execute project code and never use the network.
- **Passive web scans** make ordinary `GET` requests for the target page, `/robots.txt` and
  `/.well-known/security.txt`, and one TLS handshake.
- **Active web scans** additionally send `OPTIONS` and CORS probe requests, a small same-origin
  crawl, requests for a fixed list of well-known sensitive paths, and handshakes limited to old
  TLS versions. They never send request bodies, never attempt to log in, never fuzz parameters
  and never try to exploit anything.
- Contents of exposed files (for example `.env`) are inspected in memory to avoid false alarms and
  are **never** written to reports. Secret values are masked everywhere.
- Active scans of non-local hosts require `--authorized`. **Only scan systems you own or have
  written permission to test.**
- Kinga sends no telemetry and contacts no service other than the targets you name.
