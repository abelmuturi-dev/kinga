# Authenticated web scanning

Kinga supports an opt-in, single-origin authentication header for authorized web scans. It does not
store credentials in configuration files, reports or scan history.

Set these environment variables in the shell that runs Kinga:

```bash
export KINGA_AUTH_ORIGIN="https://staging.example.com"
export KINGA_AUTH_HEADER="Authorization"
export KINGA_AUTH_VALUE="Bearer $STAGING_TOKEN"
kinga web https://staging.example.com --authorized
```

For a session cookie, use `KINGA_AUTH_HEADER=Cookie` and supply the cookie value through
`KINGA_AUTH_VALUE`. Do not paste credentials into shell history; use your operating system's
secret manager or a protected environment injection mechanism.

Safety boundaries:

- `KINGA_AUTH_ORIGIN` must be an absolute HTTP(S) origin without a path, query or fragment.
- Only Authorization and Cookie headers are accepted.
- Credentials are attached only when the request origin exactly matches the configured origin.
- Credentials are not sent to a different scheme, port, hostname or redirect destination.
- Authenticated scans always require `--authorized`.
- Credentials are never sent to non-loopback HTTP targets; HTTPS is mandatory.
- Authenticated web scans refuse `--insecure` and stop if certificate validation fails.
- The header value is never included in Kinga findings or reports.
- This is header-based authentication only. It does not automate login forms, refresh tokens or
  multi-step identity-provider flows.

Use a dedicated low-privilege test account and revoke its session when finished.
