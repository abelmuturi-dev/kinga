# Authorized API runtime checks

Run bounded read-only probes against GET operations declared in an OpenAPI/Swagger JSON contract:

```bash
kinga assurance api-probe openapi.json https://staging.example.com --authorized
```

The command is deliberately opt-in. It sends GET requests only (never POST/PUT/PATCH/DELETE), does
not send request bodies, follows no redirects and limits the number of operations to 20. Path
parameters are replaced with the literal placeholder `kinga-probe`; operations requiring query
parameters may return 4xx responses. Credentials are optional and use the exact-origin environment
configuration described in [authenticated scanning](authenticated-scanning.md).

If a route declared protected returns 2xx without credentials, Kinga raises a review signal, not a
confirmed access-control vulnerability. GET handlers should be side-effect free, but the scanner
cannot guarantee that an application follows HTTP semantics. Only run this against systems you own
or have written permission to test.
