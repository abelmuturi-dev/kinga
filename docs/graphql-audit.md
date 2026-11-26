# GraphQL endpoint checks

Run one read-only GraphQL introspection request against an endpoint you own or are authorized to
assess:

```bash
kinga assurance graphql https://staging.example.com/graphql --authorized
```

The check sends a single GraphQL POST containing an introspection query. It never sends mutations,
does not fuzz fields, does not follow redirects and caps the response at 64 KB. If credentials are
needed, reuse the opt-in `KINGA_AUTH_ORIGIN`, `KINGA_AUTH_HEADER` and `KINGA_AUTH_VALUE`
environment variables documented in [authenticated scanning](authenticated-scanning.md). The
configured origin must exactly match the endpoint origin.

An exposed schema is reported as informational: introspection alone does not prove a vulnerability.
This is not a full GraphQL security test. It does not test authorization at individual fields,
IDOR, query depth, batching abuse, resolver injection or business logic. Those checks require a
purpose-built, authorized test plan.
