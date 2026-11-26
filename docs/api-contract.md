# API contract security audit

Kinga can statically inspect OpenAPI 3.0/3.1 and Swagger 2.0 **JSON** documents:

```bash
kinga assurance api openapi.json
kinga assurance api openapi.json api-security-report.json
```

The audit checks:
- Non-local API servers advertised over cleartext HTTP.
- Missing or malformed server declarations, embedded server credentials and cleartext transport. OpenAPI's implicit relative default server is reported as informational only.
- Missing authentication scheme declarations, query-string API keys and HTTP Basic authentication.
- Operations with no effective security requirement, including state-changing operations.
- Security requirements that reference undefined schemes.
- Duplicate or missing operation IDs.

Security is inherited from the document-level `security` property unless an operation defines its own. An operation with `security: []`, or a security requirement list containing an empty `{}` alternative, permits anonymous access and is reported so that the decision can be reviewed. Relative server URLs are accepted because they inherit the API document's origin. A public endpoint is not automatically a vulnerability: health checks, login and public catalogue routes may be intentionally unauthenticated.

The audit is local and static. It does not call API endpoints, authenticate, fuzz parameters, validate business logic, or prove server-side access control. It currently accepts JSON input, not YAML. Results are review prompts, not a penetration-test verdict.
