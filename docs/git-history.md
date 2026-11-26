# Git history secret scan

Scan recent reachable local Git history without fetching remotes or validating credentials:

```bash
kinga assurance git-secrets .
kinga assurance git-secrets ./project --max-commits 500
```

Kinga inspects added patch lines in recent commits and reports the commit, file, line, secret category and severity. It recognises common private-key markers and token formats for AWS, GitHub, Slack, Google and Stripe, plus generic secret assignments. Secret values are never included in findings or reports.

The scan is bounded (100 commits by default, maximum 5,000; 25 MB of patch output; 30-second Git timeout). It reads only local reachable history and does not contact remotes, test whether credentials are valid, or rewrite history. If a real credential was committed, revoke or rotate it first; deleting it in a later commit does not make it safe. This is a heuristic scanner, so review results and do not treat a clean result as proof that history contains no secrets.
