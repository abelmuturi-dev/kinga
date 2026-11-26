# Kinga benchmark methodology

Run the deterministic built-in rule fixture benchmark:

```bash
kinga assurance benchmark
```

The command evaluates the shipped pattern rules against version-controlled positive and negative
source-line fixtures. It reports true positives, false positives, false negatives, true negatives,
precision, recall, F1 and per-rule metrics. The test suite runs the same fixture set during CI.

This is a regression benchmark, not an independent efficacy study. The fixtures are synthetic and
small, and they were authored alongside the rule set; therefore perfect scores do not establish
real-world precision or recall. The benchmark does not currently run OWASP Juice Shop or DVWA,
measure exploitability, or represent a statistically sampled production corpus. Do not publish its
scores as independent validation. A credible external evaluation needs a held-out corpus, explicit
ground truth, versioned vulnerable application snapshots, reproducible scanner settings and manual
adjudication of false positives and false negatives.
