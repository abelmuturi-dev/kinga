import type { Finding } from '../core/types.js';

export type ComplianceFramework = 'OWASP-ASVS' | 'PCI-DSS-4.0' | 'SOC2' | 'ISO-27001-2022';
export interface ComplianceControl {
  framework: ComplianceFramework;
  control: string;
  title: string;
  rationale: string;
  confidence: 'indicative';
}
const CONTROLS: ComplianceControl[] = [
  {
    framework: 'OWASP-ASVS',
    control: 'V5',
    title: 'Validation, sanitization and encoding',
    rationale: 'Input handling and injection prevention.',
    confidence: 'indicative',
  },
  {
    framework: 'OWASP-ASVS',
    control: 'V8',
    title: 'Data protection',
    rationale: 'Protection of sensitive data and secrets.',
    confidence: 'indicative',
  },
  {
    framework: 'OWASP-ASVS',
    control: 'V9',
    title: 'Communications',
    rationale: 'Transport security and secure communication.',
    confidence: 'indicative',
  },
  {
    framework: 'OWASP-ASVS',
    control: 'V14',
    title: 'Configuration',
    rationale: 'Security configuration and hardening.',
    confidence: 'indicative',
  },
  {
    framework: 'PCI-DSS-4.0',
    control: '6.2',
    title: 'Bespoke and custom software',
    rationale: 'Secure development and coding practices.',
    confidence: 'indicative',
  },
  {
    framework: 'PCI-DSS-4.0',
    control: '6.3',
    title: 'Security vulnerabilities',
    rationale: 'Identify and manage vulnerabilities.',
    confidence: 'indicative',
  },
  {
    framework: 'PCI-DSS-4.0',
    control: '6.4',
    title: 'Public-facing web applications',
    rationale: 'Protect public-facing web applications.',
    confidence: 'indicative',
  },
  {
    framework: 'SOC2',
    control: 'CC6.1',
    title: 'Logical and physical access controls',
    rationale: 'Access and credential protection.',
    confidence: 'indicative',
  },
  {
    framework: 'SOC2',
    control: 'CC7.1',
    title: 'Vulnerability identification',
    rationale: 'Identify and monitor infrastructure vulnerabilities.',
    confidence: 'indicative',
  },
  {
    framework: 'SOC2',
    control: 'CC7.2',
    title: 'Security event monitoring',
    rationale: 'Detection and analysis of security events.',
    confidence: 'indicative',
  },
  {
    framework: 'SOC2',
    control: 'CC8.1',
    title: 'Change management',
    rationale: 'Controlled and tested changes.',
    confidence: 'indicative',
  },
  {
    framework: 'ISO-27001-2022',
    control: 'A.8.8',
    title: 'Management of technical vulnerabilities',
    rationale: 'Identify and manage technical vulnerabilities.',
    confidence: 'indicative',
  },
  {
    framework: 'ISO-27001-2022',
    control: 'A.8.9',
    title: 'Configuration management',
    rationale: 'Secure configuration and hardening.',
    confidence: 'indicative',
  },
  {
    framework: 'ISO-27001-2022',
    control: 'A.8.25',
    title: 'Secure development life cycle',
    rationale: 'Security throughout development.',
    confidence: 'indicative',
  },
  {
    framework: 'ISO-27001-2022',
    control: 'A.8.28',
    title: 'Secure coding',
    rationale: 'Secure coding practices.',
    confidence: 'indicative',
  },
];

export function mapFindingToCompliance(finding: Finding): ComplianceControl[] {
  const ids = new Set<string>();
  const rule = finding.rule.toUpperCase();
  const cwe = finding.cwe;
  if (
    cwe.some((id) => ['CWE-79', 'CWE-89', 'CWE-78', 'CWE-352'].includes(id)) ||
    /INJ|XSS|CSRF/.test(rule)
  ) {
    [
      'OWASP-ASVS:V5',
      'PCI-DSS-4.0:6.2',
      'PCI-DSS-4.0:6.3',
      'PCI-DSS-4.0:6.4',
      'ISO-27001-2022:A.8.25',
      'ISO-27001-2022:A.8.28',
    ].forEach((x) => ids.add(x));
  }
  if (finding.domain === 'secrets' || cwe.some((id) => ['CWE-798', 'CWE-522'].includes(id))) {
    ['OWASP-ASVS:V8', 'SOC2:CC6.1'].forEach((x) => ids.add(x));
  }
  if (finding.domain === 'web' && /TLS|CERT|HSTS|COOKIE|HDR/.test(rule)) {
    ['OWASP-ASVS:V9', 'OWASP-ASVS:V14', 'PCI-DSS-4.0:6.4'].forEach((x) => ids.add(x));
  }
  if (finding.domain === 'deps' || finding.domain === 'config') {
    ['PCI-DSS-4.0:6.3', 'SOC2:CC7.1', 'ISO-27001-2022:A.8.8', 'ISO-27001-2022:A.8.9'].forEach((x) =>
      ids.add(x),
    );
  }
  if (finding.domain === 'code')
    ['SOC2:CC8.1', 'ISO-27001-2022:A.8.25', 'ISO-27001-2022:A.8.28'].forEach((x) => ids.add(x));
  return CONTROLS.filter((control) => ids.has(`${control.framework}:${control.control}`));
}

export function buildComplianceReport(findings: readonly Finding[]): Record<string, unknown> {
  return {
    notice:
      'Indicative control mapping only. This report is not an audit, certification or compliance determination.',
    findings: findings.map((finding) => ({
      fingerprint: finding.fingerprint,
      rule: finding.rule,
      title: finding.title,
      severity: finding.severity,
      controls: mapFindingToCompliance(finding),
    })),
  };
}
