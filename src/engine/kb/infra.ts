import { ex, REF, type TopicMap } from './types.js';

export const INFRA_TOPICS: TopicMap = {
  'docker-unpinned': {
    cwe: ['CWE-829', 'CWE-1104'],
    owasp: ['A08', 'A06'],
    effort: 'minutes',
    summary: 'Pin base images to a specific version tag, ideally with a digest.',
    why: 'An untagged or :latest image changes without notice, so builds are not reproducible and a poisoned update is pulled in automatically.',
    steps: [
      'Use an explicit tag such as node:22.12-slim, and pin the digest for critical images.',
      'Let Dependabot/Renovate propose updates.',
    ],
    examples: [ex('docker', 'dockerfile', 'Dockerfile', `FROM node:22.12-slim@sha256:<digest>`)],
    verify: 'Every FROM line has a version tag.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'docker-root': {
    cwe: ['CWE-250'],
    owasp: ['A05'],
    effort: 'minutes',
    summary: 'Create an unprivileged user and switch to it with USER.',
    why: 'If the app is compromised, the attacker is root inside the container, which makes breakout and tampering far easier.',
    steps: ['Add a non-root user, chown the app directory, and set USER before CMD.'],
    examples: [
      ex(
        'docker',
        'dockerfile',
        'Debian/Ubuntu images',
        `RUN useradd --system --create-home --uid 10001 app\nUSER app`,
      ),
      ex(
        'docker',
        'dockerfile',
        'Alpine images',
        `RUN addgroup -S app && adduser -S -G app -u 10001 app\nUSER app`,
      ),
    ],
    verify: 'docker run --rm <image> id shows a non-zero uid.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'docker-secret-layer': {
    cwe: ['CWE-798', 'CWE-540'],
    owasp: ['A02', 'A05'],
    effort: 'hours',
    summary: 'Pass secrets at run time or with BuildKit secret mounts, never as ENV/ARG.',
    why: 'ENV and ARG values are stored in image layers and readable by anyone who can pull the image (docker history).',
    steps: [
      'Remove the value, rotate the secret, rebuild and republish the image.',
      'Inject secrets at run time (orchestrator secrets) or use RUN --mount=type=secret.',
    ],
    examples: [
      ex(
        'docker',
        'dockerfile',
        'BuildKit secret mount',
        `RUN --mount=type=secret,id=npm_token \\\n    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci`,
      ),
    ],
    verify: 'docker history --no-trunc <image> shows no secret values.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'docker-add-remote': {
    cwe: ['CWE-494'],
    owasp: ['A08'],
    effort: 'minutes',
    summary:
      'Download with curl and verify a checksum, or COPY a pinned file from your repository.',
    why: 'ADD with a URL fetches unverified content on every build.',
    steps: ['Use RUN curl -fsSLO … && sha256sum -c.'],
    examples: [],
    verify: 'No ADD lines with http(s) URLs remain.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'docker-remote-access-port': {
    cwe: ['CWE-284'],
    owasp: ['A05'],
    effort: 'minutes',
    summary:
      "Do not run SSH or RDP inside application containers; use docker exec or your orchestrator's debug tools.",
    why: 'Remote-login daemons enlarge the attack surface and usually run with weak or shared credentials.',
    steps: ['Remove the daemon and the EXPOSE line.'],
    examples: [],
    verify: 'No remote-access port is published by the image.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'container-privileged': {
    cwe: ['CWE-250'],
    owasp: ['A05'],
    effort: 'hours',
    summary:
      'Drop privileged mode and host namespaces; add only the specific capabilities the workload needs.',
    why: 'A privileged container has almost the same access as the host; a compromise of the app is a compromise of the machine.',
    steps: [
      'Remove privileged: true / network_mode: host.',
      'Use cap_add for the single capability required and cap_drop: [ALL] as the baseline.',
    ],
    examples: [
      ex(
        'docker',
        'yaml',
        'docker-compose',
        `services:\n  app:\n    cap_drop: [ALL]\n    cap_add: [NET_BIND_SERVICE]\n    security_opt: ["no-new-privileges:true"]\n    read_only: true`,
      ),
    ],
    verify: 'docker inspect shows Privileged=false and a minimal CapAdd.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'compose-published-db': {
    cwe: ['CWE-668'],
    owasp: ['A05'],
    effort: 'minutes',
    summary:
      'Bind published ports to 127.0.0.1 or keep the datastore on the internal Docker network.',
    why: 'A published database port is reachable from the network, often with default credentials, and is mass-scanned for.',
    steps: [
      'Use "127.0.0.1:5432:5432", or remove ports: and let other services reach it by service name.',
    ],
    examples: [
      ex('docker', 'yaml', 'docker-compose', `ports:\n  - "127.0.0.1:5432:5432"   # local only`),
    ],
    verify: 'ss -ltn shows the port on 127.0.0.1 only.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'docker-socket': {
    cwe: ['CWE-250'],
    owasp: ['A05'],
    effort: 'hours',
    summary:
      'Do not mount the Docker socket into containers; use a restricted socket proxy if you must.',
    why: 'Access to the socket is root on the host: the container can start privileged containers and read any data.',
    steps: ['Remove the mount, or use a proxy that only allows the exact API calls needed.'],
    examples: [],
    verify: 'No container mounts /var/run/docker.sock.',
    references: [REF.owasp('Docker_Security_Cheat_Sheet')],
  },
  'k8s-host-namespace': {
    cwe: ['CWE-250'],
    owasp: ['A05'],
    effort: 'hours',
    summary:
      'Remove hostNetwork / hostPID / hostIPC unless the workload is a node-level agent that truly needs them.',
    why: 'Sharing host namespaces lets a compromised pod observe or interfere with host processes and traffic.',
    steps: [
      'Delete the setting and use Services/Ingress for networking.',
      'Enforce with Pod Security Admission (restricted profile).',
    ],
    examples: [
      ex(
        'kubernetes',
        'yaml',
        'Namespace policy',
        `apiVersion: v1\nkind: Namespace\nmetadata:\n  name: app\n  labels:\n    pod-security.kubernetes.io/enforce: restricted`,
      ),
    ],
    verify: 'kubectl apply is rejected for pods that request host namespaces.',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/'],
  },
  'k8s-security-context': {
    cwe: ['CWE-250'],
    owasp: ['A05'],
    effort: 'hours',
    summary:
      'Add a restrictive securityContext: non-root, no privilege escalation, read-only root file system, all capabilities dropped.',
    why: 'Defaults let containers run as root with writable file systems and extra capabilities, which makes exploitation and persistence easier.',
    steps: [
      'Set the context on every container and fix whatever writes to the file system with emptyDir volumes.',
    ],
    examples: [
      ex(
        'kubernetes',
        'yaml',
        'Container securityContext',
        `securityContext:\n  runAsNonRoot: true\n  runAsUser: 10001\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true\n  capabilities:\n    drop: ["ALL"]\n  seccompProfile:\n    type: RuntimeDefault`,
      ),
    ],
    verify: 'kubectl get pod -o yaml shows the context and the pod still starts.',
    references: ['https://kubernetes.io/docs/concepts/security/pod-security-standards/'],
  },
  'terraform-open-ingress': {
    cwe: ['CWE-284', 'CWE-668'],
    owasp: ['A01', 'A05'],
    effort: 'hours',
    summary:
      'Restrict ingress to known CIDR ranges or security groups, and never expose admin or database ports to 0.0.0.0/0.',
    why: 'Open SSH, RDP and database ports are found and attacked within minutes of being exposed.',
    steps: [
      'Replace 0.0.0.0/0 with your office/VPN range or a source security group.',
      'Use a bastion, SSM Session Manager, or a VPN for administration.',
      'Keep databases in private subnets with publicly_accessible = false.',
    ],
    examples: [
      ex(
        'terraform',
        'hcl',
        'Terraform',
        `ingress {\n  from_port       = 5432\n  to_port         = 5432\n  protocol        = "tcp"\n  security_groups = [aws_security_group.app.id]   # not cidr_blocks = ["0.0.0.0/0"]\n}`,
      ),
    ],
    verify:
      'terraform plan shows no 0.0.0.0/0 on sensitive ports; a port scan from outside finds them closed.',
    references: ['https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html'],
  },
  'terraform-public-bucket': {
    cwe: ['CWE-732'],
    owasp: ['A01', 'A05'],
    effort: 'hours',
    summary:
      'Make buckets private and block public access; serve public files through a CDN with origin access control.',
    why: 'Public buckets are crawled continuously; leaked data is the most common cloud breach.',
    steps: [
      'Remove public ACLs, enable Block Public Access, and review what was exposed in access logs.',
    ],
    examples: [
      ex(
        'terraform',
        'hcl',
        'Terraform',
        `resource "aws_s3_bucket_public_access_block" "b" {\n  bucket                  = aws_s3_bucket.b.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}`,
      ),
    ],
    verify: 'aws s3api get-public-access-block shows all four settings true.',
    references: [
      'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
    ],
  },
  'terraform-unencrypted': {
    cwe: ['CWE-311'],
    owasp: ['A02'],
    effort: 'hours',
    summary: 'Enable encryption at rest with a managed KMS key.',
    why: 'Unencrypted volumes, snapshots and databases expose data if disks or backups are copied or shared.',
    steps: [
      'Set encrypted = true (a replacement may be required for existing volumes) and use a customer-managed key for sensitive data.',
    ],
    examples: [
      ex(
        'terraform',
        'hcl',
        'Terraform',
        `resource "aws_db_instance" "main" {\n  storage_encrypted = true\n  kms_key_id        = aws_kms_key.db.arn\n}`,
      ),
    ],
    verify: 'terraform plan shows encryption enabled.',
    references: ['https://docs.aws.amazon.com/kms/latest/developerguide/overview.html'],
  },
  'terraform-wildcard-iam': {
    cwe: ['CWE-732', 'CWE-250'],
    owasp: ['A01'],
    effort: 'hours',
    summary: 'Grant the specific actions and resources each role needs (least privilege).',
    why: 'A wildcard policy turns any stolen credential into full control of the account.',
    steps: [
      'List the API calls the workload makes (IAM Access Analyzer can generate a policy from CloudTrail) and allow only those.',
    ],
    examples: [
      ex(
        'terraform',
        'hcl',
        'Terraform',
        `statement {\n  actions   = ["s3:GetObject", "s3:PutObject"]\n  resources = ["\${aws_s3_bucket.data.arn}/*"]\n}`,
      ),
    ],
    verify: 'IAM Access Analyzer reports no unused or over-broad permissions.',
    references: [
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege',
    ],
  },
  'no-lockfile': {
    cwe: ['CWE-1104'],
    owasp: ['A06', 'A08'],
    effort: 'minutes',
    summary: 'Commit exactly one lockfile and install from it in CI.',
    why: 'Without a lockfile, each install can resolve different versions, so a malicious or broken release is picked up silently.',
    steps: [
      'Generate and commit the lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml).',
      'Install with npm ci (or the equivalent frozen install) in CI.',
      'Delete lockfiles of other package managers.',
    ],
    examples: [
      ex(
        'node',
        'bash',
        'Node.js',
        `npm install        # creates package-lock.json: commit it\nnpm ci             # in CI: fails if it is out of date`,
      ),
    ],
    verify: 'CI uses npm ci and fails when the lockfile is out of sync.',
    references: [REF.owasp('NPM_Security_Cheat_Sheet')],
  },
  'unpinned-dependency': {
    cwe: ['CWE-1104', 'CWE-829'],
    owasp: ['A06', 'A08'],
    effort: 'minutes',
    summary: 'Use explicit version ranges (or exact versions) and rely on the lockfile.',
    why: '"*" and "latest" install any future release, including malicious or breaking ones, with no review.',
    steps: [
      'Replace with ^x.y.z (or ==x.y.z in Python) and commit the lockfile.',
      'Use Dependabot/Renovate to review upgrades.',
    ],
    examples: [ex('python', 'text', 'requirements.txt', `flask==3.0.3\nrequests==2.32.3`)],
    verify: 'No "*" or "latest" remain in manifests.',
    references: [REF.owasp('NPM_Security_Cheat_Sheet')],
  },
  'install-script': {
    cwe: ['CWE-506', 'CWE-829'],
    owasp: ['A08'],
    effort: 'hours',
    summary:
      'Inspect and remove the script; if you did not write it, treat the machine and credentials as compromised.',
    why: 'Install hooks run automatically with your permissions on every developer machine and CI runner; they are the main way malicious packages spread.',
    steps: [
      'Read the script and the package that introduced it.',
      'If it is not yours, rotate any tokens present on machines that ran npm install and remove the package.',
      'Use npm install --ignore-scripts in CI where possible.',
    ],
    examples: [],
    verify: 'No unexpected install scripts remain (npm query ":attr(scripts, [postinstall])").',
    references: [REF.owasp('NPM_Security_Cheat_Sheet')],
  },
  'vulnerable-dependency': {
    cwe: ['CWE-1104'],
    owasp: ['A06'],
    effort: 'hours',
    summary: 'Upgrade the dependency to the fixed version (or newer) and run your tests.',
    why: 'Known vulnerabilities in dependencies are scanned for and exploited automatically.',
    steps: [
      'Upgrade to the fixed version shown in the finding; if it is a transitive dependency, upgrade the parent or use an override/resolution.',
      'Run tests; read the changelog for breaking changes.',
      'Enable automated update PRs and run an audit tool in CI.',
    ],
    examples: [
      ex(
        'node',
        'bash',
        'npm',
        `npm install <package>@<fixed-version>\nnpm audit\n# transitive: add to package.json  "overrides": { "<package>": "<fixed-version>" }`,
      ),
      ex('python', 'bash', 'pip', `pip install --upgrade "<package>>=<fixed-version>"\npip-audit`),
      ex(
        'java',
        'xml',
        'Maven',
        `<dependency>\n  <groupId>…</groupId><artifactId>…</artifactId>\n  <version><!-- fixed version --></version>\n</dependency>`,
      ),
    ],
    verify: 'Re-run Kinga and npm audit / pip-audit / OSV-Scanner: the advisory no longer appears.',
    references: [REF.owasp('Vulnerable_Dependency_Management_Cheat_Sheet'), 'https://osv.dev/'],
  },
};
