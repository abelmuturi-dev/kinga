import { languageOf } from '../../repo/languages.js';
import type { Confidence, Domain, Severity } from '../../core/types.js';

export interface CodeRule {
  id: string;
  /** Knowledge-base topic used to explain and fix the problem. */
  kb: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  domain: Domain;
  category: string;
  pattern: RegExp;
  appliesTo: (path: string) => boolean;
  /** Also inspect test files, docs and examples (default false). */
  includeTests?: boolean;
  /** Extra check on the matching line; return false to drop a false positive. */
  accept?: (line: string, match: RegExpExecArray) => boolean;
  /** Replace the matched value in shown evidence so it is never printed. */
  maskValue?: boolean;
  note?: string;
}

const lang =
  (...names: string[]) =>
  (path: string): boolean => {
    const info = languageOf(path);
    return info !== undefined && names.includes(info.name);
  };

export const JS = lang('JavaScript', 'TypeScript', 'Vue', 'Svelte');
export const PY = lang('Python');
export const PHP = lang('PHP');
export const JAVA = lang('Java', 'Kotlin', 'Scala');
export const RUBY = lang('Ruby');
export const GO = lang('Go');
export const CS = lang('C#');
export const SHELL = lang('Shell');
export const anyCode = (path: string): boolean => languageOf(path)?.kind === 'code';
export const templates = (path: string): boolean =>
  languageOf(path)?.name === 'Template' || languageOf(path)?.name === 'HTML';
export const webCode = (path: string): boolean => anyCode(path) || templates(path);

const PLACEHOLDER =
  /(change|example|your|xxx|todo|<|>|\$\{|\{\{|process\.env|getenv|environ|dummy|sample|placeholder|\*\*\*|redacted|secret_key_here|password123|test|fake|mock|foo|bar|\.\.\.)/i;

const USER_INPUT =
  /(req\.(body|query|params|headers|cookies)|request\.(args|form|values|json|GET|POST|data|files|query_params|body)|\$_(GET|POST|REQUEST|COOKIE|FILES)|params\[|ctx\.(query|request)|c\.(Query|Param|PostForm)\(|r\.(URL\.Query|FormValue)|getParameter\(|@RequestParam|@PathVariable|input\(|argv|searchParams|location\.(search|hash)|document\.(cookie|URL|referrer))/;

function hasUserInput(line: string): boolean {
  return USER_INPUT.test(line);
}

export const CODE_RULES: CodeRule[] = [
  // ---------- Injection ----------
  {
    id: 'CODE-INJ-001',
    kb: 'command-injection',
    title: 'Shell command built from variables',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'injection',
    pattern:
      /(?:\bshell\s*=\s*True|\bos\.(?:system|popen)\s*\(|\bsubprocess\.(?:call|run|Popen|check_output|check_call)\([^)]*\bshell\s*=\s*True|\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)]*\+\s*\w)|\bRuntime\.getRuntime\(\)\.exec\s*\([^)]*\+|\b(?:shell_exec|passthru|system|popen|proc_open)\s*\(\s*[^)'"][^)]*\$|\bexec\.Command\(\s*"(?:sh|bash|cmd)"\s*,\s*"-c"|%x\{|\bKernel\.system\s*\([^)]*#\{)/,
    appliesTo: (p) => anyCode(p),
    accept: (line) => !/^\s*(\/\/|#|\*)/.test(line),
  },
  {
    id: 'CODE-INJ-002',
    kb: 'sql-injection',
    title: 'SQL query built by string interpolation or concatenation',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'injection',
    pattern:
      /(?:\.(?:execute|executemany|raw|query|exec|prepare|createQuery|createNativeQuery|queryForList|queryForObject)\(\s*(?:f['"`]|['"`][^'"`]*['"`]\s*(?:%|\+|\.format\()|`[^`]*\$\{|\w+\s*\+)|\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,80}\b(?:FROM|INTO|SET|WHERE)\b[^;\n]*(?:['"]\s*\+\s*\w|\$\{|#\{|\.format\(|%s['"]?\s*%\s*\())/i,
    appliesTo: (p) => anyCode(p),
    accept: (line) =>
      !/^\s*(\/\/|#|\*)/.test(line) &&
      !/(?:console\.|logger?\.|print|log\.)/i.test(line) &&
      /(?:select|insert|update|delete|where|from|execute|query|raw)/i.test(line),
  },
  {
    id: 'CODE-INJ-003',
    kb: 'nosql-injection',
    title: 'MongoDB query built directly from request data',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'injection',
    pattern:
      /\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|aggregate|countDocuments)\(\s*(?:req\.(?:body|query|params)\b(?!\.\w+\s*[,)])|\{[^}]*:\s*req\.(?:body|query|params)\.\w+\s*[,}])/,
    appliesTo: JS,
  },
  {
    id: 'CODE-INJ-004',
    kb: 'code-eval',
    title: 'Dynamic code evaluation',
    severity: 'high',
    confidence: 'low',
    domain: 'code',
    category: 'injection',
    pattern:
      /(?:(?<![.\w$])eval\s*\(\s*[^)\s]|\bnew Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|runInContext)\(|\bsetTimeout\(\s*['"`]|\bassert\s*\(\s*\$_|\bcreate_function\s*\()/,
    appliesTo: (p) => JS(p) || PY(p) || PHP(p) || RUBY(p),
    accept: (line) => !/^\s*(\/\/|#|\*)/.test(line),
  },
  {
    id: 'CODE-INJ-007',
    kb: 'code-eval',
    title: 'Dynamic code execution with exec()',
    severity: 'high',
    confidence: 'low',
    domain: 'code',
    category: 'injection',
    pattern: /^\s*(?:[\w.]+\s*=\s*)?exec\(\s*(?!['"]\s*\))[^)]+\)/,
    appliesTo: PY,
  },
  {
    id: 'CODE-INJ-005',
    kb: 'ssti',
    title: 'Template rendered from a string that may contain user input',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'injection',
    pattern:
      /(?:render_template_string\(|Template\(\s*(?:request|f['"]|[^)'"]*\+)|jinja2\.Template\(|ejs\.render\(\s*(?:req|[^,)]*\+)|Handlebars\.compile\(\s*req|pug\.render\(\s*req|new Template\(\s*\$_)/,
    appliesTo: (p) => JS(p) || PY(p) || PHP(p),
  },
  {
    id: 'CODE-INJ-006',
    kb: 'ldap-xpath-injection',
    title: 'LDAP or XPath query built from variables',
    severity: 'medium',
    confidence: 'low',
    domain: 'code',
    category: 'injection',
    pattern:
      /(?:\bldap_search\([^)]*\$|\.search(?:_s)?\([^)]*(?:f['"]|\+\s*\w)[^)]*\(\w+=|xpath\.(?:select|evaluate)\([^)]*\+|\.xpath\(\s*(?:f['"]|[^)'"]*\+))/i,
    appliesTo: anyCode,
  },
  // ---------- XSS ----------
  {
    id: 'CODE-XSS-001',
    kb: 'xss-dom',
    title: 'Assignment to innerHTML / outerHTML / insertAdjacentHTML',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'xss',
    pattern:
      /(?:\.(?:innerHTML|outerHTML)\s*(?:\+)?=(?!=)|\.insertAdjacentHTML\(|document\.write(?:ln)?\()/,
    appliesTo: (p) => JS(p) || templates(p),
    accept: (line) => {
      const rhs = line
        .split(/=(?!=)/)
        .slice(1)
        .join('=');
      return (
        !/^\s*(\/\/|\*)/.test(line) &&
        !/=\s*(['"`])\s*\1\s*;?\s*$/.test(line) &&
        !/=\s*(['"`])[^'"`$+{}]*\1\s*;?\s*$/.test(rhs === '' ? line : `=${rhs}`)
      );
    },
  },
  {
    id: 'CODE-XSS-002',
    kb: 'xss-framework-bypass',
    title: 'Framework output escaping explicitly disabled',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'xss',
    pattern:
      /(?:dangerouslySetInnerHTML|v-html\s*=|\[innerHTML\]\s*=|bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\(|\{\{\{[^}]+\}\}\}|\|\s*safe\b|\bmark_safe\(|\bhtml_safe\b|<%-\s|\braw\s+@|\bHtml\.Raw\(|\{!!|autoescape\s*=\s*False|autoescape\s+off|\{%\s*autoescape\s+off|Markup\()/,
    appliesTo: webCode,
  },
  {
    id: 'CODE-XSS-003',
    kb: 'xss-reflected',
    title: 'Request data written straight into the response body',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'xss',
    pattern:
      /(?:res\.(?:send|write|end)\(\s*(?:[`'"][^`'"]*(?:\$\{|['"]\s*\+)|req\.(?:body|query|params))|\bresponse\.(?:write|getWriter\(\)\.(?:print|println|write))\([^)]*(?:request\.getParameter|\+)|\becho\s+[^;]*\$_(?:GET|POST|REQUEST|COOKIE)|\bprint\s*\(\s*\$_(?:GET|POST|REQUEST)|HttpResponse\(\s*f?['"][^'"]*(?:\{request|%s)|return\s+f?['"]<[^'"]*(?:\{request\.|request\.(?:args|form)))/,
    appliesTo: anyCode,
    accept: (line) => hasUserInput(line) || /\$\{|\+/.test(line),
  },
  // ---------- Crypto ----------
  {
    id: 'CODE-CRY-001',
    kb: 'weak-hash',
    title: 'Weak hash algorithm (MD5 or SHA-1)',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'cryptography',
    pattern:
      /(?:hashlib\.(?:md5|sha1)\(|createHash\(\s*['"](?:md5|sha-?1)['"]|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"|\b(?:md5|sha1)\s*\(\s*\$|Digest::(?:MD5|SHA1)|\bmd5\.New\(\)|\bsha1\.New\(\)|MD5\.Create\(\)|SHA1\.Create\(\))/i,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-CRY-002',
    kb: 'weak-cipher',
    title: 'Weak or insecure cipher mode',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'cryptography',
    pattern:
      /(?:Cipher\.getInstance\(\s*"(?:DES|DESede|RC4|AES(?:\/ECB[^"]*)?|AES\/ECB)"|createCipher\(|AES\.MODE_ECB|\bDES\.new\(|\bARC4\.new\(|(?:aes|des)-\d*-?ecb|MCRYPT_(?:DES|RC4|3DES)|new\s+(?:DES|RC2|TripleDES)CryptoServiceProvider|des\.NewCipher|rc4\.NewCipher|CipherMode\.ECB)/i,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-CRY-003',
    kb: 'insecure-random',
    title: 'Non-cryptographic random number used where a secret may be needed',
    severity: 'medium',
    confidence: 'low',
    domain: 'code',
    category: 'cryptography',
    pattern:
      /(?:(?:token|secret|password|passwd|session|nonce|salt|otp|reset|csrf|api_?key|auth|key)\w*\s*[:=][^;\n]*(?:Math\.random\(|\brandom\.(?:random|randint|choice|choices|randrange)\(|\bnew Random\(|\brand\(|\bmt_rand\(|\brand\.Intn\(|\bRandom\.new))/i,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-CRY-004',
    kb: 'tls-verification-disabled',
    title: 'TLS certificate verification disabled',
    severity: 'high',
    confidence: 'high',
    domain: 'code',
    category: 'cryptography',
    pattern:
      /(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|InsecureSkipVerify\s*:\s*true|_create_unverified_context|CURLOPT_SSL_VERIFY(?:PEER|HOST)['"]?\s*,\s*(?:false|0)|\bcurl\b[^\n|;]*\s(?:-k|--insecure)\b|ServerCertificateValidationCallback\s*[+=]\s*\([^)]*\)\s*=>\s*true|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|SSL_VERIFY_NONE|check_hostname\s*=\s*False|strictSSL\s*:\s*false)/,
    appliesTo: (p) => anyCode(p) || /Dockerfile/i.test(p) || /\.github\/workflows\//.test(p),
    includeTests: false,
  },
  {
    id: 'CODE-CRY-005',
    kb: 'password-storage',
    title: 'Password handled with a fast hash or stored in clear text',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'cryptography',
    pattern:
      /(?:password\w*\s*[:=]\s*(?:hashlib\.(?:md5|sha1|sha256)|crypto\.createHash\(\s*['"](?:md5|sha1|sha256)['"])|(?:hashlib\.(?:md5|sha1|sha256)|createHash\(\s*['"](?:md5|sha1|sha256)['"]\))\s*[.(]\s*(?:\w+\.)?password|\bmd5\(\s*\$_(?:POST|GET|REQUEST)\[\s*['"]pass)/i,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-CRY-006',
    kb: 'jwt-misuse',
    title: 'JWT verification disabled or algorithm "none" accepted',
    severity: 'critical',
    confidence: 'high',
    domain: 'code',
    category: 'authentication',
    pattern:
      /(?:jwt\.decode\([^)]*verify(?:_signature)?['"]?\s*[:=]\s*False|algorithms?\s*[:=]\s*\[\s*['"]none['"]|algorithm\s*[:=]\s*['"]none['"]|jwt\.decode\(\s*\w+\s*,\s*options\s*=\s*\{[^}]*verify_signature['"]?\s*:\s*False|ignoreExpiration\s*:\s*true|jwt\.verify\([^)]*\{[^}]*algorithms\s*:\s*\[[^\]]*['"]none)/i,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-CRY-007',
    kb: 'hardcoded-iv',
    title: 'Hard-coded encryption key or initialisation vector',
    severity: 'medium',
    confidence: 'low',
    domain: 'code',
    category: 'cryptography',
    pattern:
      /\b(?:iv|nonce|encryption_?key|aes_?key|secret_?key|cipher_?key)\s*[:=]\s*(?:b?['"][^'"\s]{8,}['"]|Buffer\.from\(\s*['"][^'"]{8,}['"]|\[\s*(?:0x[0-9a-f]{2}\s*,\s*){7,})/i,
    appliesTo: anyCode,
    maskValue: true,
    accept: (line, m) => !PLACEHOLDER.test(m[0]) && !/process\.env|getenv|environ/i.test(line),
  },
  // ---------- Secrets ----------
  {
    id: 'CODE-SEC-001',
    kb: 'hardcoded-secret',
    title: 'Possible hard-coded credential',
    severity: 'high',
    confidence: 'low',
    domain: 'secrets',
    category: 'secrets',
    pattern:
      /\b(?:password|passwd|pwd|secret|api_?key|apikey|token|auth_?key|private_?key|client_?secret|access_?key|db_?pass)\w*\s*[:=]\s*(['"])([^'"\s]{8,})\1/i,
    appliesTo: (p) => anyCode(p) || /\.(ya?ml|json|toml|ini|cfg|conf|properties|xml)$/i.test(p),
    maskValue: true,
    accept: (line, m) =>
      !PLACEHOLDER.test(m[2] ?? '') &&
      !/(?:_env|Env|ENV)\b\s*[:=]/.test(line) &&
      !/^\s*(\/\/|#|\*)/.test(line) &&
      !/^[A-Z][A-Z0-9_]+$/.test(m[2] ?? '') &&
      !/(?:type|typeof|interface|label|placeholder|description|name)\s*[:=]/i.test(line),
  },
  {
    id: 'CODE-SEC-002',
    kb: 'hardcoded-secret',
    title: 'Credentials embedded in a connection string or URL',
    severity: 'high',
    confidence: 'medium',
    domain: 'secrets',
    category: 'secrets',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|ftp|sftp|smtp|https?):\/\/[^\s:@/'"]+:([^\s@/'"]{4,})@[^\s'"]+/i,
    appliesTo: (p) =>
      anyCode(p) ||
      /\.(ya?ml|json|toml|ini|cfg|conf|properties|xml|env)$/i.test(p) ||
      /(^|\/)\.env\.[\w.]+$/i.test(p),
    maskValue: true,
    accept: (line, m) =>
      !PLACEHOLDER.test(m[1] ?? '') &&
      !/(?:user|pass|password|username)(?::|@)/i.test(
        m[0].replace(/^[a-z+]+:\/\//i, '').split('@')[0] ?? '',
      ),
  },
  // ---------- Authentication & session ----------
  {
    id: 'CODE-AUT-001',
    kb: 'insecure-session-cookie',
    title: 'Session or cookie configured without security flags',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'authentication',
    pattern:
      /(?:(?:secure|httpOnly|http_only)\s*[:=]\s*(?:false|False)\b|SESSION_COOKIE_(?:SECURE|HTTPONLY)\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|\bsame_?[Ss]ite\s*[:=]\s*['"][Nn]one['"](?![^\n]*[Ss]ecure\s*[:=]\s*true))/,
    appliesTo: anyCode,
    accept: (line) =>
      !/^\s*(\/\/|#|\*)/.test(line) && /cookie|session|SESSION|csrf|CSRF/i.test(line),
  },
  {
    id: 'CODE-AUT-002',
    kb: 'weak-session-secret',
    title: 'Weak or default signing secret',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'authentication',
    pattern:
      /(?:(?:secret(?:_key)?|SECRET_KEY|jwt_?secret|session_?secret|signing_?key)\s*[:=]\s*['"](?:secret|changeme|change_me|keyboard cat|password|default|dev|development|test|12345\d*|supersecret|super-secret|mysecret|my-secret|your[-_ ]?secret|django-insecure-[^'"]*|[a-z]{1,6})['"]|\bsecret\s*:\s*['"](?:keyboard cat|secret)['"])/i,
    appliesTo: anyCode,
    includeTests: false,
  },
  {
    id: 'CODE-AUT-003',
    kb: 'auth-disabled',
    title: 'Authentication or CSRF protection switched off',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'authentication',
    pattern:
      /(?:@csrf_exempt|csrf\(\)\.disable\(\)|\.csrf\(\s*\)\s*\.disable|http\.csrf\(\)\.disable|\.antMatchers\([^)]*\)\.permitAll\(\)\.anyRequest\(\)\.permitAll|WTF_CSRF_ENABLED\s*=\s*False|CSRF_ENABLED\s*=\s*False|SecurityContext\.setAuthentication\(null|\[AllowAnonymous\]\s*\n?\s*\[HttpPost|app\.disable\(\s*['"]x-powered-by['"]\s*\)\s*;?\s*\/\/\s*TODO|verify_csrf_token\s*=\s*false|skip_before_action\s*:verify_authenticity_token|protect_from_forgery\s+with:\s*:null_session)/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-AUT-004',
    kb: 'cors-code',
    title: 'Permissive CORS policy in code',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'cors',
    pattern:
      /(?:Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]|\borigin\s*:\s*(?:['"]\*['"]|true)\b|allow_origins\s*=\s*\[\s*['"]\*['"]|CORS_(?:ORIGIN_)?ALLOW_ALL(?:_ORIGINS)?\s*=\s*True|AllowAnyOrigin\(\)|\.allowedOrigins\(\s*"\*"\s*\)|cors\(\s*\)\s*(?:\)|;|$)|setAllowCredentials\(\s*true\s*\)[^;]*addAllowedOrigin\(\s*"\*")/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-AUT-005',
    kb: 'mass-assignment',
    title: 'Whole request body passed into a model (mass assignment)',
    severity: 'medium',
    confidence: 'low',
    domain: 'code',
    category: 'authorization',
    pattern:
      /(?:\.(?:create|update|updateOne|findByIdAndUpdate|findOneAndUpdate|insertOne|build|set)\(\s*(?:\w+\s*,\s*)?req\.body\s*[,)]|new\s+\w+\(\s*req\.body\s*\)|\.\$set\s*:\s*req\.body|Object\.assign\(\s*\w+\s*,\s*req\.body\s*\)|\.update_attributes\(\s*params\[|\.new\(\s*params\[|\bparams\.permit!|\.update\(\s*\*\*request\.(?:data|json|POST))/,
    appliesTo: anyCode,
  },
  // ---------- Deserialization / parsing ----------
  {
    id: 'CODE-DES-001',
    kb: 'insecure-deserialization',
    title: 'Unsafe deserialization of data',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'deserialization',
    pattern:
      /(?:\bpickle\.loads?\(|\bcPickle\.loads?\(|\byaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?(?:Safe|CSafe)Loader)(?![^)]*safe)|\byaml\.unsafe_load\(|\bmarshal\.loads?\(|\bshelve\.open\(|\bunserialize\(\s*\$|\bObjectInputStream\s*\(|\.readObject\(\)|new\s+ObjectInputStream|\bYaml\.load\(|\bMarshal\.load\(|\bnode-serialize|serialize\.unserialize\(|BinaryFormatter\(\)|\bJsonConvert\.DeserializeObject\([^)]*TypeNameHandling\.(?:All|Auto|Objects|Arrays)|\bLosFormatter|\bSoapFormatter|XamlReader\.(?:Load|Parse)\()/,
    appliesTo: anyCode,
    accept: (line) => !/^\s*(\/\/|#|\*)/.test(line) && !/safe_load/.test(line),
  },
  {
    id: 'CODE-DES-002',
    kb: 'xxe',
    title: 'XML parser that may resolve external entities (XXE)',
    severity: 'high',
    confidence: 'low',
    domain: 'code',
    category: 'deserialization',
    pattern:
      /(?:DocumentBuilderFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)|TransformerFactory\.newInstance\(\)|\bXmlDocument\b|XmlTextReader\(|libxml_disable_entity_loader\(\s*false|LIBXML_NOENT|resolve_entities\s*=\s*True|etree\.XMLParser\([^)]*resolve_entities\s*=\s*True|DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver)/,
    appliesTo: anyCode,
  },
  // ---------- SSRF / traversal / redirect ----------
  {
    id: 'CODE-SSR-001',
    kb: 'ssrf',
    title: 'Server-side request made to a URL taken from the request',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'ssrf',
    pattern:
      /(?:\b(?:fetch|axios(?:\.(?:get|post|request))?|got|request|needle|superagent\.(?:get|post)|http\.get|https\.get|urllib\.request\.urlopen|requests\.(?:get|post|put|head|request)|httpx\.(?:get|post)|aiohttp\.\w+\.get|file_get_contents|curl_setopt\([^)]*CURLOPT_URL|HttpClient\.\w+|new\s+URL|http\.NewRequest|http\.Get|RestTemplate\.\w+|WebClient\.\w+)\s*\(\s*[^)]*(?:req\.(?:body|query|params)|request\.(?:args|form|json|GET|POST|data)|\$_(?:GET|POST|REQUEST)|params\[|getParameter\())/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-PTH-001',
    kb: 'path-traversal',
    title: 'File path built from request data (path traversal)',
    severity: 'high',
    confidence: 'medium',
    domain: 'code',
    category: 'path-traversal',
    pattern:
      /(?:\b(?:readFile(?:Sync)?|createReadStream|writeFile(?:Sync)?|sendFile|unlink(?:Sync)?|readdir(?:Sync)?|open|send_file|send_from_directory|FileResponse|file_get_contents|fopen|include|require|include_once|require_once|readfile|File\.(?:read|open|new)|new\s+File(?:InputStream|Reader)?|Paths\.get|os\.Open|ioutil\.ReadFile|os\.ReadFile)\s*\(\s*[^)]*(?:req\.(?:body|query|params)|request\.(?:args|form|GET|POST|json|data)|\$_(?:GET|POST|REQUEST)|params\[|getParameter\())/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-RED-001',
    kb: 'open-redirect',
    title: 'Redirect to a location taken from the request',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'redirect',
    pattern:
      /(?:\bres\.redirect\(\s*(?:[^)]*req\.(?:query|body|params)|[^)]*\+)|\bredirect\(\s*request\.(?:args|form|GET|POST|values)|\bHttpResponseRedirect\(\s*request\.(?:GET|POST)|\bheader\(\s*['"]Location:\s*['"]?\s*\.\s*\$_(?:GET|POST|REQUEST)|\bsendRedirect\(\s*request\.getParameter|\bredirect_to\s+params\[|http\.Redirect\([^)]*r\.(?:URL\.Query|FormValue)|\bRedirect\(\s*Request\.(?:QueryString|Form))/,
    appliesTo: anyCode,
  },
  // ---------- Uploads, logging, misc ----------
  {
    id: 'CODE-UPL-001',
    kb: 'unsafe-upload',
    title: 'File upload saved using the client-supplied file name',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'file-upload',
    pattern:
      /(?:\.mv\(\s*[^)]*\.name\b|\.originalname\b[^;\n]*(?:path\.join|\+|`)|(?:path\.join|\+)[^;\n]*\.originalname\b|\.save\(\s*(?:os\.path\.join\([^)]*)?\w+\.filename\b|move_uploaded_file\([^)]*\$_FILES\[[^\]]+\]\[['"]name['"]\]|getOriginalFilename\(\)[^;\n]*(?:\+|Paths\.get|new File))/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-LOG-001',
    kb: 'sensitive-logging',
    title: 'Sensitive value written to logs',
    severity: 'medium',
    confidence: 'low',
    domain: 'code',
    category: 'logging',
    pattern:
      /\b(?:console\.(?:log|info|debug|warn|error)|logger?\.(?:info|debug|warn|warning|error)|log\.(?:Print|Printf|Println|Info|Debug)|print|puts|System\.out\.println|Log\.[dviwe])\s*\([^)]*\b(?:password|passwd|secret|api_?key|access_?token|refresh_?token|authorization|credit_?card|card_?number|cvv|ssn)\b/i,
    appliesTo: anyCode,
    accept: (line) =>
      !/(?:missing|invalid|required|failed|error|expired|must|should|not found|empty|reset|change|forgot)/i.test(
        line.slice(0, 200).replace(/\b(?:password|secret)\w*\s*[,)]/gi, ''),
      ),
  },
  {
    id: 'CODE-DBG-001',
    kb: 'debug-enabled',
    title: 'Debug mode enabled in application code',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'misconfiguration',
    pattern:
      /(?:\.run\([^)]*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|app\.debug\s*=\s*True|FLASK_DEBUG\s*=\s*['"]?1|display_errors\s*=\s*(?:On|1|true)|ini_set\(\s*['"]display_errors['"]\s*,\s*(?:1|['"]1['"]|true)|error_reporting\(\s*E_ALL\s*\)|APP_DEBUG\s*=\s*true|config\.debug\s*=\s*true|spring\.devtools|management\.endpoints\.web\.exposure\.include\s*=\s*\*|app\.UseDeveloperExceptionPage\(\)|ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\])/,
    appliesTo: (p) =>
      anyCode(p) || /\.(properties|ini|ya?ml|env)$/i.test(p) || /(^|\/)\.env\.[\w.]+$/i.test(p),
  },
  {
    id: 'CODE-NET-001',
    kb: 'bind-all-interfaces',
    title: 'Service bound to all network interfaces',
    severity: 'low',
    confidence: 'low',
    domain: 'code',
    category: 'misconfiguration',
    pattern:
      /(?:\.listen\([^)]*['"]0\.0\.0\.0['"]|host\s*[:=]\s*['"]0\.0\.0\.0['"]|ListenAndServe\(\s*":\d+"|\.bind\(\s*\(?\s*['"]0\.0\.0\.0['"])/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-PRM-001',
    kb: 'file-permissions',
    title: 'World-writable permissions',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'misconfiguration',
    pattern:
      /(?:chmod\s+(?:-R\s+)?0?777\b|\b0o?777\b(?=\s*[,)])|chmod\([^)]*0?777|FileMode\(0?777\)|\bumask\(\s*0\s*\))/,
    appliesTo: (p) => anyCode(p) || /Dockerfile/i.test(p),
  },
  {
    id: 'CODE-ERR-001',
    kb: 'empty-catch',
    title: 'Empty exception handler hides errors',
    severity: 'low',
    confidence: 'medium',
    domain: 'code',
    category: 'error-handling',
    pattern:
      /(?:catch\s*(?:\([^)]*\))?\s*\{\s*\}|\bexcept\b[^:\n]*:\s*pass\b|^\s*except\s*:|rescue\s*(?:=>\s*\w+)?\s*$\s*end)/,
    appliesTo: (p) => JS(p) || PY(p) || JAVA(p) || CS(p) || PHP(p),
  },
  {
    id: 'CODE-ERR-002',
    kb: 'verbose-errors-code',
    title: 'Stack trace or exception detail returned to the client',
    severity: 'medium',
    confidence: 'medium',
    domain: 'code',
    category: 'error-handling',
    pattern:
      /(?:res\.(?:status\(\d+\)\.)?(?:send|json)\(\s*(?:\{[^}]*)?(?:err|error|e)\.stack|res\.(?:status\(\d+\)\.)?(?:send|json)\(\s*(?:err|error)\s*\)|traceback\.format_exc\(\)[^\n]*(?:return|jsonify|Response)|(?:return|jsonify|Response)[^\n]*traceback\.format_exc|printStackTrace\(\s*(?:response|out|resp)|\becho\s+\$e->getMessage\(\)|\becho\s+mysqli?_error)/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-RGX-001',
    kb: 'regex-dos',
    title: 'Regular expression with nested quantifiers (ReDoS risk)',
    severity: 'low',
    confidence: 'low',
    domain: 'code',
    category: 'denial-of-service',
    pattern:
      /(?:new RegExp\(|re\.compile\(|Pattern\.compile\(|\/)[^\n]{0,80}\((?:\?:)?(?:\\[dwsDWS.]|\[[^\]\n]+\]|\.|\w)[+*]\)[+*{]/,
    appliesTo: (p) => JS(p) || PY(p) || JAVA(p),
  },
  {
    id: 'CODE-HDR-001',
    kb: 'header-injection',
    title: 'Response header value taken from the request',
    severity: 'medium',
    confidence: 'low',
    domain: 'code',
    category: 'injection',
    pattern:
      /(?:\bres\.(?:setHeader|set|header|append)\(\s*[^,)]+,\s*[^)]*req\.(?:query|body|params|headers)|\bresponse\[['"][\w-]+['"]\]\s*=\s*request\.(?:GET|POST)|\bheader\(\s*[^)]*\$_(?:GET|POST|REQUEST))/,
    appliesTo: anyCode,
  },
  {
    id: 'CODE-WEB-001',
    kb: 'postmessage-origin',
    title: 'postMessage handler or sender without origin check',
    severity: 'medium',
    confidence: 'low',
    domain: 'code',
    category: 'xss',
    pattern:
      /(?:\.postMessage\([^)]*,\s*['"]\*['"]\s*\)|addEventListener\(\s*['"]message['"]\s*,\s*(?:async\s*)?(?:\(?\s*\w*\s*\)?\s*=>|function)(?![^\n]*\.origin))/,
    appliesTo: (p) => JS(p) || templates(p),
  },
  {
    id: 'CODE-WEB-002',
    kb: 'target-blank',
    title: 'Link opens a new tab without rel="noopener"',
    severity: 'info',
    confidence: 'medium',
    domain: 'code',
    category: 'misconfiguration',
    pattern: /<a\b[^>]*\btarget\s*=\s*["']_blank["'](?![^>]*\brel\s*=\s*["'][^"']*noopener)[^>]*>/i,
    appliesTo: (p) => templates(p) || JS(p),
  },
  {
    id: 'CODE-GHA-001',
    kb: 'github-actions-injection',
    title: 'Untrusted GitHub context expanded inside a run script',
    severity: 'high',
    confidence: 'medium',
    domain: 'config',
    category: 'ci-cd',
    pattern:
      /^\s*-?\s*run:.*\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review|head_commit|pages|discussion)[\w.[\]*]*\.(?:title|body|message|name|label|ref|email)|head_ref)\s*\}\}/,
    appliesTo: (p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p),
    includeTests: true,
  },
  {
    id: 'CODE-GHA-002',
    kb: 'github-actions-pinning',
    title: 'GitHub Action pinned to a moving branch',
    severity: 'low',
    confidence: 'high',
    domain: 'config',
    category: 'ci-cd',
    pattern: /^\s*-?\s*uses:\s*[\w.-]+\/[\w./-]+@(?:main|master|latest)\s*$/,
    appliesTo: (p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p),
    includeTests: true,
  },
  {
    id: 'CODE-GHA-003',
    kb: 'github-actions-permissions',
    title: 'Workflow grants write-all permissions',
    severity: 'medium',
    confidence: 'high',
    domain: 'config',
    category: 'ci-cd',
    pattern: /^\s*permissions:\s*write-all\s*$/,
    appliesTo: (p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p),
    includeTests: true,
  },
  {
    id: 'CODE-SHL-001',
    kb: 'curl-pipe-shell',
    title: 'Remote script piped into a shell',
    severity: 'medium',
    confidence: 'medium',
    domain: 'config',
    category: 'supply-chain',
    pattern: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/,
    appliesTo: (p) => /^\.github\/workflows\//.test(p) || /Dockerfile/i.test(p) || SHELL(p),
    includeTests: true,
  },
];
