/** Small regex-based HTML helpers. They are tolerant, not a full parser, and never execute anything. */

export interface Tag {
  name: string;
  attrs: Record<string, string>;
  /** Offset of the tag in the source. */
  index: number;
}

const ATTR = /([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

export function parseAttrs(source: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const m of source.matchAll(ATTR)) {
    const name = m[1]?.toLowerCase();
    if (name === undefined || name === '') continue;
    attrs[name] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return attrs;
}

export function findTags(html: string, name: string): Tag[] {
  const re = new RegExp(`<${name}\\b([^>]*)>`, 'gi');
  const out: Tag[] = [];
  for (const m of html.matchAll(re)) {
    out.push({ name, attrs: parseAttrs(m[1] ?? ''), index: m.index ?? 0 });
  }
  return out;
}

export interface Form {
  action: string;
  method: string;
  inputs: Tag[];
  index: number;
}

export function findForms(html: string): Form[] {
  const forms: Form[] = [];
  const re = /<form\b([^>]*)>([\s\S]*?)(?:<\/form>|$)/gi;
  for (const m of html.matchAll(re)) {
    const attrs = parseAttrs(m[1] ?? '');
    forms.push({
      action: attrs['action'] ?? '',
      method: (attrs['method'] ?? 'get').toLowerCase(),
      inputs: [...findTags(m[2] ?? '', 'input'), ...findTags(m[2] ?? '', 'textarea')],
      index: m.index ?? 0,
    });
  }
  return forms;
}

export function findComments(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<!--([\s\S]*?)-->/g)) {
    const text = (m[1] ?? '').trim();
    if (text === '' || /^\[if\b|^<!\[endif|^\s*\/?noindex/i.test(text)) continue;
    out.push(text);
  }
  return out;
}

export function resolveUrl(value: string, base: string): URL | null {
  try {
    if (/^(javascript|data|mailto|tel|#)/i.test(value.trim())) return null;
    return new URL(value, base);
  } catch {
    return null;
  }
}

export interface LibraryHit {
  name: string;
  version: string;
  source: string;
}

const LIBS: Array<{ name: string; re: RegExp }> = [
  { name: 'jquery', re: /jquery[-.@/](\d+\.\d+(?:\.\d+)?)(?:\.min)?(?:\.js)?/i },
  { name: 'bootstrap', re: /bootstrap[-.@/](\d+\.\d+(?:\.\d+)?)(?:\.min)?(?:\.(?:js|css))?/i },
  { name: 'lodash', re: /lodash(?:\.js)?[-.@/](\d+\.\d+\.\d+)/i },
  { name: 'moment', re: /moment(?:\.js)?[-.@/](\d+\.\d+\.\d+)/i },
  { name: 'handlebars', re: /handlebars(?:\.runtime)?[-.@/](\d+\.\d+\.\d+)/i },
  { name: 'underscore', re: /underscore[-.@/](\d+\.\d+\.\d+)/i },
];

/** Library names and versions that can be read from script and stylesheet URLs. */
export function detectLibraries(urls: readonly string[]): LibraryHit[] {
  const seen = new Set<string>();
  const hits: LibraryHit[] = [];
  for (const url of urls) {
    for (const lib of LIBS) {
      const m = lib.re.exec(url);
      if (!m?.[1]) continue;
      const key = `${lib.name}@${m[1]}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push({ name: lib.name, version: m[1], source: url });
    }
  }
  return hits;
}
