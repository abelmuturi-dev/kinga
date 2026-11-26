import { BRAND } from './brand.js';

const C = BRAND.command;

export function mainHelp(): string {
  return `${BRAND.name}: ${BRAND.tagline}

Usage
  ${C} scan [target...]      Scan URLs and/or project folders (auto-detected)
  ${C} web <url>             Scan a live website or a dev server
  ${C} code [dir]            Scan a project under development (default: current folder)
  ${C} ask "<question>"      Ask the built-in advisor how to fix something (offline)
  ${C} explain <topic>       Show the full fix guidance for a topic
  ${C} topics                List the topics the advisor knows
  ${C} baseline [dir]        Record current findings so later scans show only new ones
  ${C} init                  Create ${BRAND.configFile}
  ${C} help [command]        Help
  ${C} --version

Common options
  -f, --format <f>        text (default), markdown, html, json, sarif
  -o, --output <file>     Write the report to a file (outside the scanned project)
      --fail-on <sev>     Exit 1 if any finding is at or above: critical, high, medium, low, info
      --min-severity <s>  Hide findings below this level in text output
  -v, --verbose           Full guidance for every finding in text output
  -c, --config <file>     Config file (default: ${BRAND.configFile})
      --no-baseline       Ignore the baseline file

Web options
      --level <l>         passive (default) or active (extra probes: CORS, methods, exposed files, TLS versions)
      --authorized        Confirm you own the target or have written permission (required for active scans of non-local hosts)
      --insecure          Continue past an invalid certificate (it is still reported)
      --max-requests <n>  Request budget (default 80)    --max-pages <n>  Pages to crawl (default 10)
      --delay <ms>        Pause between requests (default 250)    --timeout <ms>  Per-request timeout

Examples
  ${C} code .                                   # scan the project in this folder
  ${C} web https://staging.example.com          # passive check of a live site
  ${C} web http://localhost:3000 --level active # dev server (no confirmation needed for local addresses)
  ${C} scan . https://example.com -f html -o report.html
  ${C} ask "how do I stop SQL injection in Django"

Only scan systems you own or are authorised to test.`;
}

const TOPIC_HELP: Record<string, string> = {
  scan: `${C} scan [target...] [options]\n\nTargets that start with http(s):// or look like a host are scanned as websites; existing folders are scanned as code. With no target, the current folder is scanned.\nSee \`${C} help\` for options.`,
  web: `${C} web <url> [--level passive|active] [--authorized]\n\nPassive (default): fetches the page, robots.txt and security.txt, inspects TLS, headers, cookies, forms and scripts.\nActive: also sends CORS/OPTIONS probes, a small crawl, checks for exposed files such as /.env and /.git, and tests legacy TLS versions. Requires --authorized for non-local hosts.\nRequests identify themselves as ${BRAND.name} and are rate limited. No request bodies are sent and nothing is exploited.`,
  code: `${C} code [dir] [options]\n\nReads source, config, Docker/Kubernetes/Terraform files, CI workflows and dependency manifests. Never runs project code and never contacts the network. Suppress a line with a comment containing ${BRAND.ignoreMarker} (or ${BRAND.ignoreMarker}-next-line on the line before).`,
  ask: `${C} ask "<question>"\n\nAnswers from the built-in knowledge base, offline. Mention your stack (Django, Express, nginx, Spring…) to get matching examples.`,
  explain: `${C} explain <topic>\n\nPrints the full guidance for one topic id (see \`${C} topics\`). Anything else is treated as a question.`,
  baseline: `${C} baseline [dir]\n\nSaves fingerprints of current findings. Set "baseline" in ${BRAND.configFile}; later scans hide those findings and report only new ones.`,
  init: `${C} init\n\nWrites a starter ${BRAND.configFile}.`,
};

export function topicHelp(topic: string): string | undefined {
  return TOPIC_HELP[topic];
}

export function helpTopics(): string[] {
  return Object.keys(TOPIC_HELP);
}
