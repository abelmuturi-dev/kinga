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
  ${C} assurance <action>    SBOM, OSV, DNS, API contracts, compliance and scan comparison
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
  scan: `${C} scan [target...] [options]\\n\\nTargets are auto-detected as URLs or folders. With no target, the current folder is scanned.`,
  web: `${C} web <url> [--level passive|active] [--authorized]\\n\\nPassive scanning is the default. Active scans send extra probes and require authorization for non-local targets.`,
  code: `${C} code [dir] [options]\\n\\nReads source, configuration, infrastructure and dependency files. It never executes project code.`,
  ask: `${C} ask "<question>"\\n\\nAnswers from the built-in knowledge base, offline.`,
  explain: `${C} explain <topic>\\n\\nShows full guidance for a knowledge-base topic.`,
  baseline: `${C} baseline [dir]\\n\\nSaves fingerprints of current findings for future comparisons.`,
  assurance: `${C} assurance <sbom|osv|dns|js|api|compare|compliance|history|rephrase> ...\\n\\nGenerate SBOMs, check OSV, inspect DNS, JavaScript and API contracts, compare scans, map compliance controls, save history or rephrase curated advice locally.`,
  init: `${C} init\\n\\nWrites a starter ${BRAND.configFile}.`,
};

export function topicHelp(topic: string): string | undefined {
  return TOPIC_HELP[topic];
}

export function helpTopics(): string[] {
  return Object.keys(TOPIC_HELP);
}
