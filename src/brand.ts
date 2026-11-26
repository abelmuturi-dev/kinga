/**
 * Single place for the product's identity. Rename the product by editing this file
 * (plus package.json "name"/"bin"); nothing else hard-codes the name.
 */
export const BRAND = {
  /** Display name. */
  name: 'Kinga',
  /** Command typed in a terminal. */
  command: 'kinga',
  /** Swahili "kinga": protection, defence. */
  tagline:
    'Security framework for developers: scan live sites and code under development, get the fix.',
  /** Marker for inline suppressions, e.g. `kinga-ignore-next-line`. */
  ignoreMarker: 'kinga-ignore',
  /** Project-level config file and local state directory. */
  configFile: 'kinga.config.json',
  stateDir: '.kinga',
  /** Identifies scan traffic to site owners. Always sent on web scans. */
  userAgent: (version: string): string =>
    `Kinga-Security-Scanner/${version} (+defensive-scan; authorised testing only)`,
} as const;
