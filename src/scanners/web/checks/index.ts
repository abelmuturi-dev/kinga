import type { WebCheck } from '../context.js';
import { corsCheck, exposureCheck, methodsCheck } from './active.js';
import { contentChecks } from './content.js';
import { cookieChecks } from './cookies.js';
import { disclosureChecks } from './disclosure.js';
import { headerChecks } from './headers.js';
import { tlsChecks, transportChecks } from './transport.js';
import { wellKnownChecks } from './wellknown.js';

export const BUILTIN_WEB_CHECKS: readonly WebCheck[] = [
  headerChecks,
  disclosureChecks,
  cookieChecks,
  transportChecks,
  tlsChecks,
  contentChecks,
  wellKnownChecks,
  corsCheck,
  methodsCheck,
  exposureCheck,
];
