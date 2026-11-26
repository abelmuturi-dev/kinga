export { buildCycloneDx, writeCycloneDx, type CycloneDxBom, type SbomComponent } from './sbom.js';
export { scanBomWithOsv } from './osv-bom.js';
export {
  mapFindingToCompliance,
  buildComplianceReport,
  type ComplianceControl,
  type ComplianceFramework,
} from './compliance.js';
export { compareScanResults, saveScanHistory, loadScanResult, type ScanDelta } from './trends.js';
export { inspectDns, type DnsPosture } from './dns.js';
export { inspectJavaScriptAsset, type JavaScriptIndicator } from './javascript.js';
export { rephraseWithLocalModel } from './local-model.js';
