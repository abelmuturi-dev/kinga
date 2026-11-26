export interface BenchmarkCase {
  id: string;
  /** Rule IDs that should be reported for this fixture. */
  expectedRules: readonly string[];
  /** Rule IDs actually reported by the scanner. */
  actualRules: readonly string[];
  tags?: readonly string[];
}

export interface BenchmarkMetrics {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  trueNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  /** Only meaningful when a finite ruleUniverse is supplied. */
  falsePositiveRate: number;
  evaluatedCases: number;
  ruleMetrics: Record<string, {
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
    f1: number;
  }>;
}

function rate(numerator: number, denominator: number, emptyValue = 0): number {
  return denominator === 0 ? emptyValue : numerator / denominator;
}

function harmonicMean(precision: number, recall: number): number {
  return precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
}

/**
 * Evaluate scanner output against explicit expected rule IDs.
 * Supply a finite ruleUniverse to calculate true negatives and false-positive rate.
 * Without it, those two metrics are deliberately reported as zero/undefined-by-design.
 */
export function evaluateBenchmark(
  cases: readonly BenchmarkCase[],
  ruleUniverse: readonly string[] = [],
): BenchmarkMetrics {
  const caseIds = new Set<string>();
  const universe = new Set(ruleUniverse);
  if (universe.size !== ruleUniverse.length) throw new Error('ruleUniverse contains duplicate rule IDs.');

  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;
  const perRule = new Map<string, { tp: number; fp: number; fn: number }>();

  for (const testCase of cases) {
    if (!testCase.id || caseIds.has(testCase.id)) {
      throw new Error(`Duplicate or empty benchmark case ID: ${testCase.id}`);
    }
    caseIds.add(testCase.id);
    const expected = new Set(testCase.expectedRules);
    const actual = new Set(testCase.actualRules);
    if (expected.size !== testCase.expectedRules.length || actual.size !== testCase.actualRules.length) {
      throw new Error(`Benchmark case ${testCase.id} contains duplicate rule IDs.`);
    }
    if (ruleUniverse.length > 0) {
      const outside = [...expected, ...actual].filter((id) => !universe.has(id));
      if (outside.length > 0) {
        throw new Error(`Benchmark case ${testCase.id} references rules outside ruleUniverse: ${outside.join(', ')}`);
      }
    } else {
      for (const id of [...expected, ...actual]) universe.add(id);
    }

    for (const id of universe) {
      const shouldFind = expected.has(id);
      const didFind = actual.has(id);
      const counts = perRule.get(id) ?? { tp: 0, fp: 0, fn: 0 };
      if (shouldFind && didFind) { truePositives++; counts.tp++; }
      else if (!shouldFind && didFind) { falsePositives++; counts.fp++; }
      else if (shouldFind && !didFind) { falseNegatives++; counts.fn++; }
      else if (ruleUniverse.length > 0) trueNegatives++;
      perRule.set(id, counts);
    }
  }

  const precision = rate(truePositives, truePositives + falsePositives);
  const recall = rate(truePositives, truePositives + falseNegatives, 1);
  const ruleMetrics: BenchmarkMetrics['ruleMetrics'] = {};
  for (const [id, counts] of perRule) {
    const p = rate(counts.tp, counts.tp + counts.fp);
    const r = rate(counts.tp, counts.tp + counts.fn, 1);
    ruleMetrics[id] = {
      truePositives: counts.tp,
      falsePositives: counts.fp,
      falseNegatives: counts.fn,
      precision: p,
      recall: r,
      f1: harmonicMean(p, r),
    };
  }

  return {
    truePositives,
    falsePositives,
    falseNegatives,
    trueNegatives,
    precision,
    recall,
    f1: harmonicMean(precision, recall),
    falsePositiveRate: rate(falsePositives, falsePositives + trueNegatives),
    evaluatedCases: cases.length,
    ruleMetrics,
  };
}
