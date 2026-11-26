import ts from 'typescript';

export interface TaintFlow {
  rule: string;
  severity: 'high' | 'medium';
  confidence: 'medium' | 'low';
  source: string;
  sink: string;
  line: number;
  evidence: string;
}

const SOURCE =
  /(?:req\.(?:body|query|params|headers|cookies)|request\.(?:args|form|values|json|GET|POST|data|query_params|body)|\$_(?:GET|POST|REQUEST|COOKIE|FILES)|process\.argv|URLSearchParams|searchParams\.get|location\.(?:search|hash))/;
const SINK_CALL = /^(?:eval|exec|execSync|execFile|spawn|query|execute|raw|writeFile|readFile)$/;

function nodeText(node: ts.Node, source: ts.SourceFile): string {
  return node.getText(source).slice(0, 240);
}

function isSource(node: ts.Node, source: ts.SourceFile): boolean {
  return SOURCE.test(nodeText(node, source));
}

function sinkDescription(node: ts.CallExpression, source: ts.SourceFile): string | null {
  const expression = node.expression;
  if (ts.isIdentifier(expression) && SINK_CALL.test(expression.text)) {
    return expression.text;
  }
  if (ts.isPropertyAccessExpression(expression)) {
    const method = expression.name.text;
    const receiver = nodeText(expression.expression, source);
    if (
      ['query', 'execute', 'raw', 'writeFile', 'readFile'].includes(method) ||
      (['exec', 'execSync', 'execFile', 'spawn'].includes(method) && /child_process/.test(receiver))
    ) {
      return method;
    }
  }
  return null;
}

/**
 * Conservative intraprocedural taint heuristic over the TypeScript/JavaScript AST.
 * It propagates taint through variable declarations and assignments within a file.
 * It does not perform interprocedural, path-sensitive or framework-aware analysis.
 */
export function analyseTaint(sourceText: string, fileName = 'source.ts'): TaintFlow[] {
  const kind = /\.tsx$/i.test(fileName)
    ? ts.ScriptKind.TSX
    : /\.(?:[cm]?ts)$/i.test(fileName)
      ? ts.ScriptKind.TS
      : /\.jsx$/i.test(fileName)
        ? ts.ScriptKind.JSX
        : ts.ScriptKind.JS;
  const source = ts.createSourceFile(fileName, sourceText, ts.ScriptTarget.Latest, true, kind);
  const tainted = new Set<string>();
  const flows: TaintFlow[] = [];
  const seen = new Set<string>();

  const expressionIsTainted = (node: ts.Node): boolean => {
    if (isSource(node, source)) return true;
    if (ts.isIdentifier(node)) return tainted.has(node.text);
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      return (
        expressionIsTainted(node.expression) ||
        (ts.isElementAccessExpression(node) &&
          node.argumentExpression !== undefined &&
          expressionIsTainted(node.argumentExpression))
      );
    }
    if (ts.isBinaryExpression(node)) {
      return expressionIsTainted(node.left) || expressionIsTainted(node.right);
    }
    if (ts.isTemplateExpression(node)) {
      return node.templateSpans.some((span) => expressionIsTainted(span.expression));
    }
    if (ts.isArrayLiteralExpression(node)) {
      return node.elements.some(expressionIsTainted);
    }
    if (ts.isObjectLiteralExpression(node)) {
      return node.properties.some((property) => {
        if (ts.isPropertyAssignment(property)) return expressionIsTainted(property.initializer);
        if (ts.isShorthandPropertyAssignment(property)) return tainted.has(property.name.text);
        return false;
      });
    }
    if (ts.isCallExpression(node)) {
      return isSource(node, source) || node.arguments.some(expressionIsTainted);
    }
    return node.forEachChild((child) => expressionIsTainted(child)) ?? false;
  };

  const addFlow = (
    sink: string,
    node: ts.Node,
    severity: TaintFlow['severity'],
    confidence: TaintFlow['confidence'],
  ): void => {
    const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
    const key = `${sink}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    flows.push({
      rule: 'CODE-TAINT-001',
      severity,
      confidence,
      source: 'untrusted input',
      sink,
      line,
      evidence: `AST flow candidate from untrusted input to ${sink}; review sanitization and validation.`,
    });
  };

  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      if (expressionIsTainted(node.initializer)) tainted.add(node.name.text);
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      if (expressionIsTainted(node.right)) tainted.add(node.left.text);
      else tainted.delete(node.left.text);
    }

    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) &&
      ['innerHTML', 'outerHTML'].includes(node.left.name.text) &&
      expressionIsTainted(node.right)
    ) {
      addFlow(node.left.name.text, node, 'medium', 'low');
    }

    if (ts.isCallExpression(node)) {
      const sink = sinkDescription(node, source);
      const taintedArgument = node.arguments.find(expressionIsTainted);
      if (sink && taintedArgument) {
        const severity: TaintFlow['severity'] = [
          'exec',
          'execSync',
          'execFile',
          'spawn',
          'eval',
        ].includes(sink)
          ? 'high'
          : 'medium';
        addFlow(sink, node, severity, isSource(taintedArgument, source) ? 'medium' : 'low');
      }
    }

    if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === 'Function' &&
      (node.arguments ?? []).some(expressionIsTainted)
    ) {
      addFlow('Function constructor', node, 'high', 'medium');
    }

    ts.forEachChild(node, visit);
  };

  visit(source);
  return flows;
}
