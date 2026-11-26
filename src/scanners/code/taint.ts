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
const SINK_CALL =
  /^(?:eval|exec|execSync|execFile|spawn|query|execute|raw|innerHTML|outerHTML|write|writeFile|readFile|createElement)$/;
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
      [
        'query',
        'execute',
        'raw',
        'innerHTML',
        'outerHTML',
        'write',
        'writeFile',
        'readFile',
      ].includes(method) ||
      (['exec', 'execSync', 'execFile', 'spawn'].includes(method) && /child_process/.test(receiver))
    ) {
      return method;
    }
  }
  if (
    ts.isNewExpression(expression) &&
    ts.isIdentifier(expression.expression) &&
    expression.expression.text === 'Function'
  ) {
    return 'Function constructor';
  }
  return null;
}

/**
 * Conservative intraprocedural taint heuristic over the TypeScript/JavaScript AST.
 * It propagates taint through variable declarations and assignments within a file.
 * It does not perform interprocedural, path-sensitive or framework-aware analysis.
 */
export function analyseTaint(sourceText: string, fileName = 'source.ts'): TaintFlow[] {
  const kind = /\.tsx?$/i.test(fileName)
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
    if (ts.isBinaryExpression(node))
      return expressionIsTainted(node.left) || expressionIsTainted(node.right);
    if (ts.isTemplateExpression(node))
      return node.templateSpans.some((span) => expressionIsTainted(span.expression));
    if (ts.isArrayLiteralExpression(node)) return node.elements.some(expressionIsTainted);
    if (ts.isObjectLiteralExpression(node))
      return node.properties.some((property) => {
        if (ts.isPropertyAssignment(property)) return expressionIsTainted(property.initializer);
        if (ts.isShorthandPropertyAssignment(property)) return tainted.has(property.name.text);
        return false;
      });
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isPropertyAccessExpression(node.left) &&
      ['innerHTML', 'outerHTML'].includes(node.left.name.text) &&
      expressionIsTainted(node.right)
    ) {
      const location = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
      const key = `dom:${location}`;
      if (!seen.has(key)) {
        seen.add(key);
        flows.push({
          rule: 'CODE-TAINT-001',
          severity: 'medium',
          confidence: 'low',
          source: 'request-derived value (tracked expression)',
          sink: node.left.name.text,
          line: location,
          evidence: `AST flow candidate from untrusted input to ${node.left.name.text}; review output encoding and sanitization.`,
        });
      }
    }
    if (ts.isCallExpression(node)) {
      return isSource(node, source) || node.arguments.some(expressionIsTainted);
    }
    return node.forEachChild((child) => expressionIsTainted(child)) ?? false;
  };

  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      if (expressionIsTainted(node.initializer)) {
        tainted.add(node.name.text);
        origins.set(
          node.name.text,
          isSource(node.initializer, source)
            ? nodeText(node.initializer, source)
            : (origins.get(node.name.text) ?? 'tainted variable'),
        );
      }
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      if (expressionIsTainted(node.right)) {
        tainted.add(node.left.text);
        origins.set(
          node.left.text,
          isSource(node.right, source)
            ? nodeText(node.right, source)
            : (origins.get(node.left.text) ?? 'tainted assignment'),
        );
      } else {
        tainted.delete(node.left.text);
      }
    }
    if (ts.isCallExpression(node)) {
      const sink = sinkDescription(node, source);
      const taintedArgument = node.arguments.find(expressionIsTainted);
      if (sink && taintedArgument) {
        const location = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
        const key = `${sink}:${location}`;
        if (!seen.has(key)) {
          seen.add(key);
          const direct = isSource(taintedArgument, source);
          flows.push({
            rule: 'CODE-TAINT-001',
            severity: ['exec', 'execSync', 'spawn', 'eval', 'Function constructor'].includes(sink)
              ? 'high'
              : 'medium',
            confidence: direct ? 'medium' : 'low',
            source: direct
              ? nodeText(taintedArgument, source)
              : 'request-derived value (tracked identifier)',
            sink,
            line: location,
            evidence: `AST flow candidate from untrusted input to ${sink}; review sanitization and validation.`,
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return flows;
}
