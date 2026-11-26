/* eslint-disable @typescript-eslint/no-require-imports, no-undef */
const vscode = require('vscode');
const { execFile } = require('node:child_process');

function activate(context) {
  const diagnostics = vscode.languages.createDiagnosticCollection('kinga');
  const output = vscode.window.createOutputChannel('Kinga Security');
  const command = vscode.commands.registerCommand('kinga.scanWorkspace', async () => {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showWarningMessage('Open a workspace folder before running Kinga.');
      return;
    }
    const root = folder.uri.fsPath;
    output.appendLine(`Scanning ${root}`);
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: 'Kinga security scan',
        cancellable: false,
      },
      () =>
        new Promise((resolve) => {
          execFile(
            'kinga',
            ['code', root, '--format', 'json'],
            {
              cwd: root,
              timeout: 120000,
              maxBuffer: 8 * 1024 * 1024,
            },
            (error, stdout, stderr) => {
              if (stderr) output.appendLine(stderr.trim());
              if (error && !stdout) {
                output.appendLine(error.message);
                vscode.window.showErrorMessage(
                  'Kinga scan failed. See the Kinga Security output channel.',
                );
                resolve();
                return;
              }
              try {
                const report = JSON.parse(stdout);
                diagnostics.clear();
                const grouped = new Map();
                for (const finding of report.findings ?? []) {
                  if (!finding.target || !finding.line) continue;
                  const uri = vscode.Uri.joinPath(folder.uri, finding.target);
                  const severity =
                    finding.severity === 'critical' || finding.severity === 'high'
                      ? vscode.DiagnosticSeverity.Error
                      : finding.severity === 'medium'
                        ? vscode.DiagnosticSeverity.Warning
                        : vscode.DiagnosticSeverity.Information;
                  const diagnostic = new vscode.Diagnostic(
                    new vscode.Range(
                      Math.max(0, finding.line - 1),
                      0,
                      Math.max(0, finding.line - 1),
                      1,
                    ),
                    `${finding.title} [${finding.rule}] — ${finding.evidence}`,
                    severity,
                  );
                  diagnostic.source = 'Kinga';
                  diagnostic.code = finding.rule;
                  const list = grouped.get(uri.toString()) ?? { uri, items: [] };
                  list.items.push(diagnostic);
                  grouped.set(uri.toString(), list);
                }
                for (const item of grouped.values()) diagnostics.set(item.uri, item.items);
                output.appendLine(`Completed: ${report.findings?.length ?? 0} finding(s).`);
                vscode.window.showInformationMessage(
                  `Kinga found ${report.findings?.length ?? 0} issue(s).`,
                );
              } catch (parseError) {
                output.appendLine(String(parseError));
                vscode.window.showErrorMessage(
                  'Kinga returned an unreadable report. See output channel.',
                );
              }
              resolve();
            },
          );
        }),
    );
  });
  context.subscriptions.push(command, diagnostics, output);
}

function deactivate() {}

module.exports = { activate, deactivate };
