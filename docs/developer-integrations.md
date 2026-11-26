# Developer integrations

## Watch mode

Run a baseline scan and rescan when files change:

```bash
kinga watch .
```

Watch mode uses the platform's recursive filesystem watcher, debounces rapid editor writes and
ignores generated directories such as `.git`, `node_modules`, `dist` and `.kinga`. It performs
the same read-only static scan as `kinga code`; it does not execute project files. Press Ctrl+C
to stop it. If recursive filesystem notifications are unavailable on the platform, use your
editor's task runner to rerun `kinga code .`.

## Git pre-commit hook

The optional hook is provided at `integrations/git-hooks/pre-commit`:

```bash
cp integrations/git-hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

It runs `kinga code . --fail-on high` before each commit. Install Kinga first and ensure it is on
PATH. The hook is opt-in; it does not alter Git configuration or install itself.

## VS Code extension (local development)

The minimal extension at `integrations/vscode` contributes **Kinga: Scan Workspace** and maps
Kinga JSON findings to editor diagnostics.

1. Install Kinga and make sure `kinga` is available on PATH.
2. Open the repository's `integrations/vscode` directory as an extension project.
3. Press F5 in VS Code to launch an Extension Development Host.
4. Run **Kinga: Scan Workspace** from the Command Palette.

The extension invokes the local CLI using argument arrays (not a shell), imposes a two-minute
timeout and displays findings as diagnostics. It does not upload source code. This first version
is a command-triggered integration; automatic on-save scanning, marketplace packaging and richer
code actions are not included yet.
