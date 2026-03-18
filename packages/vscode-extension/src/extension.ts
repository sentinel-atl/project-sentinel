import * as vscode from 'vscode';
import { scan } from '@sentinel-atl/scanner';

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand('sentinel.scanPackage', scanPackage),
    vscode.commands.registerCommand('sentinel.scanWorkspace', scanWorkspace),
    vscode.commands.registerCommand('sentinel.validateGatewayConfig', validateConfig),
  );
}

async function scanPackage() {
  const packageName = await vscode.window.showInputBox({
    prompt: 'Enter npm package name to scan',
    placeHolder: 'e.g., @modelcontextprotocol/server-filesystem',
  });

  if (!packageName) return;

  await runScan(packageName);
}

async function scanWorkspace() {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage('No workspace folder open');
    return;
  }

  const pkgPath = vscode.Uri.joinPath(workspaceFolder.uri, 'package.json');
  try {
    const content = await vscode.workspace.fs.readFile(pkgPath);
    const pkg = JSON.parse(Buffer.from(content).toString('utf-8'));
    if (!pkg.name) {
      vscode.window.showErrorMessage('package.json has no name field');
      return;
    }
    await runScan(pkg.name, workspaceFolder.uri.fsPath);
  } catch {
    vscode.window.showErrorMessage('No package.json found in workspace root');
  }
}

async function runScan(packageName: string, packagePath?: string) {
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Scanning ${packageName}...`,
      cancellable: false,
    },
    async () => {
      try {
        const report = await scan({ packageName, packagePath });
        const { overall, grade } = report.trustScore;
        const findings = report.findings || [];

        const critical = findings.filter((f: any) => f.severity === 'critical').length;
        const high = findings.filter((f: any) => f.severity === 'high').length;

        const icon = overall >= 80 ? '✅' : overall >= 60 ? '⚠️' : '❌';
        const message = `${icon} ${packageName}: ${overall}/100 (Grade ${grade}) — ${critical} critical, ${high} high`;

        const action = await vscode.window.showInformationMessage(
          message,
          'View Full Report',
          'Copy Score',
        );

        if (action === 'View Full Report') {
          const doc = await vscode.workspace.openTextDocument({
            content: JSON.stringify(report, null, 2),
            language: 'json',
          });
          await vscode.window.showTextDocument(doc);
        } else if (action === 'Copy Score') {
          await vscode.env.clipboard.writeText(`${overall}/100 (${grade})`);
          vscode.window.showInformationMessage('Trust score copied to clipboard');
        }
      } catch (err: any) {
        vscode.window.showErrorMessage(`Scan failed: ${err.message}`);
      }
    },
  );
}

async function validateConfig() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    // Try to find sentinel.yaml in workspace
    const files = await vscode.workspace.findFiles('**/sentinel.{yaml,yml}', '**/node_modules/**', 1);
    if (files.length === 0) {
      vscode.window.showErrorMessage('No sentinel.yaml found. Open one or create it in your workspace.');
      return;
    }
    const doc = await vscode.workspace.openTextDocument(files[0]);
    await vscode.window.showTextDocument(doc);
    vscode.window.showInformationMessage('Opened sentinel.yaml — run validation again to check it.');
    return;
  }

  const text = editor.document.getText();
  if (!text.includes('gateway:') || !text.includes('servers:')) {
    vscode.window.showWarningMessage('This file does not appear to be a Sentinel gateway config.');
    return;
  }

  // Basic structural validation
  const issues: string[] = [];
  if (!text.includes('port:')) issues.push('Missing gateway.port');
  if (!text.includes('mode:')) issues.push('Missing gateway.mode (strict|permissive)');
  if (!text.includes('upstream:')) issues.push('Missing server upstream URL');

  if (issues.length > 0) {
    vscode.window.showWarningMessage(`Config issues: ${issues.join(', ')}`);
  } else {
    vscode.window.showInformationMessage('✅ Gateway config looks valid');
  }
}

export function deactivate() {}
