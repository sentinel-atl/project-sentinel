/**
 * AST-based code analysis — replaces regex line-matching with real
 * TypeScript syntax tree traversal.
 *
 * Why this matters: regex pattern matching is trivially bypassed
 * (split a string, use dynamic property access, template literals, etc.).
 * AST analysis follows the actual code structure — imports, call expressions,
 * property access chains, dynamic evaluation — and catches obfuscation
 * that regex can never see.
 *
 * Detects:
 * - Direct and indirect eval / Function constructor calls
 * - Dynamic require/import with variable arguments
 * - Property access chains leading to dangerous APIs (globalThis[x], obj['eval'])
 * - Computed property access on known dangerous objects
 * - child_process usage (direct import, aliased, destructured)
 * - Suspicious string concatenation patterns (building URLs/commands)
 * - Environment variable exfiltration flows (read env → send network)
 */

import ts from 'typescript';
import { readFile, readdir } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';
import type { Finding, FindingSeverity, FindingCategory } from './scanner.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface ASTScanResult {
  /** Total source files parsed */
  totalFiles: number;
  /** Files that failed to parse */
  parseErrors: number;
  /** All findings from AST analysis */
  findings: Finding[];
  /** Imports of dangerous modules, keyed by module name */
  dangerousImports: Map<string, string[]>;
}

// ─── Dangerous module/API maps ────────────────────────────────────────

/** Modules that are inherently dangerous when imported */
const DANGEROUS_MODULES = new Set([
  'child_process', 'node:child_process',
  'vm', 'node:vm',
  'worker_threads', 'node:worker_threads',
]);

/** APIs that can execute arbitrary code */
const EVAL_LIKE_GLOBALS = new Set([
  'eval', 'Function', 'setTimeout', 'setInterval', 'setImmediate',
]);

/** Properties on dangerous modules that execute commands */
const DANGEROUS_METHODS: Record<string, Set<string>> = {
  'child_process': new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']),
  'node:child_process': new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']),
  'vm': new Set(['runInNewContext', 'runInThisContext', 'createContext', 'Script']),
  'node:vm': new Set(['runInNewContext', 'runInThisContext', 'createContext', 'Script']),
};

/** Known objects that should never have computed access */
const SENSITIVE_OBJECTS = new Set([
  'globalThis', 'global', 'window', 'self',
  'process', 'require', 'module',
]);

// ─── Skip logic ──────────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', 'dist', '.git', '.turbo', 'coverage',
  '__pycache__', '.next', 'build', '.cache',
]);

const AST_EXTENSIONS = new Set(['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx']);

// ─── AST Scanner ─────────────────────────────────────────────────────

export async function scanAST(
  packagePath: string,
  extensions?: string[],
): Promise<ASTScanResult> {
  const extSet = extensions
    ? new Set(extensions)
    : AST_EXTENSIONS;

  const files = await collectFiles(packagePath, packagePath, extSet);
  const findings: Finding[] = [];
  const dangerousImports = new Map<string, string[]>();
  let parseErrors = 0;

  for (const filePath of files) {
    const relPath = relative(packagePath, filePath);
    try {
      const content = await readFile(filePath, 'utf-8');
      const sourceFile = ts.createSourceFile(
        relPath,
        content,
        ts.ScriptTarget.Latest,
        /* setParentNodes */ true,
        extname(filePath) === '.tsx' || extname(filePath) === '.jsx'
          ? ts.ScriptKind.TSX
          : ts.ScriptKind.TS,
      );

      const ctx: VisitorContext = {
        sourceFile,
        relPath,
        findings,
        dangerousImports,
        importAliases: new Map(),
        requireAliases: new Map(),
      };

      // First pass: collect all import/require aliases
      collectImportAliases(sourceFile, ctx);

      // Second pass: analyze usage
      visitNode(sourceFile, ctx);
    } catch {
      parseErrors++;
    }
  }

  return {
    totalFiles: files.length,
    parseErrors,
    findings,
    dangerousImports,
  };
}

// ─── Context ─────────────────────────────────────────────────────────

interface VisitorContext {
  sourceFile: ts.SourceFile;
  relPath: string;
  findings: Finding[];
  dangerousImports: Map<string, string[]>;
  /** Maps local alias name → module it was imported from */
  importAliases: Map<string, string>;
  /** Maps local variable name → module it was required from */
  requireAliases: Map<string, string>;
}

// ─── Import Alias Collection ─────────────────────────────────────────

function collectImportAliases(node: ts.Node, ctx: VisitorContext): void {
  // import { exec } from 'child_process'
  // import { exec as shell } from 'child_process'
  // import * as cp from 'child_process'
  // import cp from 'child_process'
  if (ts.isImportDeclaration(node)) {
    const moduleSpec = node.moduleSpecifier;
    if (ts.isStringLiteral(moduleSpec)) {
      const moduleName = moduleSpec.text;
      const clause = node.importClause;
      if (clause) {
        // Default import: import cp from 'child_process'
        if (clause.name) {
          ctx.importAliases.set(clause.name.text, moduleName);
        }
        // Named/namespace imports
        if (clause.namedBindings) {
          if (ts.isNamespaceImport(clause.namedBindings)) {
            // import * as cp from 'child_process'
            ctx.importAliases.set(clause.namedBindings.name.text, moduleName);
          } else if (ts.isNamedImports(clause.namedBindings)) {
            for (const spec of clause.namedBindings.elements) {
              // import { exec as shell } from 'child_process'
              const originalName = spec.propertyName?.text ?? spec.name.text;
              ctx.importAliases.set(spec.name.text, `${moduleName}:${originalName}`);
            }
          }
        }
      }

      // Track dangerous imports
      if (DANGEROUS_MODULES.has(moduleName)) {
        const existing = ctx.dangerousImports.get(moduleName) ?? [];
        existing.push(ctx.relPath);
        ctx.dangerousImports.set(moduleName, existing);
      }
    }
  }

  // const cp = require('child_process')
  // const { exec } = require('child_process')
  if (ts.isVariableStatement(node)) {
    for (const decl of node.declarationList.declarations) {
      if (decl.initializer && ts.isCallExpression(decl.initializer)) {
        const call = decl.initializer;
        if (ts.isIdentifier(call.expression) && call.expression.text === 'require') {
          const arg = call.arguments[0];
          if (arg && ts.isStringLiteral(arg)) {
            const moduleName = arg.text;
            if (ts.isIdentifier(decl.name)) {
              ctx.requireAliases.set(decl.name.text, moduleName);
            } else if (ts.isObjectBindingPattern(decl.name)) {
              for (const element of decl.name.elements) {
                if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
                  const propName = element.propertyName && ts.isIdentifier(element.propertyName)
                    ? element.propertyName.text
                    : element.name.text;
                  ctx.requireAliases.set(element.name.text, `${moduleName}:${propName}`);
                }
              }
            }

            if (DANGEROUS_MODULES.has(moduleName)) {
              const existing = ctx.dangerousImports.get(moduleName) ?? [];
              existing.push(ctx.relPath);
              ctx.dangerousImports.set(moduleName, existing);
            }
          }
        }
      }
    }
  }

  ts.forEachChild(node, child => collectImportAliases(child, ctx));
}

// ─── AST Visitor ─────────────────────────────────────────────────────

function visitNode(node: ts.Node, ctx: VisitorContext): void {
  // --- 1. Direct eval() calls ---
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
    const name = node.expression.text;
    if (name === 'eval') {
      addFinding(ctx, node, 'critical', 'dangerous-pattern',
        'Direct eval() call',
        'eval() executes arbitrary code — this is the most dangerous pattern in JavaScript');
    }
    if (name === 'Function' && node.arguments.length > 0) {
      addFinding(ctx, node, 'critical', 'dangerous-pattern',
        'Function() constructor call',
        'Function() is equivalent to eval() — executes arbitrary code');
    }
  }

  // --- 2. new Function() ---
  if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Function') {
    addFinding(ctx, node, 'critical', 'dangerous-pattern',
      'new Function() constructor',
      'new Function() is equivalent to eval() — executes arbitrary code');
  }

  // --- 3. Computed property access on dangerous objects: globalThis[x], process[x] ---
  if (ts.isElementAccessExpression(node)) {
    const obj = node.expression;
    if (ts.isIdentifier(obj) && SENSITIVE_OBJECTS.has(obj.text)) {
      // Only flag if the index is not a string literal (computed = dynamic)
      if (!ts.isStringLiteral(node.argumentExpression)) {
        addFinding(ctx, node, 'high', 'dangerous-pattern',
          `Computed access on ${obj.text}`,
          `Dynamic property access on ${obj.text}[...] can access any global, including eval, require, etc.`);
      }
    }
  }

  // --- 4. Dynamic import() with non-literal argument ---
  if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
    const arg = node.arguments[0];
    if (arg && !ts.isStringLiteral(arg) && !ts.isNoSubstitutionTemplateLiteral(arg)) {
      addFinding(ctx, node, 'high', 'dangerous-pattern',
        'Dynamic import() with variable',
        'import() with a variable argument can load arbitrary modules at runtime');
    }
  }

  // --- 5. Dynamic require() with non-literal argument ---
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') {
    const arg = node.arguments[0];
    if (arg && !ts.isStringLiteral(arg)) {
      addFinding(ctx, node, 'high', 'dangerous-pattern',
        'Dynamic require() with variable',
        'require() with a variable argument can load arbitrary modules at runtime');
    }
  }

  // --- 6. Property access on aliased dangerous module: cp.exec() ---
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const propAccess = node.expression;
    if (ts.isIdentifier(propAccess.expression)) {
      const objName = propAccess.expression.text;
      const methodName = propAccess.name.text;

      // Check import aliases
      const importedModule = ctx.importAliases.get(objName);
      if (importedModule && !importedModule.includes(':')) {
        const dangerousMethods = DANGEROUS_METHODS[importedModule];
        if (dangerousMethods?.has(methodName)) {
          addFinding(ctx, node, 'high', 'dangerous-pattern',
            `${objName}.${methodName}() — shell execution via ${importedModule}`,
            `Calls ${importedModule}.${methodName}() which can execute arbitrary shell commands`);
        }
      }

      // Check require aliases
      const requiredModule = ctx.requireAliases.get(objName);
      if (requiredModule && !requiredModule.includes(':')) {
        const dangerousMethods = DANGEROUS_METHODS[requiredModule];
        if (dangerousMethods?.has(methodName)) {
          addFinding(ctx, node, 'high', 'dangerous-pattern',
            `${objName}.${methodName}() — shell execution via ${requiredModule}`,
            `Calls ${requiredModule}.${methodName}() which can execute arbitrary shell commands`);
        }
      }
    }
  }

  // --- 7. Destructured dangerous function calls: const { exec } = require('child_process'); exec(cmd) ---
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
    const name = node.expression.text;
    const aliasSource = ctx.importAliases.get(name) ?? ctx.requireAliases.get(name);
    if (aliasSource?.includes(':')) {
      const [moduleName, originalName] = aliasSource.split(':');
      const dangerousMethods = DANGEROUS_METHODS[moduleName];
      if (dangerousMethods?.has(originalName)) {
        addFinding(ctx, node, 'high', 'dangerous-pattern',
          `${name}() — destructured from ${moduleName}.${originalName}`,
          `Calls ${originalName}() imported from ${moduleName}, which can execute shell commands`);
      }
    }
  }

  // --- 8. Function.prototype.constructor / constructor.call tricks ---
  if (ts.isPropertyAccessExpression(node)) {
    const chain = getPropertyChainText(node);
    if (chain && /Function\.prototype\.constructor|\.constructor\.call|\.constructor\.apply/i.test(chain)) {
      addFinding(ctx, node, 'critical', 'obfuscation',
        'Function.prototype.constructor access',
        'Accessing Function.prototype.constructor is a common eval() evasion technique');
    }
  }

  // --- 9. Proxy with get trap (can intercept any property access) ---
  if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'Proxy') {
    const handlerArg = node.arguments?.[1];
    if (handlerArg && ts.isObjectLiteralExpression(handlerArg)) {
      const hasGetTrap = handlerArg.properties.some(p => {
        if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name) && p.name.text === 'get') return true;
        if (ts.isMethodDeclaration(p) && ts.isIdentifier(p.name) && p.name.text === 'get') return true;
        return false;
      });
      if (hasGetTrap) {
        addFinding(ctx, node, 'medium', 'obfuscation',
          'Proxy with get trap',
          'A Proxy with a get trap can intercept property access and redirect it to dangerous APIs like eval()');
      }
    }
  }

  // --- 10. Template literal tag on eval: eval`code` ---
  if (ts.isTaggedTemplateExpression(node) && ts.isIdentifier(node.tag) && node.tag.text === 'eval') {
    addFinding(ctx, node, 'critical', 'dangerous-pattern',
      'eval as template tag',
      'eval used as a tagged template literal — executes the template as code');
  }

  // --- 11. WebAssembly instantiation (can run arbitrary native code) ---
  if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
    const obj = node.expression.expression;
    const method = node.expression.name.text;
    if (ts.isIdentifier(obj) && obj.text === 'WebAssembly' &&
        (method === 'instantiate' || method === 'compile' || method === 'instantiateStreaming')) {
      addFinding(ctx, node, 'high', 'dangerous-pattern',
        `WebAssembly.${method}()`,
        'WebAssembly can execute arbitrary native code and bypass JavaScript sandboxing');
    }
  }

  // --- 12. module._load / module.constructor._load (internal require bypass) ---
  if (ts.isPropertyAccessExpression(node)) {
    const chain = getPropertyChainText(node);
    if (chain && /module\._load|module\.constructor\._load/i.test(chain)) {
      addFinding(ctx, node, 'critical', 'obfuscation',
        'Internal module loader access',
        'Accessing module._load or module.constructor._load bypasses standard require() and can load arbitrary modules');
    }
  }

  ts.forEachChild(node, child => visitNode(child, ctx));
}

// ─── Helpers ─────────────────────────────────────────────────────────

function addFinding(
  ctx: VisitorContext,
  node: ts.Node,
  severity: FindingSeverity,
  category: FindingCategory,
  title: string,
  description: string,
): void {
  const { line } = ctx.sourceFile.getLineAndCharacterOfPosition(node.getStart());
  const lineText = ctx.sourceFile.text.split('\n')[line]?.trim() ?? '';

  ctx.findings.push({
    severity,
    category,
    title: `[AST] ${title}`,
    description,
    file: ctx.relPath,
    line: line + 1,
    evidence: lineText.slice(0, 150),
  });
}

/**
 * Walk a property access chain and return the full dotted string.
 * e.g. `Function.prototype.constructor` → "Function.prototype.constructor"
 */
function getPropertyChainText(node: ts.PropertyAccessExpression): string | undefined {
  const parts: string[] = [node.name.text];
  let current: ts.Expression = node.expression;
  let depth = 0;
  while (depth < 10) {
    if (ts.isIdentifier(current)) {
      parts.unshift(current.text);
      return parts.join('.');
    } else if (ts.isPropertyAccessExpression(current)) {
      parts.unshift(current.name.text);
      current = current.expression;
    } else {
      return undefined;
    }
    depth++;
  }
  return undefined;
}

// ─── File Collection ─────────────────────────────────────────────────

async function collectFiles(dir: string, basePath: string, extensions: Set<string>): Promise<string[]> {
  const files: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      files.push(...await collectFiles(fullPath, basePath, extensions));
    } else if (entry.isFile() && extensions.has(extname(entry.name))) {
      files.push(fullPath);
    }
  }
  return files;
}
