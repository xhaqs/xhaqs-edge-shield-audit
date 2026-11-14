#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import { scanForSecrets } from '../src/rules/secrets.ts';

const args = process.argv.slice(2);
const targetPath = args[0];

if (!targetPath) {
  console.log("🛡️ Usage: edge-shield <file-or-directory-path>");
  process.exit(1);
}

const resolvedPath = path.resolve(process.cwd(), targetPath);

if (!fs.existsSync(resolvedPath)) {
  console.error(`❌ Error: Path not found -> ${resolvedPath}`);
  process.exit(1);
}

const stats = fs.statSync(resolvedPath);
let filesToScan = [];

if (stats.isDirectory()) {
  // Simple recursive file finder for local audits
  function walk(dir) {
    const list = fs.readdirSync(dir);
    list.forEach(file => {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      if (stat && stat.isDirectory()) {
        if (!filePath.includes('node_modules') && !filePath.includes('.git')) {
          walk(filePath);
        }
      } else {
        filesToScan.push(filePath);
      }
    });
  }
  walk(resolvedPath);
} else {
  filesToScan.push(resolvedPath);
}

console.log(`\n🔍 Scanning ${filesToScan.length} file(s) for security vulnerabilities...\n`);

let totalFindings = 0;

filesToScan.forEach(file => {
  try {
    const content = fs.readFileSync(file, 'utf8');
    const findings = scanForSecrets(content);
    if (findings.length > 0) {
      console.log(`📁 File: ${path.relative(process.cwd(), file)}`);
      findings.forEach(f => {
        console.log(`   ⚠️  [${f.severity}] Line ${f.line}: ${f.description} (${f.redactedMatch})`);
        totalFindings++;
      });
    }
  } catch (err) {
    // Skip unreadable binary files
  }
});

console.log(`\n✨ Audit complete. Total vulnerabilities found: ${totalFindings}\n`);
