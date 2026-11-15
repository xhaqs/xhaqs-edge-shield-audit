#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import { auditCustomRules } from '../rules/custom.js';

const targetDir = process.argv[2] || '.';
console.log(`🛡️ Running Edge Shield Audit on: ${targetDir}`);

function walkDir(dir: string, fileList: string[] = []): string[] {
  const files = fs.readdirSync(dir);
  files.forEach(file => {
    const filePath = path.join(dir, file);
    if (file === 'node_modules' || file === '.git' || file === 'dist' || file === 'tests') return;
    if (fs.statSync(filePath).isDirectory()) {
      walkDir(filePath, fileList);
    } else if (
      (filePath.endsWith('.ts') || filePath.endsWith('.js') || filePath.endsWith('.json') || filePath.endsWith('.html')) &&
      !file.endsWith('.test.ts') &&
      !file.endsWith('.test.js') &&
      file !== 'test.js' &&
      !filePath.includes('/rules/')
    ) {
      fileList.push(filePath);
    }
  });
  return fileList;
}

try {
  const absoluteTarget = path.resolve(targetDir);
  const files = fs.statSync(absoluteTarget).isDirectory() ? walkDir(absoluteTarget) : [absoluteTarget];
  
  let totalFindings = 0;
  let blockingFindings = 0;

  files.forEach(file => {
    const content = fs.readFileSync(file, 'utf8');
    const findings = auditCustomRules(content);
    if (findings.length > 0) {
      console.log(`\n📄 File: ${path.relative(absoluteTarget, file)}`);
      findings.forEach((f: any) => {
        totalFindings++;
        if (f.severity === 'HIGH' || f.severity === 'MEDIUM') {
          blockingFindings++;
        }
        console.log(`  [${f.severity}] ${f.ruleId}: ${f.message} (Line ${f.line})`);
      });
    }
  });

  console.log(`\n✨ Audit complete. Scanned ${files.length} files. Total findings: ${totalFindings} (Blocking: ${blockingFindings})`);
  if (blockingFindings > 0) {
    console.log(`❌ Edge Shield Audit failed due to ${blockingFindings} blocking security findings.`);
    process.exit(1);
  }
} catch (error) {
  console.error('❌ Audit failed:', error);
  process.exit(1);
}
