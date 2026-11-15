import test from 'node:test';
import assert from 'node:assert';
import { auditCustomRules } from '../rules/custom.js';

test('detects hardcoded internal tokens (CUSTOM-SECRET-01)', () => {
  const code = 'const apiKey = "xhaqs_live_1234567890abcdef1234567890abcdef";';
  const findings = auditCustomRules(code);
  assert.strictEqual(findings.length, 1);
  assert.strictEqual(findings[0].ruleId, 'CUSTOM-SECRET-01');
});

test('detects hardcoded database connection strings (CUSTOM-DB-01)', () => {
  const code = 'const DATABASE_URL = "postgresql://user:pass@localhost:5432/db";';
  const findings = auditCustomRules(code);
  const dbFinding = findings.find(f => f.ruleId === 'CUSTOM-DB-01');
  assert.ok(dbFinding, 'Should detect database connection string');
  assert.strictEqual(dbFinding?.severity, 'HIGH');
});

test('detects unauthenticated KV bindings (EDGE-SECURITY-02)', () => {
  const code = 'const val = await env.KV.get("key");';
  const findings = auditCustomRules(code);
  assert.ok(findings.some(f => f.ruleId === 'EDGE-SECURITY-02'));
});

test('detects unencrypted HTTP fetch requests (EDGE-SECURITY-03)', () => {
  const code = 'await fetch("http://api.example.com/data");';
  const findings = auditCustomRules(code);
  assert.ok(findings.some(f => f.ruleId === 'EDGE-SECURITY-03'));
});

test('detects missing security headers in responses (EDGE-SECURITY-04)', () => {
  const code = 'return new Response("Hello");';
  const findings = auditCustomRules(code);
  assert.ok(findings.some(f => f.ruleId === 'EDGE-SECURITY-04'));
});
