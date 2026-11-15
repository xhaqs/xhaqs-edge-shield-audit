export interface AuditFinding {
  ruleId: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  message: string;
  line?: number;
}

export function auditCustomRules(content: string): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const lines = content.split('\n');

  lines.forEach((line, index) => {
    const lineNumber = index + 1;

    // CUSTOM-SECRET-01: Hardcoded internal tokens
    if (/xhaqs_(live|test)_[a-zA-Z0-9]{32}/.test(line)) {
      findings.push({
        ruleId: 'CUSTOM-SECRET-01',
        severity: 'HIGH',
        message: 'Hardcoded internal token detected.',
        line: lineNumber,
      });
    }

    // CUSTOM-DB-01: Hardcoded database connection strings
    if (/(postgres|postgresql|mysql|mongodb|redis):\/\/[^\s"']+/.test(line)) {
      findings.push({
        ruleId: 'CUSTOM-DB-01',
        severity: 'HIGH',
        message: 'Hardcoded database connection string with credentials detected.',
        line: lineNumber,
      });
    }

    // EDGE-SECURITY-02: Unauthenticated KV bindings
    if (/env\.KV/.test(line) && !/auth/.test(line)) {
      findings.push({
        ruleId: 'EDGE-SECURITY-02',
        severity: 'MEDIUM',
        message: 'Unauthenticated Cloudflare KV binding access detected.',
        line: lineNumber,
      });
    }

    // EDGE-SECURITY-03: Unencrypted HTTP fetch requests
    if (/fetch\s*\(['"`].*http:\/\//.test(line)) {
      findings.push({
        ruleId: 'EDGE-SECURITY-03',
        severity: 'HIGH',
        message: 'Unencrypted HTTP fetch request detected.',
        line: lineNumber,
      });
    }

    // EDGE-SECURITY-04: Missing response security headers
    if (/new Response\(/.test(line) && !/X-Content-Type-Options/.test(line)) {
      findings.push({
        ruleId: 'EDGE-SECURITY-04',
        severity: 'LOW',
        message: 'Response missing mandatory X-Content-Type-Options security header.',
        line: lineNumber,
      });
    }
  });

  return findings;
}
