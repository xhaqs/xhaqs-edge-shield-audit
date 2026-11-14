export interface Finding {
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  line: number;
  redactedMatch: string;
}

export function scanContent(content: string): Finding[] {
  const lines = content.split('\n');
  const findings: Finding[] = [];

  const rules = [
    {
      id: 'SEC-001',
      severity: 'CRITICAL' as const,
      desc: 'Exposed OpenAI API Key',
      regex: /sk-[a-zA-Z0-9-_]{20,}/g
    },
    {
      id: 'SEC-002',
      severity: 'CRITICAL' as const,
      desc: 'Exposed AWS Access Key ID',
      regex: /AKIA[0-9A-Z]{16}/g
    },
    {
      id: 'SEC-003',
      severity: 'CRITICAL' as const,
      desc: 'Exposed Stripe Live Secret Key',
      regex: /sk_live_[0-9a-zA-Z]{24,}/g
    },
    {
      id: 'SEC-004',
      severity: 'HIGH' as const,
      desc: 'Exposed GitHub Personal Access Token',
      regex: /ghp_[0-9a-zA-Z]{36}/g
    },
    {
      id: 'SEC-005',
      severity: 'HIGH' as const,
      desc: 'Exposed Google / Firebase API Key',
      regex: /AIza[0-9A-Za-z-_]{35}/g
    },
    {
      id: 'SEC-006',
      severity: 'CRITICAL' as const,
      desc: 'Exposed Database Connection String',
      regex: /(postgres|mongodb(?:\+srv)?|mysql):\/\/[^\s]+:[^\s]+@[^\s]+/g
    }
  ];

  lines.forEach((line, index) => {
    rules.forEach(rule => {
      let match;
      while ((match = rule.regex.exec(line)) !== null) {
        const fullMatch = match[0];
        const redacted = fullMatch.length > 10 
          ? fullMatch.substring(0, 6) + '...' + fullMatch.substring(fullMatch.length - 4)
          : 'REDACTED';

        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          description: rule.desc,
          line: index + 1,
          redactedMatch: redacted
        });
      }
    });
  });

  return findings;
}
