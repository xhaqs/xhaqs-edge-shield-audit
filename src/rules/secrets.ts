export interface SecretFinding {
  ruleId: string;
  severity: "CRITICAL" | "HIGH";
  description: string;
  line: number;
  redactedMatch: string;
}

interface SecretRule {
  id: string;
  severity: "CRITICAL" | "HIGH";
  description: string;
  pattern: RegExp;
}

const SECRET_RULES: SecretRule[] = [
  {
    id: "SEC-001",
    severity: "CRITICAL",
    description: "Exposed OpenAI API Key",
    pattern: /sk-(?:proj-)?[a-zA-Z0-9_-]{32,}/g,
  },
  {
    id: "SEC-002",
    severity: "CRITICAL",
    description: "Exposed Anthropic API Key",
    pattern: /sk-ant-api03-[a-zA-Z0-9_-]{80,}/g,
  },
  {
    id: "SEC-003",
    severity: "CRITICAL",
    description: "Exposed GitHub Personal Access Token",
    pattern: /(?:ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/g,
  },
  {
    id: "SEC-004",
    severity: "HIGH",
    description: "Hardcoded Supabase / JWT Service Key",
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
  },
  {
    id: "SEC-005",
    severity: "CRITICAL",
    description: "Exposed AWS Access Key ID",
    pattern: /AKIA[0-9A-Z]{16}/g,
  },
  {
    id: "SEC-006",
    severity: "HIGH",
    description: "Generic Hardcoded Secret Assignment",
    pattern: /(?:api_key|secret_key|private_key|auth_token)\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}["']/gi,
  },
];

function redactSecret(raw: string): string {
  if (raw.length <= 10) return "***REDACTED***";
  return `${raw.slice(0, 6)}...${raw.slice(-4)}`;
}

export function scanForSecrets(sourceCode: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = sourceCode.split("\n");

  lines.forEach((lineContent, index) => {
    for (const rule of SECRET_RULES) {
      // Reset regex state for global patterns
      rule.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = rule.pattern.exec(lineContent)) !== null) {
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          description: rule.description,
          line: index + 1,
          redactedMatch: redactSecret(match[0]),
        });
      }
    }
  });

  return findings;
}
