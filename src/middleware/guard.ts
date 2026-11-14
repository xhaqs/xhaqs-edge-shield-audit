export interface GuardResult {
  allowed: boolean;
  reason?: string;
  threatLevel?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export function inspectPrompt(prompt: string): GuardResult {
  const lower = prompt.toLowerCase();
  const injectionPatterns = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "reveal system prompt",
    "system prompt",
    "bypass guardrails",
    "you are now unrestricted"
  ];

  for (const pattern of injectionPatterns) {
    if (lower.includes(pattern)) {
      return {
        allowed: false,
        reason: "Prompt injection pattern detected",
        threatLevel: "HIGH"
      };
    }
  }

  return {
    allowed: true
  };
}

export function applySecurityHeaders(response: Response): Response {
  const newHeaders = new Headers(response.headers);
  newHeaders.set("X-Content-Type-Options", "nosniff");
  newHeaders.set("X-Frame-Options", "DENY");
  newHeaders.set("X-XSS-Protection", "1; mode=block");
  newHeaders.set("Referrer-Policy", "strict-origin-when-cross-origin");
  newHeaders.set("Content-Security-Policy", "default-src 'self'");
  
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: newHeaders
  });
}
