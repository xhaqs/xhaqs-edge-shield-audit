const PROMPT_INJECTION_PATTERNS = [
    /ignore previous instructions/i,
    /disregard all prior directives/i,
    /you are now in developer mode/i,
    /reveal system prompt/i,
    /bypass safety filters/i,
];
export function inspectPrompt(promptText) {
    for (const pattern of PROMPT_INJECTION_PATTERNS) {
        if (pattern.test(promptText)) {
            return {
                allowed: false,
                reason: `Detected potential prompt injection matching pattern: ${pattern.source}`,
            };
        }
    }
    return { allowed: true };
}
export function applySecurityHeaders(headers) {
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("X-Frame-Options", "DENY");
    headers.set("X-XSS-Protection", "1; mode=block");
    headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
    headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");
}
