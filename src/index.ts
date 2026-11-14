import { scanForSecrets } from "./rules/secrets";
import { inspectPrompt, applySecurityHeaders } from "./middleware/guard";
import { checkRateLimit } from "./middleware/ratelimit";

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const clientIp = request.headers.get("CF-Connecting-IP") || "127.0.0.1";

    // 1. Apply Edge Rate Limit (20 requests per 60 seconds per IP)
    const rate = checkRateLimit(clientIp, 20, 60);
    if (!rate.allowed) {
      return applySecurityHeaders(
        new Response(
          JSON.stringify({
            error: "Too Many Requests",
            retryAfterSeconds: rate.resetInSeconds,
          }),
          { status: 429, headers: { "Content-Type": "application/json" } }
        )
      );
    }

    // 2. Endpoint: POST /scan (Audit code for exposed secrets)
    if (request.method === "POST" && url.pathname === "/scan") {
      const body = (await request.json()) as { code?: string };
      const findings = scanForSecrets(body.code || "");
      return applySecurityHeaders(
        new Response(JSON.stringify({ status: "audited", findings }), {
          headers: { "Content-Type": "application/json" },
        })
      );
    }

    // 3. Endpoint: POST /guard-ai (Check prompts for injection attacks)
    if (request.method === "POST" && url.pathname === "/guard-ai") {
      const body = (await request.json()) as { prompt?: string };
      const check = inspectPrompt(body.prompt || "");
      const status = check.allowed ? 200 : 403;
      return applySecurityHeaders(
        new Response(JSON.stringify(check), {
          status,
          headers: { "Content-Type": "application/json" },
        })
      );
    }

    return applySecurityHeaders(
      new Response(
        JSON.stringify({
          service: "xhaqs-edge-shield-audit",
          endpoints: ["POST /scan", "POST /guard-ai"],
          rateLimitRemaining: rate.remaining,
        }),
        { headers: { "Content-Type": "application/json" } }
      )
    );
  },
};
