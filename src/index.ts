import { scanForSecrets } from "./rules/secrets";
import { inspectPrompt, applySecurityHeaders } from "./middleware/guard";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const responseHeaders = new Headers();
    applySecurityHeaders(responseHeaders);

    // Handle CORS preflight if needed
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: responseHeaders });
    }

    try {
      // Endpoint 1: Static Code & Secret Audit Scanner
      if (url.pathname === "/scan" && request.method === "POST") {
        const body = await request.text();
        if (!body) {
          return new Response(JSON.stringify({ error: "Empty request body provided" }), {
            status: 400,
            headers: { ...Object.fromEntries(responseHeaders), "Content-Type": "application/json" },
          });
        }

        const findings = scanForSecrets(body);
        const report = {
          timestamp: new Date().toISOString(),
          totalFindings: findings.length,
          status: findings.length > 0 ? "VULNERABLE" : "SECURE",
          findings,
        };

        return new Response(JSON.stringify(report, null, 2), {
          status: 200,
          headers: { ...Object.fromEntries(responseHeaders), "Content-Type": "application/json" },
        });
      }

      // Endpoint 2: AI Prompt Injection Guardrail
      if (url.pathname === "/guard-ai" && request.method === "POST") {
        const data = (await request.json()) as { prompt?: string };
        if (!data || !data.prompt) {
          return new Response(JSON.stringify({ error: "Missing 'prompt' field in JSON body" }), {
            status: 400,
            headers: { ...Object.fromEntries(responseHeaders), "Content-Type": "application/json" },
          });
        }

        const guardCheck = inspectPrompt(data.prompt);
        if (!guardCheck.allowed) {
          return new Response(
            JSON.stringify({
              error: "Blocked by Edge Guardrail",
              reason: guardCheck.reason,
            }),
            {
              status: 403,
              headers: { ...Object.fromEntries(responseHeaders), "Content-Type": "application/json" },
            }
          );
        }

        return new Response(
          JSON.stringify({
            status: "PASSED",
            message: "Prompt is safe to forward to LLM backend.",
          }),
          {
            status: 200,
            headers: { ...Object.fromEntries(responseHeaders), "Content-Type": "application/json" },
          }
        );
      }

      // Default Health Check
      return new Response(
        JSON.stringify({
          service: "Edge Shield Audit & Guardrail API",
          version: "1.0.0",
          endpoints: ["POST /scan", "POST /guard-ai"],
        }),
        {
          status: 200,
          headers: { ...Object.fromEntries(responseHeaders), "Content-Type": "application/json" },
        }
      );
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message || "Internal Server Error" }), {
        status: 500,
        headers: { ...Object.fromEntries(responseHeaders), "Content-Type": "application/json" },
      });
    }
  },
};
