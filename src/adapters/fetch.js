import { scanContent } from '../core/scanner';
export async function handleFetchGuard(request) {
    if (request.method === 'POST' || request.method === 'PUT') {
        const cloned = request.clone();
        const text = await cloned.text();
        const findings = scanContent(text);
        if (findings.length > 0) {
            return new Response(JSON.stringify({
                blocked: true,
                reason: 'Sensitive credentials detected in request payload',
                findings
            }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }
    }
    return null;
}
