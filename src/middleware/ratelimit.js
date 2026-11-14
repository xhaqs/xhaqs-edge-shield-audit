// In-memory store for lightweight isolate-level protection
const ipTracker = new Map();
export function checkRateLimit(clientIp, maxRequests = 20, windowSeconds = 60) {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    const record = ipTracker.get(clientIp);
    // First request or expired window
    if (!record || now > record.resetAt) {
        ipTracker.set(clientIp, { count: 1, resetAt: now + windowMs });
        return {
            allowed: true,
            remaining: maxRequests - 1,
            resetInSeconds: windowSeconds,
        };
    }
    // Exceeded limit
    if (record.count >= maxRequests) {
        return {
            allowed: false,
            remaining: 0,
            resetInSeconds: Math.ceil((record.resetAt - now) / 1000),
        };
    }
    // Increment valid request
    record.count += 1;
    return {
        allowed: true,
        remaining: maxRequests - record.count,
        resetInSeconds: Math.ceil((record.resetAt - now) / 1000),
    };
}
