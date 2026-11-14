export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetInSeconds: number;
}

// In-memory store for lightweight isolate-level protection
const ipTracker = new Map<string, { count: number; resetAt: number }>();

export function checkRateLimit(
  clientIp: string,
  maxRequests: number = 20,
  windowSeconds: number = 60
): RateLimitResult {
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
