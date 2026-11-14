import { scanContent } from '../core/scanner';

export function edgeShieldExpress() {
  return (req: any, res: any, next: any) => {
    const payload = JSON.stringify({
      body: req.body,
      query: req.query,
      headers: req.headers
    });
    const findings = scanContent(payload);
    if (findings.length > 0) {
      return res.status(403).json({
        blocked: true,
        reason: 'Sensitive credentials detected in request payload',
        findings
      });
    }
    next();
  };
}
