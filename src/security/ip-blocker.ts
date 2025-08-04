const blockedIPs = new Map<string, { reason: string, expiresAt?: number }>();

export function isBlocked(ip: string): boolean {
  const rule = blockedIPs.get(ip);
  if (!rule) return false;
  if (rule.expiresAt && Date.now() > rule.expiresAt) {
    blockedIPs.delete(ip);
    return false;
  }
  return true;
}

export function blockIP(ip: string, reason: string, durationMs?: number) {
  blockedIPs.set(ip, {
    reason,
    expiresAt: durationMs ? Date.now() + durationMs : undefined
  });
}
