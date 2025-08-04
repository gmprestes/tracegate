// src/services/waf.ts
import http from 'http';
import { loadConfig } from '../utils/configLoader';
const config = loadConfig();

export function applyWAFRules(req: http.IncomingMessage): { allowed: boolean; reason?: string } {
  const ip = req.socket.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || '';
  const url = req.url || '';
  const host = req.headers.host || '';

  const routeKey = (req.socket as any).encrypted ? `https://${host}` : `http://${host}`;
  const routeConfig = config.routes?.[routeKey];
  const wafConfig = routeConfig?.waf;

  if (!wafConfig) return { allowed: true };

  const blockedAgents = wafConfig.blockUserAgents || [];
  const blockedIPs = wafConfig.blockIPs || [];
  const blockedPaths = wafConfig.blockPaths || [];
  const mode = wafConfig.mode || 'block'; // 'monitor', 'log-only', 'block'

  let matchReason = '';

  if (blockedIPs.includes(ip)) {
    matchReason = 'Blocked IP';
  } else {
    for (const agent of blockedAgents) {
      if (userAgent.toLowerCase().includes(agent.toLowerCase())) {
        matchReason = 'Blocked User-Agent';
        break;
      }
    }
  }

  if (!matchReason) {
    for (const pattern of blockedPaths) {
      if (url.includes(pattern)) {
        matchReason = 'Blocked Path';
        break;
      }
    }
  }

  if (!matchReason) {
    return { allowed: true };
  }

  if (mode === 'monitor' || mode === 'log-only') {
    return { allowed: true, reason: `[${mode}] ${matchReason}` };
  }

  return { allowed: false, reason: matchReason };
}
