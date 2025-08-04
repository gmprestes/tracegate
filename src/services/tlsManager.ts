// src/services/tlsManager.ts
import fs from 'fs';
import path from 'path';
import tls from 'tls';
import { LRUCache } from 'lru-cache';
import { TLSConfig } from '../types/config';

const certCache = new LRUCache<string, tls.SecureContext>({
  max: 100,
  ttl: 1000 * 60 * 60 // 1 hour
});

/**
 * Resolve the cache key uniquely for each cert.
 */
function getCacheKey(domain: string, certPath: string, keyPath: string) {
  return `${domain}:${certPath}:${keyPath}`;
}

/**
 * Returns a cached TLS SecureContext or loads it from disk based on domain config.
 */
export async function getCachedSecureContext(domain: string, tlsConfig: TLSConfig): Promise<tls.SecureContext> {
  const key = getCacheKey(domain, tlsConfig.certPath, tlsConfig.keyPath);

  if (certCache.has(key)) {
    return certCache.get(key)!;
  }

  try {
    const cert = fs.readFileSync(path.resolve(tlsConfig.certPath), 'utf8');
    const privkey = fs.readFileSync(path.resolve(tlsConfig.keyPath), 'utf8');
    const context = tls.createSecureContext({ cert, key: privkey });

    console.log(`Loaded TLS context for ${domain} from disk`);

    //certCache.set(key, context);
    return context;
  } catch (err) {
    throw new Error(`Failed to load certificate for ${domain}: ${(err as Error).message}`);
  }
}