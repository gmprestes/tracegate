// src/core/balancer.ts
import http2, { ClientSessionOptions, SecureClientSessionOptions, ClientHttp2Session } from 'http2';
import http from 'http';
import https from 'https';
import httpProxy from 'http-proxy';
import tls from 'tls';
import { getCachedSecureContext } from '../services/tlsManager';
import { logger, createTraceId } from '../services/logger';
import { loadConfig } from '../utils/configLoader';
import { applyWAFRules } from '../services/waf';
import { ServerResponse, IncomingMessage } from 'http';
import fs from 'fs';
import { LRUCache } from 'lru-cache';
import { Readable, PassThrough } from 'stream';

const CLIENT_HTTP2_TIMEOUT_MS = 0; // 1min para HTTP/2 (evita hangs infinitos)
const DEFAULT_TIMEOUT_MS = 15000;     // Padrão para HTTP/1

const config = loadConfig();
validateRouteTargets(config.routes);
const proxy = httpProxy.createProxyServer({});
const routes = config.routes;

const keepAliveHttpAgent = new http.Agent({ keepAlive: true });
const keepAliveHttpsAgent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });

const backendHttp2Support = new LRUCache<string, boolean>({ max: 100, ttl: 600_000 });
const backendSessions = new Map<string, ClientHttp2Session>();

// Improvement: Make probe timeout configurable; handle auth if needed in future.
async function isHttp2Backend(target: string): Promise<boolean> {
  if (backendHttp2Support.has(target)) return backendHttp2Support.get(target)!;

  return new Promise((resolve) => {
    const client = http2.connect(target, { rejectUnauthorized: false });
    const timeout = setTimeout(() => {
      client.destroy();
      backendHttp2Support.set(target, false);
      resolve(false);
    }, 1500);

    client.on('error', () => {
      clearTimeout(timeout);
      client.close();
      backendHttp2Support.set(target, false);
      resolve(false);
    });

    client.on('connect', () => {
      const req = client.request({ ':method': 'HEAD', ':path': '/' });
      req.on('response', () => {
        clearTimeout(timeout);
        req.close();
        client.close();
        backendHttp2Support.set(target, true);
        resolve(true);
      });
      req.on('error', () => {
        clearTimeout(timeout);
        req.close();
        client.close();
        backendHttp2Support.set(target, false);
        resolve(false);
      });
    });
  });
}

// Improvement: Explicitly set timeout to 0; add idle check (optional: setInterval to close if session.pending + session.active === 0).
function getOrCreateSession(target: string): ClientHttp2Session {
  let session = backendSessions.get(target);
  if (session && !session.closed && !session.destroyed) {
    return session;
  }

  const isHttps = target.startsWith('https');
  let options: ClientSessionOptions | SecureClientSessionOptions = { settings: { enablePush: false } }; // Disable push by default.
  if (isHttps) {
    options = { ...options, rejectUnauthorized: false } as SecureClientSessionOptions;
  }

  session = http2.connect(target, options);
  session.setTimeout(0); // Fix: Disable idle timeout to prevent premature closes.

  session.on('close', () => backendSessions.delete(target));

  session.on('error', (err) => {
    logger.warn({ msg: 'HTTP/2 backend session error', target, error: err.message });
    backendSessions.delete(target);
    session.destroy();
  });

  session.on('goaway', (code) => {
    logger.warn({ msg: 'Received GOAWAY', code, target });
    backendSessions.delete(target);
    session.destroy();
  });

  session.on('frameError', (type, code, id) => {
    logger.warn({ msg: 'Frame error from backend', type, code, id });
  });

  backendSessions.set(target, session);
  return session;
}

function filterHttp2Headers(headers: http.IncomingHttpHeaders): http2.OutgoingHttpHeaders {
  const out: http2.OutgoingHttpHeaders = {};
  for (const key in headers) {
    if (!key.startsWith(':') && key.toLowerCase() !== 'connection') {
      out[key.toLowerCase()] = headers[key] as string;
    }
  }
  return out;
}

function convertHttp2ToHttp1Headers(h2Headers: http2.IncomingHttpHeaders): http.IncomingHttpHeaders {
  const h1Headers: http.IncomingHttpHeaders = {};
  const validToken = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

  for (const [key, value] of Object.entries(h2Headers)) {
    if (key.startsWith(':') || !validToken.test(key)) continue;
    const lowerKey = key.toLowerCase();
    if (['connection', 'upgrade', 'keep-alive',].includes(lowerKey)) continue;
    if (value !== undefined) {
      h1Headers[lowerKey] = Array.isArray(value) ? value.join(',') : value.toString(); // Improvement: Explicit toString for safety.
    }
  }

  // 'transfer-encoding'

  if (!h1Headers['host'] && h2Headers[':authority']) {
    h1Headers['host'] = h2Headers[':authority'] as string;
  }

  return h1Headers;
}

// Improvement: Use a Duplex stream mock if needed; ensure no real socket attachment.
function cloneHttp2ToHttp1Request(h2req: http2.Http2ServerRequest, headers: http.IncomingHttpHeaders): IncomingMessage {
  const clonedReq = new PassThrough() as PassThrough & IncomingMessage;
  clonedReq.headers = headers;
  clonedReq.method = h2req.method;
  clonedReq.url = h2req.url;
  clonedReq.httpVersion = '1.1';
  clonedReq.connection = { remoteAddress: h2req.stream?.session?.socket?.remoteAddress || 'unknown' } as any;

  h2req.pipe(clonedReq); // Pipe data from h2req into clonedReq

  // Optional: Propagate errors between streams for robustness
  h2req.on('error', (err) => clonedReq.destroy(err));
  clonedReq.on('error', (err) => h2req.destroy(err));

  return clonedReq;
}

function extractSchemeAndHost(headers: http2.IncomingHttpHeaders | http.IncomingHttpHeaders, socket: any) {
  const hostHeader = headers[':authority'] || headers['host'] || '';
  const isEncrypted = !!socket?.encrypted;
  const scheme: 'http' | 'https' = isEncrypted ? 'https' : 'http';
  const remoteAddr = socket?.remoteAddress || 'unknown';
  return { scheme, host: hostHeader.toString(), remoteAddr };
}

function getRoute(scheme: 'http' | 'https', host: string) {
  return routes[`${scheme}://${host}`];
}

function validateRouteTargets(routes: Record<string, any>) {
  const urlRegex = /^(http|https):\/\//;
  for (const domain in routes) {
    const route = routes[domain];
    if (!urlRegex.test(route.target)) {
      logger.warn({ msg: 'Invalid target URL in route config', domain, target: route.target });
    }
    if (route.tls?.enabled) {
      const certExists = fs.existsSync(route.tls.certPath);
      const keyExists = fs.existsSync(route.tls.keyPath);
      if (!certExists || !keyExists) {
        logger.warn({ msg: 'TLS certificate or key missing', domain });
      }
    }
  }
}

proxy.on('error', async (err, req, res) => {
  const traceId = (req as any).traceId || 'unknown';
  const host = req.headers.host || 'unknown';
  const url = req.url || 'unknown';
  await logger.warn({ traceId, msg: 'Proxy target connection failed', host, url, error: err.message });
  if (res instanceof ServerResponse && !res.headersSent) {
    res.setHeader('X-TGate-Trace-Id', traceId);
    res.writeHead(502);
    res.end();
  }
});

proxy.on('proxyReq', (proxyReq, req) => {
  const traceId = (req as any).traceId || 'unknown';
  proxyReq.setHeader('X-TGate-Trace-Id', traceId);
  proxyReq.setHeader('Server', 'TraceGate');
  (req as any)._startAt = process.hrtime();
});

proxy.on('proxyRes', async (proxyRes, req, res) => {
  const traceId = (req as any).traceId || 'unknown';
  const isHttp2Client = res instanceof http2.Http2ServerResponse;
  const forbiddenHeaders = ['connection', 'keep-alive', 'upgrade'];
  const headersToSend: Record<string, any> = {};

  for (const [key, value] of Object.entries(proxyRes.headers)) {
    const lowerKey = key.toLowerCase();
    if (isHttp2Client && forbiddenHeaders.includes(lowerKey)) continue;
    if (value !== undefined) headersToSend[lowerKey] = value;
  }

  headersToSend['x-tgate-trace-id'] = traceId;
  headersToSend['server'] = 'TraceGate';

  if (!res.headersSent) {
    res.writeHead(proxyRes.statusCode || 200, headersToSend);
  }

  proxyRes.pipe(res);

  const startAt = (req as any)._startAt;
  const diff = process.hrtime(startAt);
  const durationMs = (diff[0] * 1e3) + (diff[1] / 1e6);
  await logger.info({ traceId, msg: 'Proxy target responded', host: req.headers.host || 'unknown', durationMs: `${durationMs.toFixed(2)}ms` });
});

// Improvement: Removed res.on('close', () => client.close()) to fix connection closed errors; use logger instead of console; add try-catch.
async function proxyHttp2(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, route: any) {
  const traceId = (req as any).traceId || createTraceId();
  (req as any).traceId = traceId;

  try {
    const client = getOrCreateSession(route.target);

    logger.debug({ traceId, msg: `Proxying HTTP/2 request to ${route.target} for ${req.method} ${req.url}` }); // Fix: Use logger.

    const proxyHeaders: http2.OutgoingHttpHeaders = {
      ':method': req.method,
      ':path': req.url || '/',
      ...filterHttp2Headers(req.headers)
    };

    // Improvement: Stronger header validation.
    for (const key in proxyHeaders) {
      const isValid = /^[:a-z0-9!#$%&'*+.^_`|~-]+$/.test(key);
      if (!isValid) {
        logger.warn({ traceId, msg: 'Invalid HTTP/2 header name, dropping', header: key });
        delete proxyHeaders[key];
        continue;
      }
      const val = proxyHeaders[key];
      if (Array.isArray(val)) {
        proxyHeaders[key] = val.join(',');
      }
    }

    const proxyReq = client.request(proxyHeaders);

    proxyReq.setTimeout(CLIENT_HTTP2_TIMEOUT_MS, () => {
      logger.warn({ traceId, msg: 'Proxy HTTP/2 stream timed out' });
      proxyReq.destroy();
      if (!res.headersSent) 
        res.writeHead(504);
      res.end();
    });

    proxyReq.on('response', (headers) => {
      const status = headers[':status'] || 200;
      if (!res.headersSent) {
        res.writeHead(Number(status), headers);
      }
    });

    proxyReq.on('push', (headers) => {
      logger.info({ traceId, msg: 'Received HTTP/2 push from origin (ignored)', path: headers[':path'] });
    });

    proxyReq.on('trailers', (trailers) => res.addTrailers(trailers));

    res.on('close', () => {
      logger.debug({ traceId, msg: 'Client closed connection before response completed' });
      proxyReq.destroy();
    });

    proxyReq.on('aborted', () => {
      logger.warn({ traceId, msg: 'Proxy request aborted' });
      proxyReq.destroy();
    });

    proxyReq.on('error', (err) => {
      logger.warn({ traceId, msg: 'Proxy HTTP/2 stream error', error: err.message });

      if (!res.headersSent)
        res.writeHead(502);

      res.end('Proxy error: ' + err.message);
      proxyReq.destroy();
    });

    //req.pipe(proxyReq);
    //proxyReq.pipe(res);

  } catch (err) {
    logger.error({ traceId, msg: 'HTTP/2 proxy failure', error: (err as Error).message });

    if (!res.headersSent)
      res.writeHead(500);

    res.end();
  }
}

// Improvement: Use logger for debug; add try-catch.
async function proxyRequest(req: any, res: any, scheme: 'http' | 'https', host: string, remoteAddr: string) {
  const traceId = req.traceId;
  const route = getRoute(scheme, host);
  const secureRoute = getRoute('https', host);
  const plainRoute = getRoute('http', host);

  if (scheme === 'http' && !plainRoute && secureRoute) {
    logger.info({ traceId, msg: 'Redirecting HTTP to HTTPS', host, remoteAddr });
    res.writeHead(308, { Location: `https://${host}${req.url}` });
    res.end();
    return;
  }

  if (!route) {
    logger.warn({ traceId, msg: `No ${scheme.toUpperCase()} route configured. Dropping.`, host, remoteAddr });
    res.writeHead(502);
    res.end();
    return;
  }

  try {
    const supportsHttp2 = await isHttp2Backend(route.target);
    logger.debug({ traceId, msg: `Backend ${route.target} supports HTTP/2: ${supportsHttp2}` }); // Fix: Use logger.

    if (supportsHttp2) {
      await proxyHttp2(req, res, route);
    } else {
      logger.info({ traceId, msg: `Proxying ${scheme.toUpperCase()} request`, host, target: route.target, remoteAddr });

      const isHttp2 = req instanceof http2.Http2ServerRequest;
      const sanitizedHeaders = isHttp2 ? convertHttp2ToHttp1Headers(req.headers) : req.headers;

      const proxyInputReq = isHttp2 ? cloneHttp2ToHttp1Request(req, sanitizedHeaders) : req;

      if (!(proxyInputReq as any).traceId) {
        (proxyInputReq as any).traceId = traceId;
      }

      proxy.web(proxyInputReq, res, {
        target: route.target,
        secure: route.target.startsWith('https'),
        changeOrigin: true,
        agent: route.target.startsWith('https') ? keepAliveHttpsAgent : keepAliveHttpAgent,
        xfwd: true,
        timeout: isHttp2 ? CLIENT_HTTP2_TIMEOUT_MS : DEFAULT_TIMEOUT_MS, // Adaptado para protocolo do cliente
        proxyTimeout: isHttp2 ? CLIENT_HTTP2_TIMEOUT_MS : DEFAULT_TIMEOUT_MS,
        headers: sanitizedHeaders,
      });

    }
  } catch (err) {
    logger.error({ traceId, msg: 'Proxy request failure', error: (err as Error).message });
    if (!res.headersSent) {
      res.writeHead(500);
    }
    res.end();
  }
}

// Improvement: Add try-catch for WAF.
function handleHttp1Request(req: http.IncomingMessage, res: http.ServerResponse) {
  const traceId = createTraceId();
  (req as any).traceId = traceId;
  res.setHeader('X-TGate-Trace-Id', traceId);

  const { scheme, host, remoteAddr } = extractSchemeAndHost(req.headers, req.socket);

  try {
    const wafResult = applyWAFRules(req);
    if (!wafResult.allowed) {
      logger.warn({ traceId, msg: 'Request blocked by WAF', host, remoteAddr, reason: wafResult.reason });
      res.writeHead(403);
      res.end();
      return;
    }
  } catch (err) {
    logger.error({ traceId, msg: 'WAF error', error: (err as Error).message });
    res.writeHead(500);
    res.end();
    return;
  }

  proxyRequest(req, res, scheme, host, remoteAddr);
}

// Same as above for HTTP/2 handler.
function handleHttp2Request(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse) {
  const traceId = createTraceId();
  (req as any).traceId = traceId;
  res.setHeader('X-TGate-Trace-Id', traceId);

  const socket = req.stream?.session?.socket;
  const { scheme, host, remoteAddr } = extractSchemeAndHost(req.headers, socket);

  try {
    const wafResult = applyWAFRules(req as any);
    if (!wafResult.allowed) {
      logger.warn({ traceId, msg: 'Request blocked by WAF', host, remoteAddr, reason: wafResult.reason });
      res.writeHead(403);
      res.end();
      return;
    }
  } catch (err) {
    logger.error({ traceId, msg: 'WAF error', error: (err as Error).message });
    res.writeHead(500);
    res.end();
    return;
  }

  proxyRequest(req, res, scheme, host, remoteAddr);
}

export function startTraceGate() {
  const httpServer = http.createServer(handleHttp1Request);
  httpServer.listen(80, () => logger.info({ msg: 'HTTP server running on port 80' }));

  const httpsServer = http2.createSecureServer({
    allowHTTP1: true,
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    SNICallback: async (domain, cb) => {
      try {
        const route = routes[`https://${domain}`];
        if (!route?.tls?.enabled) throw new Error('TLS not enabled');
        const ctx = await getCachedSecureContext(domain, route.tls);
        cb(null, ctx);
      } catch (err) {
        logger.warn({ msg: 'Dropping connection: no certificate configured', domain, error: (err as Error).message });
        cb(new Error('No TLS context'));
      }
    }
  });

  httpsServer.on('request', (req, res) => {
    if ((req as any).httpVersion === '2.0') {
      handleHttp2Request(req as http2.Http2ServerRequest, res as http2.Http2ServerResponse);
    } else {
      handleHttp1Request(req as any, res as any);
    }
  });

  httpsServer.listen(443, () => logger.info({ msg: 'HTTPS server running on port 443' }));
}