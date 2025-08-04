// src/core/balancer.ts
import http2 from 'http2';
import http from 'http';
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

const config = loadConfig();
validateRouteTargets(config.routes);
const proxy = httpProxy.createProxyServer({});
const routes = config.routes;

const keepAliveHttpAgent = new http.Agent({ keepAlive: true });
const keepAliveHttpsAgent = new http.Agent({ keepAlive: true });

const backendHttp2Support = new LRUCache<string, boolean>({ max: 100, ttl: 600_000 });

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
    if (['connection', 'upgrade', 'keep-alive', 'transfer-encoding'].includes(lowerKey)) continue;
    if (value !== undefined) {
      h1Headers[lowerKey] = Array.isArray(value) ? value.join(',') : value;
    }
  }

  if (!h1Headers['host'] && h2Headers[':authority']) {
    h1Headers['host'] = h2Headers[':authority'] as string;
  }

  return h1Headers;
}

function cloneHttp2ToHttp1Request(h2req: http2.Http2ServerRequest, headers: http.IncomingHttpHeaders): IncomingMessage {
  const clonedReq = Readable.from(h2req) as unknown as IncomingMessage;
  clonedReq.headers = headers;
  clonedReq.method = h2req.method;
  clonedReq.url = h2req.url;
  clonedReq.httpVersion = '1.1';

  const socket = h2req.stream?.session?.socket;
  if (socket) {
    clonedReq.connection = socket as any;
    (clonedReq as any).socket = socket;
  } else {
    throw new Error('Cannot extract socket from HTTP/2 request');
  }

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
  const forbiddenHeaders = ['connection', 'keep-alive', 'transfer-encoding', 'upgrade', 'proxy-connection', 'content-encoding'];
  const headersToSend: Record<string, any> = {};

  for (const [key, value] of Object.entries(proxyRes.headers)) {
    const lowerKey = key.toLowerCase();
    if (isHttp2Client && forbiddenHeaders.includes(lowerKey)) continue;
    if (value !== undefined) headersToSend[lowerKey] = value;
  }

  // const contentType = headersToSend['content-type'];
  // if (typeof contentType === 'string' && contentType.startsWith('image/svg')) {
  //   headersToSend['content-disposition'] = 'inline';
  // }

   headersToSend['x-tgate-trace-id'] = traceId;
   headersToSend['server'] = 'TraceGate';

   //headersToSend['x-content-type-options'] = 'nosniff';

  if (!res.headersSent) {
    res.writeHead(proxyRes.statusCode || 200, headersToSend);
  }

  const pass = new PassThrough();
  let totalBytes = 0;
  const chunks: Buffer[] = [];

  pass.on('data', (chunk) => {
    totalBytes += chunk.length;
    chunks.push(chunk);
  });

  pass.on('end', () => {
    // console.log(`[${traceId}] proxyRes completed. Bytes: ${totalBytes}`);
    // if (typeof contentType === 'string' && contentType.startsWith('image/svg')) {
    //   const fullBody = Buffer.concat(chunks);
    //   const dumpPath = `/tmp/svg-${traceId}.svg`;
    //   fs.writeFileSync(dumpPath, fullBody);
    //   console.log(`[${traceId}] Saved full SVG to ${dumpPath}`);
    // }
  });

  proxyRes.pipe(pass);
  pass.pipe(res);

  const startAt = (req as any)._startAt;
  const diff = process.hrtime(startAt);
  const durationMs = (diff[0] * 1e3) + (diff[1] / 1e6);
  await logger.info({ traceId, msg: 'Proxy target responded', host: req.headers.host || 'unknown', durationMs: `${durationMs.toFixed(2)}ms` });
});

function proxyHttp2(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse, route: any) {

  if (!(req as any).traceId)
    (req as any).traceId = createTraceId();

  console.log(`Proxying HTTP/2 request to ${route.target} for ${req.method} ${req.url}`);
  const client = http2.connect(route.target);

  const proxyHeaders: http2.OutgoingHttpHeaders = {
    ':method': req.method,
    ':path': req.url || '/',
    ...filterHttp2Headers(req.headers)
  };

  for (const key in proxyHeaders) {
    const isPseudo = key.startsWith(':');
    const isValid = /^[:a-z0-9!#$%&'*+.^_`|~-]+$/.test(key); // inclui pseudo-headers

    if (!isValid) {
      logger.warn({ msg: 'Invalid HTTP/2 header name, dropping', header: key });
      delete proxyHeaders[key];
      continue;
    }

    const val = proxyHeaders[key];
    if (Array.isArray(val)) {
      proxyHeaders[key] = val.join(','); // HTTP/2 espera valores simples em headers
    }
  }


  const proxyReq = client.request(proxyHeaders);

  proxyReq.on('response', (headers, flags) => {
    const status = headers[':status'] || 200;
    if (!res.headersSent) {
      res.writeHead(Number(status), headers as any);
    }
    proxyReq.pipe(res);
  });

  proxyReq.on('push', (headers, pushStream) => {
    const pushPath = headers[':path'] || '';
    logger.info({ msg: 'Received HTTP/2 push from origin', path: pushPath });
  });

  proxyReq.on('trailers', (trailers) => {
    res.addTrailers(trailers as any);
  });

  req.on('end', () => {
    proxyReq.end();
  });

  req.pipe(proxyReq);

  proxyReq.on('error', (err) => {
    logger.warn({ msg: 'Proxy HTTP/2 error', error: err.message });
    if (!res.headersSent) {
      res.writeHead(502);
    }
    res.end('Proxy error: ' + err.message);
  });

  res.on('close', () => client.close());
}

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

  var x = await isHttp2Backend(route.target);
  console.log(`isHttp2Backend(${route.target}) = ${x}`);

  if (await isHttp2Backend(route.target)) {
    proxyHttp2(req, res, route);
  } else {

    logger.info({ traceId, msg: `Proxying ${scheme.toUpperCase()} request`, host, target: route.target, remoteAddr });

    // 🧠 Se for uma requisição HTTP/2 de entrada e o destino NÃO suporta H2, precisamos adaptar headers


    const isHttp2 = req instanceof http2.Http2ServerRequest;
    const sanitizedHeaders = isHttp2
      ? convertHttp2ToHttp1Headers(req.headers)
      : req.headers;

    //console.log('sanitizedHeaders = ', sanitizedHeaders);

    const proxyInputReq = isHttp2
      ? cloneHttp2ToHttp1Request(req, sanitizedHeaders)
      : req;

    if (!(proxyInputReq as any).traceId) {
      (proxyInputReq as any).traceId = traceId;
    }

    //logger.info({ traceId, msg: `Proxying ${scheme.toUpperCase()} request`, host, target: route.target, remoteAddr });
    proxy.web(proxyInputReq, res, {
      target: route.target,
      secure: route.target.startsWith('https'),
      changeOrigin: true,
      agent: route.target.startsWith('https') ? keepAliveHttpsAgent : keepAliveHttpAgent,
      xfwd: true,
      timeout: 15000,
      proxyTimeout: 15000,
      headers: sanitizedHeaders,
    });
  }
}

function handleHttp1Request(req: http.IncomingMessage, res: http.ServerResponse) {

  const traceId = createTraceId();
  (req as any).traceId = traceId;
  res.setHeader('X-TGate-Trace-Id', traceId);

  const { scheme, host, remoteAddr } = extractSchemeAndHost(req.headers, req.socket);


  const wafResult = applyWAFRules(req);
  if (!wafResult.allowed) {
    logger.warn({ traceId, msg: 'Request blocked by WAF', host, remoteAddr, reason: wafResult.reason });
    res.writeHead(403);
    res.end();
    return;
  }

  proxyRequest(req, res, scheme, host, remoteAddr);
}

function handleHttp2Request(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse) {
  const traceId = createTraceId();
  (req as any).traceId = traceId;
  res.setHeader('X-TGate-Trace-Id', traceId);

  const socket = req.stream?.session?.socket;
  const { scheme, host, remoteAddr } = extractSchemeAndHost(req.headers, socket);

  const wafResult = applyWAFRules(req as any);
  if (!wafResult.allowed) {
    logger.warn({ traceId, msg: 'Request blocked by WAF', host, remoteAddr, reason: wafResult.reason });
    res.writeHead(403);
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
        cb(new Error());
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
