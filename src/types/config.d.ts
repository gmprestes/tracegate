// src/types/config.d.ts
export type WAFConfig = {
  mode?: 'block' | 'monitor' | 'log-only';
  blockIPs?: string[];
  blockUserAgents?: string[];
  blockPaths?: string[];
};

export type TLSConfig = {
  enabled: boolean;
  certPath: string;
  keyPath: string;
};

export type RouteConfig = {
  target: string;
  tls?: TLSConfig;
  waf?: WAFConfig;
};

export type LoggerConfig = {
  level: 'info' | 'warn' | 'error' | 'debug';
  fileLogs?: {
    enabled: boolean;
    outputDir?: string;
    rotation: {
      enabled: boolean;
      interval: string;
      compress: boolean | 'gzip' | 'brotli';
    };
  };
  cloud?: {
    enabled: boolean;
    provider: 'cloudwatch' | 'datadog' | 'loki';
    endpoint?: string;
    apiKey?: string;
    region?: string;
    [key: string]: any;
  };
};

export type TraceGateConfig = {
  logger: LoggerConfig;
  routes: Record<string, RouteConfig>;
};
