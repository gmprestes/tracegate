// src/services/logger.ts

import pino from 'pino';
import crypto from 'crypto';
import path from 'path';
import { createStream, Generator } from 'rotating-file-stream';
import fs from 'fs';

import { loadConfig } from '../utils/configLoader';
const config = loadConfig();

let fileStream;
const streams: { stream: any }[] = [{ stream: process.stdout }];

if (config.logger.fileLogs?.enabled) {
  const logDir = config.logger.fileLogs.outputDir
    ? path.resolve(config.logger.fileLogs.outputDir)
    : path.resolve(__dirname, '../../logs');

  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const generator: Generator = (time, index) => {
    if (!time) return 'tracegate.log';
    const date = new Date(time).toISOString().split('T')[0]; // YYYY-MM-DD
    return `tracegate-${date}.log`;
  };

  fileStream = config.logger.fileLogs.rotation.enabled
    ? createStream(generator, {
        interval: config.logger.fileLogs.rotation.interval,
        compress: config.logger.fileLogs.rotation.compress,
        path: logDir
      })
    : fs.createWriteStream(path.join(logDir, 'tracegate.log'), { flags: 'a' });

  streams.unshift({ stream: fileStream });
}

// Optional: Cloud log integrations
if (config.logger.cloud?.enabled) {
  if (config.logger.cloud.provider === 'cloudwatch') {
    // const cloudStream = createCloudWatchStream(config.logger.cloud);
    // streams.push({ stream: cloudStream });
  } else if (config.logger.cloud.provider === 'datadog') {
    // const datadogStream = createDatadogStream(config.logger.cloud);
    // streams.push({ stream: datadogStream });
  } else if (config.logger.cloud.provider === 'loki') {
    // const lokiStream = createLokiStream(config.logger.cloud);
    // streams.push({ stream: lokiStream });
  }
}

const logger = pino({
  level: config.logger.level || 'info',
  timestamp: pino.stdTimeFunctions.isoTime,
  formatters: {
    level(label) {
      return { level: label };
    }
  }
}, pino.multistream(streams));

export { logger };

export function createTraceId(): string {
  return crypto.randomBytes(8).toString('hex');
}
