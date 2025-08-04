// src/utils/configLoader.ts
import fs from 'fs';
import path from 'path';
import { TraceGateConfig } from '../types/config';

const CONFIG_PATH = path.resolve(__dirname, '../config/tracegate.config.json');

let cachedConfig: TraceGateConfig | null = null;

export function loadConfig(): TraceGateConfig {
  if (cachedConfig) return cachedConfig;

  const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
  const parsed = JSON.parse(raw) as TraceGateConfig;

  cachedConfig = parsed;
  return parsed;
}
