import compression from 'compression';
import crypto from 'crypto';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import path from 'path';
import process from 'process';
import { promises as fs } from 'fs';
import { UAParser } from 'ua-parser-js';
import { z } from 'zod';

const PORT = Number.parseInt(process.env.PORT ?? '10000', 10);
const LOG_TO_FILE = (process.env.LOG_TO_FILE ?? 'true').toLowerCase() === 'true';
const LOG_DIR = process.env.LOG_DIR ?? path.resolve('data', 'logs');
const IP_HASH_SALT = process.env.IP_HASH_SALT;
const CONSENT_REQUIRED = (process.env.CONSENT_REQUIRED ?? 'false').toLowerCase() === 'true';

if (!IP_HASH_SALT) {
  console.error('Environment variable IP_HASH_SALT is required to hash client IP addresses.');
  process.exit(1);
}

let logDirReadyPromise = null;
if (LOG_TO_FILE) {
  logDirReadyPromise = fs.mkdir(LOG_DIR, { recursive: true }).catch((error) => {
    console.error('Unable to prepare log directory:', error);
    process.exit(1);
  });
}

const app = express();
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin-allow-popups' },
}));
app.use(compression());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

const telemetrySchema = z
  .object({
    identifiers: z
      .object({
        sessionId: z.string().min(1).max(128),
        visitorId: z.string().min(1).max(128),
        deviceFingerprint: z.string().min(1).max(256),
        navigatorFingerprint: z.string().min(1).max(256),
      })
      .strict(),
    system: z
      .object({
        platform: z.string().min(1).max(128).optional(),
        os: z.string().min(1).max(128).optional(),
        osVersion: z.string().min(1).max(128).optional(),
        architecture: z.string().min(1).max(64).optional(),
        hardwareConcurrency: z.number().int().positive().max(1024).optional(),
        deviceMemory: z.number().positive().max(4096).optional(),
        userAgent: z.string().min(1).max(2048).optional(),
        localTime: z.string().min(1).max(128).optional(),
        language: z.string().min(1).max(64).optional(),
        languages: z.array(z.string().min(1).max(64)).max(32).optional(),
      })
      .strict(),
    network: z
      .object({
        connectionType: z.string().min(1).max(64).optional(),
        effectiveType: z.string().min(1).max(64).optional(),
        downlink: z.number().nonnegative().max(10000).optional(),
        rtt: z.number().nonnegative().max(100000).optional(),
        saveData: z.boolean().optional(),
      })
      .strict(),
    hardware: z
      .object({
        screen: z
          .object({
            width: z.number().int().nonnegative(),
            height: z.number().int().nonnegative(),
            colorDepth: z.number().int().nonnegative().optional(),
            pixelDepth: z.number().int().nonnegative().optional(),
          })
          .strict(),
        viewport: z
          .object({
            width: z.number().int().nonnegative(),
            height: z.number().int().nonnegative(),
          })
          .strict()
          .optional(),
        pixelRatio: z.number().positive().max(10).optional(),
        touchSupport: z
          .object({
            maxTouchPoints: z.number().int().nonnegative().max(100),
            touchEvent: z.boolean(),
            pointerEvent: z.boolean(),
          })
          .strict()
          .optional(),
        gpu: z
          .object({
            vendor: z.string().min(1).max(256).optional(),
            renderer: z.string().min(1).max(512).optional(),
          })
          .strict()
          .optional(),
        battery: z
          .object({
            charging: z.boolean().optional(),
            chargingTime: z.number().nonnegative().optional(),
            dischargingTime: z.number().nonnegative().optional(),
            level: z.number().min(0).max(1).optional(),
          })
          .strict()
          .optional(),
        audioDevices: z.number().int().nonnegative().optional(),
        videoDevices: z.number().int().nonnegative().optional(),
      })
      .strict(),
    features: z
      .object({
        cookiesEnabled: z.boolean().optional(),
        javaScriptEnabled: z.boolean().optional(),
        serviceWorkerStatus: z.string().min(1).max(64).optional(),
        mediaDevices: z.boolean().optional(),
        storageEstimate: z
          .object({
            quota: z.number().nonnegative().optional(),
            usage: z.number().nonnegative().optional(),
          })
          .strict()
          .optional(),
      })
      .strict(),
    activityLog: z
      .array(
        z
          .object({
            timestamp: z.string().min(1).max(64),
            message: z.string().min(1).max(256),
          })
          .strict(),
      )
      .max(256)
      .optional(),
    consentGranted: z.boolean().optional(),
  })
  .strict();

function normalizeIp(rawIp) {
  if (!rawIp) return '';
  const first = rawIp.split(',')[0].trim();
  return first.startsWith('::ffff:') ? first.slice(7) : first;
}

function resolveClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  let candidate = '';

  if (Array.isArray(forwarded)) {
    candidate = forwarded.find((value) => typeof value === 'string' && value.trim().length > 0) ?? '';
  } else if (typeof forwarded === 'string' && forwarded.trim().length > 0) {
    candidate = forwarded;
  }

  if (candidate) {
    return normalizeIp(candidate);
  }

  const remoteAddress = req.socket?.remoteAddress ?? req.connection?.remoteAddress ?? '';
  return normalizeIp(remoteAddress);
}

function hashIp(ip) {
  if (!ip) return null;
  const hash = crypto.createHash('sha256');
  hash.update(ip);
  hash.update(IP_HASH_SALT);
  return hash.digest('hex');
}

function selectHeaders(headers) {
  const keys = ['user-agent', 'referer', 'accept-language'];
  return keys.reduce((acc, key) => {
    if (headers[key]) {
      acc[key] = headers[key];
    }
    return acc;
  }, {});
}

function indentBlock(text, spaces = 2) {
  const indent = ' '.repeat(spaces);
  return text
    .split('\n')
    .map((line) => indent + line)
    .join('\n');
}

function formatTextLogEntry(entry) {
  const {
    timestamp,
    method,
    path: requestPath,
    hashedIp,
    headers,
    userAgent,
    event,
    telemetry,
    ...rest
  } = entry;

  const lines = [];
  lines.push(`Timestamp: ${timestamp ?? 'Unknown'}`);
  const requestLine = [method ?? 'UNKNOWN', requestPath ?? ''].filter(Boolean).join(' ');
  lines.push(`Request: ${requestLine || 'Unavailable'}`);
  lines.push(`Hashed IP: ${hashedIp ?? 'Unavailable'}`);
  lines.push('Selected Headers:');
  lines.push(indentBlock(JSON.stringify(headers ?? {}, null, 2)));
  lines.push('Parsed User Agent:');
  lines.push(indentBlock(JSON.stringify(userAgent ?? {}, null, 2)));

  if (event) {
    lines.push(`Event: ${event}`);
  }

  if (telemetry) {
    lines.push('Telemetry Snapshot:');
    lines.push(indentBlock(JSON.stringify(telemetry, null, 2)));
  }

  const remaining = Object.keys(rest).length > 0 ? rest : null;
  if (remaining) {
    lines.push('Additional Fields:');
    lines.push(indentBlock(JSON.stringify(remaining, null, 2)));
  }

  lines.push('-----');
  return lines.join('\n') + '\n';
}

function sanitizeUAResult(result) {
  const { browser, engine, os, device, cpu } = result;
  return {
    browser,
    engine,
    os,
    device,
    cpu,
  };
}

async function persistLog(entry) {
  const line = `${JSON.stringify(entry)}\n`;
  process.stdout.write(line);

  if (!LOG_TO_FILE) {
    return;
  }

  await logDirReadyPromise;
  const now = new Date();
  const dateStamp = now.toISOString().slice(0, 10);
  const jsonlPath = path.join(LOG_DIR, `visits-${dateStamp}.jsonl`);
  const textPath = path.join(LOG_DIR, `visits-${dateStamp}.txt`);

  try {
    await fs.appendFile(jsonlPath, line, 'utf8');
  } catch (error) {
    console.error('Failed to append visit log (jsonl):', error);
  }

  try {
    const formatted = formatTextLogEntry(entry);
    await fs.appendFile(textPath, formatted, 'utf8');
  } catch (error) {
    console.error('Failed to append visit log (text):', error);
  }
}

function buildBaseLog(req) {
  const timestamp = new Date().toISOString();
  const ip = resolveClientIp(req);
  const hashedIp = hashIp(ip);
  const parser = new UAParser(req.headers['user-agent'] ?? '');
  const ua = sanitizeUAResult(parser.getResult());

  return {
    timestamp,
    method: req.method,
    path: req.originalUrl,
    hashedIp,
    headers: selectHeaders(req.headers),
    userAgent: ua,
  };
}

async function logVisit(req, extra = {}) {
  const base = buildBaseLog(req);
  const entry = { ...base, ...extra };
  await persistLog(entry);
}

function renderLandingPage(consentRequired) {
  const title = 'Enhanced Device Info Collector';
  const description = 'Comprehensive device information collection with local logging and export capabilities';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      --bg: #0b1120;
      --panel: #111c2f;
      --panel-muted: rgba(30, 41, 59, 0.75);
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-strong: #0ea5e9;
      --border: rgba(148, 163, 184, 0.2);
      --shadow: 0 24px 65px rgba(8, 47, 73, 0.35);
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      padding: 3rem 1.5rem 4rem;
      min-height: 100vh;
      background: radial-gradient(circle at top left, #172554, #0b1120 55%);
      color: var(--text);
      display: flex;
      justify-content: center;
      align-items: flex-start;
    }

    .page {
      width: min(1120px, 100%);
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    .page__header {
      background: linear-gradient(135deg, rgba(37, 99, 235, 0.35), rgba(8, 47, 73, 0.8));
      border-radius: 1.5rem;
      padding: 2rem 2.5rem;
      box-shadow: var(--shadow);
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 1.5rem;
      border: 1px solid var(--border);
    }

    .page__header h1 {
      margin: 0;
      font-size: clamp(1.75rem, 3vw, 2.5rem);
      letter-spacing: -0.02em;
    }

    .page__header p {
      margin: 0.75rem 0 0;
      color: var(--text-muted);
      max-width: 480px;
      line-height: 1.6;
    }

    .action-group {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.75rem;
    }

    button {
      border: 1px solid transparent;
      background: rgba(56, 189, 248, 0.12);
      color: var(--text);
      padding: 0.75rem 1.4rem;
      border-radius: 999px;
      font-size: 0.95rem;
      letter-spacing: 0.02em;
      cursor: pointer;
      transition: transform 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
      box-shadow: 0 10px 30px rgba(14, 165, 233, 0.25);
      backdrop-filter: blur(6px);
    }

    button:hover {
      transform: translateY(-1px);
      background: rgba(56, 189, 248, 0.24);
      border-color: rgba(56, 189, 248, 0.65);
    }

    button:disabled {
      opacity: 0.45;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }

    button.secondary {
      background: rgba(148, 163, 184, 0.14);
      box-shadow: none;
    }

    button.secondary:hover {
      background: rgba(148, 163, 184, 0.28);
      border-color: rgba(148, 163, 184, 0.4);
    }

    .cards-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1.25rem;
    }

    .card {
      background: linear-gradient(145deg, rgba(15, 23, 42, 0.85), rgba(15, 23, 42, 0.6));
      border-radius: 1.4rem;
      padding: 1.5rem;
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      display: flex;
      flex-direction: column;
      gap: 1rem;
      position: relative;
    }

    .card::after {
      content: '';
      position: absolute;
      inset: 1px;
      border-radius: 1.35rem;
      border: 1px solid rgba(255, 255, 255, 0.02);
      pointer-events: none;
    }

    .card--wide {
      grid-column: 1 / -1;
    }

    .card__title {
      font-size: 1.05rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--text-muted);
    }

    .metric-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 1rem 1.25rem;
    }

    .metric {
      display: flex;
      flex-direction: column;
      gap: 0.4rem;
      padding: 0.75rem 0.85rem;
      background: rgba(15, 23, 42, 0.65);
      border-radius: 0.85rem;
      border: 1px solid rgba(148, 163, 184, 0.12);
      min-height: 82px;
    }

    .metric__label {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
    }

    .metric__value {
      font-size: 0.98rem;
      line-height: 1.4;
      word-break: break-word;
    }

    .metric__hint {
      font-size: 0.7rem;
      color: var(--accent);
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }

    .activity-card {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 1rem;
    }

    .activity-log {
      display: grid;
      gap: 0.75rem;
      max-height: 280px;
      overflow-y: auto;
      padding-right: 0.5rem;
    }

    .activity-entry {
      display: grid;
      grid-template-columns: 90px 1fr;
      align-items: center;
      gap: 0.75rem;
      background: rgba(15, 23, 42, 0.55);
      border-radius: 0.75rem;
      padding: 0.75rem;
      border: 1px solid rgba(56, 189, 248, 0.18);
    }

    .activity-entry__time {
      font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
      font-size: 0.75rem;
      color: var(--accent);
    }

    .activity-entry__message {
      font-size: 0.9rem;
      color: var(--text);
    }

    .consent-banner {
      position: fixed;
      inset: auto 1.5rem 1.5rem;
      background: rgba(8, 47, 73, 0.95);
      border-radius: 1rem;
      padding: 1.5rem;
      border: 1px solid rgba(56, 189, 248, 0.3);
      box-shadow: var(--shadow);
      display: none;
      gap: 1rem;
      max-width: min(520px, calc(100% - 3rem));
    }

    .consent-banner.active {
      display: flex;
      flex-direction: column;
    }

    .consent-banner p {
      margin: 0;
      color: var(--text-muted);
      line-height: 1.5;
    }

    @media (max-width: 720px) {
      body {
        padding: 2.5rem 1rem 3rem;
      }

      .page__header {
        padding: 1.75rem 1.5rem;
      }

      .metric {
        min-height: 72px;
      }
    }
  </style>
</head>
<body>
  <div class="page">
    <header class="page__header">
      <div>
        <h1>${title}</h1>
        <p>${description}</p>
      </div>
      <div class="action-group">
        <button type="button" data-action="refresh">Refresh Data</button>
        <button type="button" class="secondary" data-action="export" disabled>Download Report</button>
      </div>
    </header>

    <section class="card card--wide">
      <div class="card__title">Baseline &amp; Controls</div>
      <div class="metric-grid">
        <div class="metric">
          <span class="metric__label">Session ID</span>
          <span class="metric__value" data-field="session-id">Collecting…</span>
        </div>
        <div class="metric">
          <span class="metric__label">Visitor ID</span>
          <span class="metric__value" data-field="visitor-id">Collecting…</span>
        </div>
        <div class="metric">
          <span class="metric__label">Last Updated</span>
          <span class="metric__value" data-field="last-updated">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Consent Status</span>
          <span class="metric__value" data-field="consent-status">Pending</span>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card__title">Device Identifiers</div>
      <div class="metric-grid">
        <div class="metric">
          <span class="metric__label">Device Fingerprint</span>
          <span class="metric__value" data-field="device-fingerprint">Collecting…</span>
          <span class="metric__hint">Hashed fingerprint</span>
        </div>
        <div class="metric">
          <span class="metric__label">Navigator Fingerprint</span>
          <span class="metric__value" data-field="navigator-fingerprint">Collecting…</span>
          <span class="metric__hint">Navigator traits hash</span>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card__title">System Information</div>
      <div class="metric-grid">
        <div class="metric">
          <span class="metric__label">Operating System</span>
          <span class="metric__value" data-field="operating-system">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">OS Version</span>
          <span class="metric__value" data-field="os-version">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Architecture</span>
          <span class="metric__value" data-field="architecture">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">CPU Cores</span>
          <span class="metric__value" data-field="cpu-cores">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Device Memory</span>
          <span class="metric__value" data-field="device-memory">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">User Agent</span>
          <span class="metric__value" data-field="user-agent">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Local Time</span>
          <span class="metric__value" data-field="local-time">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Languages</span>
          <span class="metric__value" data-field="languages">—</span>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card__title">Network &amp; Connection</div>
      <div class="metric-grid">
        <div class="metric">
          <span class="metric__label">Network Type</span>
          <span class="metric__value" data-field="network-type">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Effective Type</span>
          <span class="metric__value" data-field="effective-type">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Downlink</span>
          <span class="metric__value" data-field="downlink">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">RTT</span>
          <span class="metric__value" data-field="rtt">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Save Data</span>
          <span class="metric__value" data-field="save-data">—</span>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card__title">Hardware Details</div>
      <div class="metric-grid">
        <div class="metric">
          <span class="metric__label">Screen Resolution</span>
          <span class="metric__value" data-field="screen-resolution">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Viewport Size</span>
          <span class="metric__value" data-field="viewport-size">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Color Depth</span>
          <span class="metric__value" data-field="color-depth">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Pixel Ratio</span>
          <span class="metric__value" data-field="pixel-ratio">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Touch Support</span>
          <span class="metric__value" data-field="touch-support">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">GPU</span>
          <span class="metric__value" data-field="gpu">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Battery</span>
          <span class="metric__value" data-field="battery">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Audio Devices</span>
          <span class="metric__value" data-field="audio-devices">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Video Devices</span>
          <span class="metric__value" data-field="video-devices">—</span>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card__title">Browser &amp; Features</div>
      <div class="metric-grid">
        <div class="metric">
          <span class="metric__label">Cookies</span>
          <span class="metric__value" data-field="cookies-enabled">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">JavaScript</span>
          <span class="metric__value" data-field="javascript-enabled">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Service Worker</span>
          <span class="metric__value" data-field="service-worker">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Media Devices API</span>
          <span class="metric__value" data-field="media-devices">—</span>
        </div>
        <div class="metric">
          <span class="metric__label">Storage Estimate</span>
          <span class="metric__value" data-field="storage-estimate">—</span>
        </div>
      </div>
    </section>

    <section class="card card--wide activity-card">
      <div class="card__title">Activity Log</div>
      <div class="activity-log" data-activity-log>
        <div class="activity-entry">
          <span class="activity-entry__time">00:00:00</span>
          <span class="activity-entry__message">Awaiting telemetry collection…</span>
        </div>
      </div>
    </section>
  </div>

  <div class="consent-banner" id="consent-banner">
    <p>This collector captures device metadata such as hardware, network, and browser capabilities. Share details to begin secure logging.</p>
    <button id="consent-button" type="button">Allow secure collection</button>
  </div>

  <script>
    (function () {
      const consentRequired = ${consentRequired ? 'true' : 'false'};
      const banner = document.getElementById('consent-banner');
      const button = document.getElementById('consent-button');
      const refreshBtn = document.querySelector('[data-action="refresh"]');
      const exportBtn = document.querySelector('[data-action="export"]');
      const activityContainer = document.querySelector('[data-activity-log]');
      const state = {
        collecting: false,
        consentGranted: !consentRequired,
        latestPayload: null,
        activityLog: [],
      };

      function formatFingerprint(value) {
        if (!value) return 'Unknown';
        const short = value.slice(0, 16).toUpperCase();
        return { text: short, title: value };
      }

      function setField(key, value) {
        const element = document.querySelector('[data-field="' + key + '"]');
        if (!element) return;

        if (value && typeof value === 'object' && 'text' in value) {
          element.textContent = value.text ?? 'Unknown';
          if (value.title) {
            element.setAttribute('title', value.title);
          } else {
            element.removeAttribute('title');
          }
          return;
        }

        if (value === undefined || value === null || value === '') {
          element.textContent = 'Unknown';
          element.removeAttribute('title');
        } else {
          element.textContent = String(value);
          element.setAttribute('title', String(value));
        }
      }

      function addActivity(message) {
        const timestamp = new Date().toLocaleTimeString();
        state.activityLog.unshift({ timestamp, message });
        state.activityLog = state.activityLog.slice(0, 12);
        renderActivity();
      }

      function renderActivity() {
        if (!activityContainer) return;
        activityContainer.innerHTML = '';
        if (state.activityLog.length === 0) {
          const entry = document.createElement('div');
          entry.className = 'activity-entry';
          entry.innerHTML = '<span class="activity-entry__time">—</span><span class="activity-entry__message">No events recorded yet.</span>';
          activityContainer.appendChild(entry);
          return;
        }
        for (const log of state.activityLog) {
          const entry = document.createElement('div');
          entry.className = 'activity-entry';
          const time = document.createElement('span');
          time.className = 'activity-entry__time';
          time.textContent = log.timestamp;
          const message = document.createElement('span');
          message.className = 'activity-entry__message';
          message.textContent = log.message;
          entry.append(time, message);
          activityContainer.appendChild(entry);
        }
      }

      function ensureId(storage, key) {
        if (!storage) {
          return Math.random().toString(16).slice(2) + Date.now().toString(16);
        }
        try {
          const existing = storage.getItem(key);
          if (existing) return existing;
          const id = (crypto && crypto.randomUUID) ? crypto.randomUUID() : Math.random().toString(16).slice(2) + Date.now().toString(16);
          storage.setItem(key, id);
          return id;
        } catch (error) {
          console.warn('Unable to persist identifier:', error);
          return Math.random().toString(16).slice(2) + Date.now().toString(16);
        }
      }

      async function hashString(value) {
        if (!value) return '';
        if (window.crypto?.subtle) {
          try {
            const encoded = new TextEncoder().encode(value);
            const buffer = await window.crypto.subtle.digest('SHA-256', encoded);
            return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, '0')).join('');
          } catch (error) {
            console.warn('Unable to hash string:', error);
          }
        }
        return value;
      }

      function detectOS(userAgent) {
        if (!userAgent) return { name: 'Unknown', version: '' };
        const matchers = [
          { regex: /Windows NT ([\d.]+)/, name: 'Windows' },
          { regex: /Mac OS X ([\d_]+)/, name: 'macOS', transform: (v) => v.replace(/_/g, '.') },
          { regex: /Android ([\d.]+)/, name: 'Android' },
          { regex: /iPhone OS ([\d_]+)/, name: 'iOS', transform: (v) => v.replace(/_/g, '.') },
          { regex: /iPad; CPU OS ([\d_]+)/, name: 'iPadOS', transform: (v) => v.replace(/_/g, '.') },
          { regex: /Linux/, name: 'Linux' },
          { regex: /CrOS ([^;]+)/, name: 'ChromeOS' },
        ];
        for (const matcher of matchers) {
          const match = userAgent.match(matcher.regex);
          if (match) {
            return {
              name: matcher.name,
              version: matcher.transform ? matcher.transform(match[1] ?? '') : match[1] ?? '',
            };
          }
        }
        return { name: navigator.platform || 'Unknown', version: '' };
      }

      function detectArchitecture(userAgent) {
        if (!userAgent) return 'Unknown';
        if (/arm64|aarch64/i.test(userAgent)) return 'ARM64';
        if (/arm/i.test(userAgent)) return 'ARM';
        if (/x86_64|Win64|WOW64|amd64/i.test(userAgent)) return 'x64';
        if (/i[3-6]86|x86/i.test(userAgent)) return 'x86';
        return 'Unknown';
      }

      function describeTouchSupport(maxTouchPoints) {
        if (!Number.isFinite(maxTouchPoints)) return 'Unknown';
        if (maxTouchPoints === 0) return 'No touch';
        if (maxTouchPoints === 1) return 'Single touch';
        return maxTouchPoints + ' touch points';
      }

      function describeBattery(battery) {
        if (!battery) return 'Unavailable';
        const level = battery.level != null ? Math.round(battery.level * 100) + '%' : '—';
        const charging = battery.charging === undefined ? '' : (battery.charging ? ' (Charging)' : ' (On battery)');
        return level + charging;
      }

      function formatStorage(estimate) {
        if (!estimate) return 'Unavailable';
        const { usage, quota } = estimate;
        const toGB = (value) => value == null ? null : (value / (1024 ** 3));
        const usageGB = toGB(usage);
        const quotaGB = toGB(quota);
        if (usageGB == null || quotaGB == null) return 'Unavailable';
        return usageGB.toFixed(2) + ' GB / ' + quotaGB.toFixed(2) + ' GB';
      }

      function formatDownlink(value) {
        if (typeof value !== 'number' || Number.isNaN(value)) return 'Unknown';
        return value.toFixed(2) + ' Mbps';
      }

      function formatRTT(value) {
        if (typeof value !== 'number' || Number.isNaN(value)) return 'Unknown';
        return Math.round(value) + ' ms';
      }

      function formatList(list) {
        if (!Array.isArray(list) || list.length === 0) return 'Unknown';
        return list.join(', ');
      }

      function updateConsentStatus() {
        setField('consent-status', state.consentGranted ? 'Granted' : 'Pending');
      }

      async function gatherIdentifiers() {
        addActivity('Preparing identifiers');
        let sessionStorageRef = null;
        let localStorageRef = null;
        try {
          sessionStorageRef = window.sessionStorage;
        } catch (error) {
          console.warn('Session storage unavailable:', error);
        }
        try {
          localStorageRef = window.localStorage;
        } catch (error) {
          console.warn('Local storage unavailable:', error);
        }

        const sessionId = ensureId(sessionStorageRef, 'device-collector-session');
        const visitorId = ensureId(localStorageRef, 'device-collector-visitor');
        const ua = navigator.userAgent || '';
        const language = navigator.language || '';
        const screen = window.screen || {};
        const baseFingerprint = [ua, language, screen.width + 'x' + screen.height, navigator.hardwareConcurrency, navigator.deviceMemory].filter(Boolean).join('::');
        const navigatorFingerprintBase = [navigator.platform, formatList(navigator.languages || []), navigator.maxTouchPoints, navigator.vendor, navigator.productSub].filter(Boolean).join('::');
        const deviceFingerprint = await hashString(baseFingerprint);
        const navigatorFingerprint = await hashString(navigatorFingerprintBase);
        setField('session-id', { text: sessionId, title: sessionId });
        setField('visitor-id', { text: visitorId, title: visitorId });
        setField('device-fingerprint', formatFingerprint(deviceFingerprint));
        setField('navigator-fingerprint', formatFingerprint(navigatorFingerprint));
        return { sessionId, visitorId, deviceFingerprint, navigatorFingerprint };
      }

      function gatherSystemInfo() {
        addActivity('Collecting system profile');
        const ua = navigator.userAgent || 'Unavailable';
        const osInfo = detectOS(ua);
        const osVersionValue = osInfo.version && osInfo.version.trim().length > 0 ? osInfo.version : undefined;
        const platformValue = navigator.platform && navigator.platform.trim().length > 0 ? navigator.platform : undefined;
        const architecture = detectArchitecture(ua);
        const cores = navigator.hardwareConcurrency ?? null;
        const memory = navigator.deviceMemory ?? null;
        const languages = navigator.languages && navigator.languages.length ? navigator.languages : (navigator.language ? [navigator.language] : []);
        const localTime = new Date().toString();
        setField('operating-system', osInfo.name || 'Unknown');
        setField('os-version', osInfo.version || 'Unknown');
        setField('architecture', architecture);
        setField('cpu-cores', cores ? String(cores) : 'Unknown');
        setField('device-memory', memory ? memory + ' GB' : 'Unknown');
        setField('user-agent', ua);
        setField('local-time', localTime);
        setField('languages', languages.length ? languages.join(', ') : 'Unknown');
        return {
          platform: platformValue,
          os: osInfo.name,
          osVersion: osVersionValue,
          architecture,
          hardwareConcurrency: cores ?? undefined,
          deviceMemory: memory ?? undefined,
          userAgent: ua,
          localTime,
          language: navigator.language || undefined,
          languages,
        };
      }

      function gatherNetworkInfo() {
        addActivity('Inspecting network connection');
        const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        const connectionType = connection?.type || connection?.connectionType || 'Unknown';
        const effectiveType = connection?.effectiveType || 'Unknown';
        const downlink = connection?.downlink;
        const rtt = connection?.rtt;
        const saveData = connection?.saveData;
        setField('network-type', connectionType);
        setField('effective-type', effectiveType);
        setField('downlink', formatDownlink(downlink));
        setField('rtt', formatRTT(rtt));
        setField('save-data', saveData === undefined ? 'Unknown' : (saveData ? 'Enabled' : 'Disabled'));
        return {
          connectionType,
          effectiveType,
          downlink: typeof downlink === 'number' ? downlink : undefined,
          rtt: typeof rtt === 'number' ? rtt : undefined,
          saveData,
        };
      }

      async function gatherHardwareInfo() {
        addActivity('Assessing hardware metrics');
        const screen = window.screen || {};
        const width = Number(screen.width) || 0;
        const height = Number(screen.height) || 0;
        const colorDepth = Number(screen.colorDepth) || null;
        const pixelDepth = Number(screen.pixelDepth) || null;
        const viewport = { width: window.innerWidth || 0, height: window.innerHeight || 0 };
        const pixelRatio = window.devicePixelRatio || 1;
        const touchSupport = {
          maxTouchPoints: navigator.maxTouchPoints ?? 0,
          touchEvent: 'ontouchstart' in window,
          pointerEvent: window.PointerEvent ? true : false,
        };

        setField('screen-resolution', width && height ? width + ' x ' + height : 'Unknown');
        setField('viewport-size', viewport.width && viewport.height ? viewport.width + ' x ' + viewport.height : 'Unknown');
        setField('color-depth', colorDepth ? colorDepth + '-bit' : 'Unknown');
        setField('pixel-ratio', pixelRatio ? pixelRatio.toFixed(2) : 'Unknown');
        setField('touch-support', describeTouchSupport(touchSupport.maxTouchPoints));

        const gpu = (() => {
          try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return { vendor: undefined, renderer: undefined };
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (!debugInfo) return { vendor: undefined, renderer: undefined };
            const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
            const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            return { vendor, renderer };
          } catch (error) {
            console.warn('Unable to query GPU info:', error);
            return { vendor: undefined, renderer: undefined };
          }
        })();

        const gpuLabel = gpu.vendor || gpu.renderer ? [gpu.vendor, gpu.renderer].filter(Boolean).join(' • ') : 'Unavailable';
        setField('gpu', gpuLabel || 'Unavailable');

        let battery = null;
        if (navigator.getBattery) {
          try {
            battery = await navigator.getBattery();
          } catch (error) {
            console.warn('Unable to access battery manager:', error);
          }
        }
        setField('battery', describeBattery(battery));

        const normalizeBatteryTime = (value) => (Number.isFinite(value) && value >= 0 ? value : undefined);
        const normalizeBatteryLevel = (value) => (Number.isFinite(value) ? Math.min(Math.max(value, 0), 1) : undefined);

        let audioDevices;
        let videoDevices;
        if (navigator.mediaDevices?.enumerateDevices) {
          try {
            const devices = await navigator.mediaDevices.enumerateDevices();
            audioDevices = devices.filter((d) => d.kind === 'audioinput').length;
            videoDevices = devices.filter((d) => d.kind === 'videoinput').length;
          } catch (error) {
            console.warn('Unable to enumerate media devices:', error);
          }
        }
        setField('audio-devices', audioDevices === undefined ? 'Unavailable' : audioDevices + ' inputs');
        setField('video-devices', videoDevices === undefined ? 'Unavailable' : videoDevices + ' inputs');

        return {
          screen: {
            width,
            height,
            colorDepth: colorDepth ?? undefined,
            pixelDepth: pixelDepth ?? undefined,
          },
          viewport,
          pixelRatio,
          touchSupport,
          gpu,
          battery: battery
            ? {
                charging: battery.charging,
                chargingTime: normalizeBatteryTime(battery.chargingTime),
                dischargingTime: normalizeBatteryTime(battery.dischargingTime),
                level: normalizeBatteryLevel(battery.level),
              }
            : undefined,
          audioDevices,
          videoDevices,
        };
      }

      async function gatherFeaturesInfo() {
        addActivity('Interrogating browser capabilities');
        const cookiesEnabled = navigator.cookieEnabled;
        const javaScriptEnabled = true;
        const serviceWorkerSupported = 'serviceWorker' in navigator;
        let serviceWorkerStatus = serviceWorkerSupported ? 'Supported' : 'Unsupported';
        if (serviceWorkerSupported) {
          try {
            const registration = await navigator.serviceWorker.getRegistration();
            if (registration) {
              serviceWorkerStatus = 'Registered';
            } else if (navigator.serviceWorker.controller) {
              serviceWorkerStatus = 'Active';
            }
          } catch (error) {
            console.warn('Service worker status unavailable:', error);
          }
        }
        const mediaDevices = !!navigator.mediaDevices;
        let storageEstimateRaw;
        if (navigator.storage?.estimate) {
          try {
            storageEstimateRaw = await navigator.storage.estimate();
          } catch (error) {
            console.warn('Storage estimate unavailable:', error);
          }
        }
        const normalizeStorage = (estimate) => {
          if (!estimate) return undefined;
          const quota = Number.isFinite(estimate.quota) ? estimate.quota : undefined;
          const usage = Number.isFinite(estimate.usage) ? estimate.usage : undefined;
          if (quota === undefined && usage === undefined) {
            return undefined;
          }
          return { quota, usage };
        };
        const storageEstimate = normalizeStorage(storageEstimateRaw);
        setField('cookies-enabled', cookiesEnabled ? 'Enabled' : 'Disabled');
        setField('javascript-enabled', javaScriptEnabled ? 'Enabled' : 'Disabled');
        setField('service-worker', serviceWorkerStatus);
        setField('media-devices', mediaDevices ? 'Available' : 'Unavailable');
        setField('storage-estimate', formatStorage(storageEstimate));
        return {
          cookiesEnabled,
          javaScriptEnabled,
          serviceWorkerStatus,
          mediaDevices,
          storageEstimate,
        };
      }

      function updateLastUpdated() {
        const timestamp = new Date().toLocaleString();
        setField('last-updated', timestamp);
      }

      async function collectTelemetry() {
        if (state.collecting) return;
        state.collecting = true;
        state.activityLog = [];
        renderActivity();
        addActivity('Starting device diagnostics');

        try {
          if (exportBtn) {
            exportBtn.disabled = true;
          }
          updateConsentStatus();
          const identifiers = await gatherIdentifiers();
          const system = gatherSystemInfo();
          const network = gatherNetworkInfo();
          const hardware = await gatherHardwareInfo();
          const features = await gatherFeaturesInfo();
          updateLastUpdated();

          const payload = {
            identifiers,
            system,
            network,
            hardware,
            features,
            activityLog: [...state.activityLog],
            consentGranted: state.consentGranted,
          };

          state.latestPayload = payload;
          if (exportBtn) {
            exportBtn.disabled = false;
          }

          addActivity('Transmitting telemetry payload');
          await fetch('/api/telemetry', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            keepalive: true,
          });
          addActivity('Telemetry successfully logged');
        } catch (error) {
          console.error('Telemetry collection failed:', error);
          addActivity('Telemetry collection failed: ' + (error?.message || 'Unexpected error'));
        } finally {
          state.collecting = false;
        }
      }

      function exportReport() {
        if (!state.latestPayload) return;
        try {
          const blob = new Blob([JSON.stringify(state.latestPayload, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
          link.download = 'device-telemetry-' + timestamp + '.json';
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          URL.revokeObjectURL(url);
          addActivity('Downloaded local telemetry snapshot');
        } catch (error) {
          console.error('Unable to export telemetry:', error);
        }
      }

      refreshBtn?.addEventListener('click', () => {
        collectTelemetry();
      });

      exportBtn?.addEventListener('click', () => {
        exportReport();
      });

      if (consentRequired) {
        banner?.classList.add('active');
        updateConsentStatus();
        button?.addEventListener('click', () => {
          state.consentGranted = true;
          updateConsentStatus();
          banner?.classList.remove('active');
          collectTelemetry();
        });
      } else {
        collectTelemetry();
      }
    })();
  </script>
</body>
</html>`;
}

app.get('/healthz', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/', (req, res) => {
  res.type('html').send(renderLandingPage(CONSENT_REQUIRED));
  logVisit(req, { event: 'pageview' }).catch((error) => {
    console.error('Failed to log page view:', error);
  });
});

app.post('/api/telemetry', async (req, res) => {
  try {
    const telemetry = telemetrySchema.parse(req.body);
    await logVisit(req, { event: 'telemetry', telemetry });
    res.status(204).end();
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.warn('Invalid telemetry payload received:', error.flatten());
      res.status(400).json({ error: 'Invalid payload', details: error.flatten() });
      return;
    }
    console.error('Unexpected error while processing telemetry:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`device-logger listening on port ${PORT}`);
});
