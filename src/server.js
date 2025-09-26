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
const LOG_TO_FILE = (process.env.LOG_TO_FILE ?? 'false').toLowerCase() === 'true';
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
    screen: z
      .object({
        width: z.number().int().nonnegative(),
        height: z.number().int().nonnegative(),
        colorDepth: z.number().int().nonnegative().optional(),
        pixelDepth: z.number().int().nonnegative().optional(),
      })
      .strict(),
    timezone: z.string().min(1).max(100),
    language: z.string().min(1).max(64).optional(),
    languages: z.array(z.string().min(1).max(64)).max(16).optional(),
    platform: z.string().min(1).max(128).optional(),
    hardwareConcurrency: z.number().int().positive().max(512).optional(),
    deviceMemory: z.number().positive().max(1024).optional(),
    userAgent: z.string().min(1).max(2048).optional(),
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
  const fileName = `visits-${now.toISOString().slice(0, 10)}.jsonl`;
  const filePath = path.join(LOG_DIR, fileName);
  try {
    await fs.appendFile(filePath, line, 'utf8');
  } catch (error) {
    console.error('Failed to append visit log:', error);
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
  const title = 'Device Logger';
  const description = 'A minimal diagnostic endpoint that records basic device metadata for security investigations.';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #0f172a; background: #f8fafc; }
    main { max-width: 720px; margin: 0 auto; background: #ffffff; padding: 2rem; border-radius: 1rem; box-shadow: 0 20px 45px rgba(15, 23, 42, 0.12); }
    h1 { font-size: 2.5rem; margin-bottom: 0.5rem; }
    p { line-height: 1.6; }
    .consent-banner { display: none; margin-top: 1.5rem; padding: 1rem 1.5rem; border-radius: 0.75rem; background: #e0f2fe; }
    .consent-banner.active { display: block; }
    button { border: none; background: #2563eb; color: #fff; padding: 0.75rem 1.25rem; border-radius: 999px; font-size: 1rem; cursor: pointer; }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <main>
    <h1>${title}</h1>
    <p>${description}</p>
    <p>This page collects a minimal telemetry snapshot consisting of screen size, timezone, language, and similar non-invasive client hints. The data is used strictly for diagnostics and abuse prevention.</p>
    <section class="consent-banner" id="consent-banner">
      <p>We use this telemetry to detect suspicious activity. Click below to share device details.</p>
      <button id="consent-button" type="button">Share device details</button>
    </section>
  </main>
  <script>
    (function () {
      const consentRequired = ${consentRequired ? 'true' : 'false'};
      const banner = document.getElementById('consent-banner');
      const button = document.getElementById('consent-button');
      let hasSubmitted = false;

      function collectTelemetry() {
        if (hasSubmitted) return;
        hasSubmitted = true;
        const screen = window.screen || {};
        const payload = {
          screen: {
            width: Number(screen.width) || 0,
            height: Number(screen.height) || 0,
            colorDepth: Number(screen.colorDepth) || undefined,
            pixelDepth: Number(screen.pixelDepth) || undefined,
          },
          timezone: (Intl.DateTimeFormat().resolvedOptions().timeZone) || 'unknown',
          language: navigator.language || undefined,
          languages: Array.isArray(navigator.languages) ? navigator.languages.slice(0, 16) : undefined,
          platform: navigator.platform || undefined,
          hardwareConcurrency: navigator.hardwareConcurrency || undefined,
          deviceMemory: navigator.deviceMemory || undefined,
          userAgent: navigator.userAgent || undefined,
          consentGranted: consentRequired ? true : false,
        };

        fetch('/api/telemetry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          keepalive: true,
        }).catch(() => {});
      }

      if (consentRequired) {
        banner.classList.add('active');
        button?.addEventListener('click', function () {
          collectTelemetry();
          banner.classList.remove('active');
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
