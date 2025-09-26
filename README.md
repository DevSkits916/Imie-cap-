
# Hood-Rat-trap	# Device Logger
Find stolen phones 	
A minimal Express application that captures basic visit metadata and client-provided device details for diagnostics and abuse prevention. Designed for deployment on [Render](https://render.com) with secure defaults and optional client consent gating.

## Features

- Logs hashed IP, selected headers, and parsed user-agent data for each page view.
- Collects non-invasive client hints (screen size, timezone, language, platform, hardware concurrency, optional device memory).
- Persists visit records as JSON lines per day on disk and streams structured lines to stdout.
- Protects endpoints with Helmet, rate limiting, strict JSON/body size limits, and schema validation via Zod.
- Consent banner controlled via `CONSENT_REQUIRED` environment variable (default `false`).
- Includes `/healthz` endpoint for platform checks and a simple landing page that auto-posts telemetry when allowed.

## Getting Started

```bash
npm install
npm start
```

The app listens on port `10000` by default. Configure via environment variables as needed.

## Environment Variables

See [`.env.example`](./.env.example) for defaults:

- `NODE_ENV` – Node environment (`development`, `production`, etc.).
- `LOG_TO_FILE` – When `true`, append visit logs to disk under `LOG_DIR`.
- `LOG_DIR` – Directory for JSONL visit logs (defaults to `./data/logs`). Ensure it exists or mount a persistent volume.
- `IP_HASH_SALT` – Required secret salt for hashing IP addresses before storage.
- `CONSENT_REQUIRED` – When `true`, visitors must click consent before client telemetry is sent.
- `PORT` – Port to bind the HTTP server (defaults to `10000`).

## Deployment on Render

1. Create a new **Web Service** from this repository.
2. Set the runtime to **Node** with build command `npm install` and start command `npm start`.
3. Add a persistent **Disk** named `device-logger-disk`, mount path `/data`, size `1 GB`.
4. Configure environment variables:
   - `LOG_TO_FILE=true`
   - `LOG_DIR=/data/logs`
   - `IP_HASH_SALT=<long-random-string>`
   - `CONSENT_REQUIRED=false` (set to `true` if you want a consent banner)
5. Set the health check path to `/healthz`.
6. Deploy. Visit logs will appear in Render logs and persist under `/data/logs/visits-YYYY-MM-DD.jsonl` on the attached disk.

## Privacy Notes

- All IP addresses are hashed with a secret salt before logging.
- Only basic device information is collected; no invasive fingerprinting techniques are used.
- Server-side request metadata is logged on every hit for standard operational monitoring.
