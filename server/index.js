import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';
import { createMemoryStore, createPostgresStore } from './store.js';
import { createDemoTarget, startWorker } from './relay.js';
import { checkTarget, createLimiter, verify } from './security.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MAX_BODY = 100 * 1024;
const MAX_ENDPOINTS = 20;

const json = (res, status, data) => {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
};

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function readBody(req, limit = MAX_BODY) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooBig = false;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (tooBig) return; // keep draining so the client can read our 413
      if (size > limit) {
        tooBig = true;
        chunks.length = 0;
        reject(new HttpError(413, `Payload too large (limit ${limit / 1024} KB)`));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const raw = await readBody(req, 8 * 1024);
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    throw new HttpError(400, 'Request body must be valid JSON');
  }
}

const KEEP_HEADERS = /^(content-type|user-agent|x-[a-z0-9-]+)$/i;
const pickHeaders = (h) => Object.fromEntries(Object.entries(h).filter(([k]) => KEEP_HEADERS.test(k) && !/signature/i.test(k)));

// Hide secrets from list responses; the creation response shows it once.
const publicEndpoint = (ep, withSecret = false) => ({
  id: ep.id, name: ep.name, targetUrl: ep.targetUrl, createdAt: ep.createdAt,
  secret: withSecret ? ep.secret : `${ep.secret.slice(0, 9)}…`,
});

export function createApp({ store, demo, adminToken = '', ingestLimit = 120, adminLimit = 90 }) {
  const ingestAllowed = createLimiter(ingestLimit, 60_000);
  const adminAllowed = createLimiter(adminLimit, 60_000);

  async function handle(req, res) {
    const url = new URL(req.url, 'http://x');
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const route = `${req.method} ${url.pathname}`;

    // Static dashboard
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      const html = await readFile(path.join(HERE, 'public', 'index.html'));
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(html);
    }
    if (route === 'GET /api/health') return json(res, 200, { ok: true, db: store.kind, authRequired: Boolean(adminToken) });

    // Public ingest endpoint: POST /hook/:endpointId
    const hook = url.pathname.match(/^\/hook\/([\w-]+)$/);
    if (hook) {
      if (req.method !== 'POST') throw new HttpError(405, 'Send webhooks with POST');
      if (!ingestAllowed(ip)) throw new HttpError(429, 'Too many requests, slow down');
      const ep = await store.getEndpoint(hook[1]);
      if (!ep) throw new HttpError(404, 'Unknown endpoint');
      const body = await readBody(req);
      if (!body) throw new HttpError(400, 'Empty body');
      const sig = req.headers['x-signature'];
      if (sig && !verify(ep.secret, body, sig)) throw new HttpError(401, 'Invalid signature');
      const ev = await store.insertEvent({ endpointId: ep.id, headers: pickHeaders(req.headers), body });
      return json(res, 202, { id: ev.id, status: 'queued' });
    }

    // Everything under /api needs the admin token when one is configured.
    if (url.pathname.startsWith('/api/')) {
      if (adminToken && req.headers.authorization !== `Bearer ${adminToken}`) throw new HttpError(401, 'Admin token required');
      if (req.method !== 'GET' && !adminAllowed(ip)) throw new HttpError(429, 'Too many requests, slow down');
    }

    if (route === 'GET /api/stats') return json(res, 200, await store.stats());
    if (route === 'GET /api/demo') return json(res, 200, { healthy: demo.healthy });
    if (route === 'POST /api/demo/health') {
      const { healthy } = await readJson(req);
      demo.healthy = Boolean(healthy);
      return json(res, 200, { healthy: demo.healthy });
    }

    if (route === 'GET /api/endpoints') {
      return json(res, 200, (await store.listEndpoints()).map((e) => publicEndpoint(e)));
    }
    if (route === 'POST /api/endpoints') {
      const { name, targetUrl, secret } = await readJson(req);
      const cleanName = String(name || '').trim().slice(0, 60);
      if (!cleanName) throw new HttpError(400, 'Name is required');
      if ((await store.listEndpoints()).length >= MAX_ENDPOINTS) throw new HttpError(409, `Limit of ${MAX_ENDPOINTS} endpoints reached. Delete one first.`);
      const target = String(targetUrl || '').trim();
      if (target !== 'demo') {
        try {
          await checkTarget(target);
        } catch (err) {
          throw new HttpError(400, err.message);
        }
      }
      const ep = await store.createEndpoint({ name: cleanName, targetUrl: target, secret: secret ? String(secret).slice(0, 100) : undefined });
      return json(res, 201, publicEndpoint(ep, true));
    }
    const epMatch = url.pathname.match(/^\/api\/endpoints\/([\w-]+)$/);
    if (epMatch && req.method === 'DELETE') {
      const ok = await store.deleteEndpoint(epMatch[1]);
      return json(res, ok ? 200 : 404, { ok });
    }

    if (route === 'GET /api/events') {
      const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 200);
      const events = await store.listEvents({
        endpointId: url.searchParams.get('endpointId') || undefined,
        status: url.searchParams.get('status') || undefined,
        limit,
      });
      return json(res, 200, events);
    }
    const evMatch = url.pathname.match(/^\/api\/events\/([\w-]+)(\/replay)?$/);
    if (evMatch && req.method === 'GET' && !evMatch[2]) {
      const ev = await store.getEvent(evMatch[1]);
      return ev ? json(res, 200, ev) : json(res, 404, { error: 'Event not found' });
    }
    if (evMatch && req.method === 'POST' && evMatch[2]) {
      const ev = await store.requeue(evMatch[1]);
      return ev ? json(res, 202, { id: ev.id, status: 'queued' }) : json(res, 409, { error: 'Event not found or currently being delivered' });
    }

    throw new HttpError(404, 'Not found');
  }

  return http.createServer(async (req, res) => {
    try {
      await handle(req, res);
    } catch (err) {
      if (res.headersSent) return res.end();
      const status = err.status || 500;
      if (status === 500) console.error(err);
      json(res, status, { error: status === 500 ? 'Internal error' : err.message });
    }
  });
}

export async function createStore(databaseUrl = process.env.DATABASE_URL) {
  if (databaseUrl) {
    try {
      const store = await createPostgresStore(databaseUrl);
      await store.init();
      return store;
    } catch (err) {
      console.error('Postgres unavailable, falling back to in-memory storage:', err.message);
    }
  }
  const store = createMemoryStore();
  await store.init();
  return store;
}

// Gives a fresh instance something to look at: one endpoint pointed at the demo destination.
async function seed(store) {
  if ((await store.listEndpoints()).length === 0) {
    await store.createEndpoint({ name: 'Demo endpoint', targetUrl: 'demo' });
  }
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const store = await createStore();
  await seed(store);
  const demo = createDemoTarget();
  startWorker(store, { demo });
  const port = Number(process.env.PORT) || 4300;
  createApp({ store, demo, adminToken: process.env.ADMIN_TOKEN || '' }).listen(port, () => {
    console.log(`HookRelay listening on :${port} (storage: ${store.kind})`);
  });
}
