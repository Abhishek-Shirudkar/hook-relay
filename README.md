# HookRelay: reliable webhook delivery

Receives webhooks, queues them, and delivers them to your destination with automatic retries and backoff. A live dashboard shows every event and every delivery attempt, and any event can be replayed.

**Stack:** Node.js 20+ (plain `node:http`, no framework) and MongoDB. The only dependency is the official `mongodb` driver.

## What it does

1. **Ingest:** `POST /hook/<endpoint-id>` accepts a payload (up to 100 KB), stores it, and answers `202` straight away. If you send an `X-Signature: sha256=<hmac>` header it is verified, and bad signatures get `401`.
2. **Queue:** events wait in MongoDB. Workers claim due events with an atomic `findOneAndUpdate`, so several workers can run without delivering the same event twice. Events stuck mid-delivery (a crashed worker) go back to the queue after 60 s.
3. **Deliver:** each attempt is a signed `POST` (`X-HookRelay-Signature: sha256=<hmac of the body>`) with an 8 s timeout. Any 2xx counts as delivered.
4. **Retry:** failures retry after 5 s, 15 s, 45 s, 2 min and 5 min. After 5 failed attempts the event is marked **dead** and stays visible for inspection.
5. **Inspect and replay:** the dashboard lists events, shows each attempt (status code, time, response snippet) and has a Replay button.

## Safety

- **SSRF protection:** destinations must be public `http(s)` URLs. The host is resolved and rejected if any address is private, loopback, link-local or otherwise internal. This is checked when an endpoint is created and again before every delivery, and redirects are never followed.
- **Limits:** 100 KB payloads, 20 endpoints, 500 stored events, per-IP rate limits on ingest and admin writes.
- **Optional admin token:** set `ADMIN_TOKEN` and every `/api/*` call needs `Authorization: Bearer <token>`. The public ingest URLs stay open. Without it (the public demo) anyone can use the dashboard, so don't send real data.
- If MongoDB is unreachable at start-up the server falls back to in-memory storage instead of going down.

## Try the retries (in the dashboard)

The demo endpoint delivers to a built-in destination. Set it to **failing**, click **Send test event** a few times, and watch the events retry with growing delays. Switch it back to **healthy** and they are delivered on their next retry.

## Run it locally

```bash
cd server
npm install
npm start            # http://localhost:4300, in-memory storage
# with MongoDB:
MONGODB_URI=mongodb://localhost:27017/hookrelay npm start
npm test             # 13 tests, no database needed
```

Send a test webhook:

```bash
curl -X POST http://localhost:4300/hook/<endpoint-id> \
  -H 'content-type: application/json' -d '{"type":"order.created","id":42}'
```

## Verifying deliveries on the receiving side

```js
import { createHmac, timingSafeEqual } from 'node:crypto';
const expected = 'sha256=' + createHmac('sha256', SECRET).update(rawBody).digest('hex');
const ok = timingSafeEqual(Buffer.from(expected), Buffer.from(req.headers['x-hookrelay-signature'] || ''));
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `MONGODB_URI` | none | MongoDB connection string (Atlas free tier works). Without it, data lives in memory |
| `ADMIN_TOKEN` | none | Protects the dashboard API |
| `PORT` | `4300` | Port to listen on |

## Deploying (Render)

Create a Web Service from this repo with root directory `server`, build command `npm install`, start command `npm start`. Optionally create a free MongoDB Atlas cluster and set `MONGODB_URI` to its connection string.

## Known limits and next steps

- A destination's DNS could change between the address check and the request (DNS rebinding). Pinning the resolved IP for the request closes that gap.
- Delivery is at-least-once: a receiver that responds slowly after processing may see a retry. Receivers should de-duplicate on the `X-HookRelay-Event` header.
- Next steps: per-endpoint retry settings, payload filtering, a dead-letter alert by email, and multi-tenant accounts.
