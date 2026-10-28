import { randomBytes } from 'node:crypto';

export const newId = (prefix) => `${prefix}_${randomBytes(5).toString('hex')}`;
export const newSecret = () => `whsec_${randomBytes(18).toString('hex')}`;

const MAX_EVENTS = 500;

// ---------------------------------------------------------------- memory ----
// Used when no DATABASE_URL is set (local dev, tests) and as a fallback if the
// database is unreachable, so the demo never goes down with it.
export function createMemoryStore() {
  const endpoints = new Map();
  let events = [];
  const attempts = [];

  return {
    kind: 'memory',
    async init() {},

    async createEndpoint({ name, targetUrl, secret }) {
      const ep = { id: newId('ep'), name, targetUrl, secret: secret || newSecret(), createdAt: new Date().toISOString() };
      endpoints.set(ep.id, ep);
      return ep;
    },
    async listEndpoints() {
      return [...endpoints.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    },
    async getEndpoint(id) {
      return endpoints.get(id) || null;
    },
    async deleteEndpoint(id) {
      const had = endpoints.delete(id);
      events = events.filter((e) => e.endpointId !== id);
      return had;
    },

    async insertEvent({ endpointId, headers, body }) {
      const now = new Date().toISOString();
      const ev = {
        id: newId('evt'), endpointId, receivedAt: now, headers, body,
        status: 'pending', attempts: 0, nextAttemptAt: now, lastStatus: null, lastError: null, deliveredAt: null,
      };
      events.push(ev);
      if (events.length > MAX_EVENTS) events = events.slice(-MAX_EVENTS);
      return ev;
    },
    async claimDue(limit, now = Date.now()) {
      const due = events
        .filter((e) => e.status === 'pending' && Date.parse(e.nextAttemptAt) <= now)
        .sort((a, b) => a.nextAttemptAt.localeCompare(b.nextAttemptAt))
        .slice(0, limit);
      for (const e of due) {
        e.status = 'delivering';
        e.claimedAt = now;
      }
      return due.map((e) => ({ ...e }));
    },
    async requeueStale(olderThanMs) {
      const cutoff = Date.now() - olderThanMs;
      let n = 0;
      for (const e of events) {
        if (e.status === 'delivering' && e.claimedAt < cutoff) {
          e.status = 'pending';
          n += 1;
        }
      }
      return n;
    },
    async recordAttempt(eventId, { ok, status, ms, snippet, error }, update) {
      attempts.push({ eventId, at: new Date().toISOString(), ok, status, ms, snippet, error });
      const e = events.find((x) => x.id === eventId);
      if (!e) return;
      e.attempts += 1;
      e.status = update.status;
      e.nextAttemptAt = update.nextAttemptAt;
      e.lastStatus = status ?? null;
      e.lastError = error || null;
      e.deliveredAt = update.status === 'delivered' ? new Date().toISOString() : e.deliveredAt;
    },
    async requeue(id) {
      const e = events.find((x) => x.id === id);
      if (!e || e.status === 'delivering') return null;
      e.status = 'pending';
      e.attempts = 0;
      e.nextAttemptAt = new Date().toISOString();
      return { ...e };
    },
    async getEvent(id) {
      const e = events.find((x) => x.id === id);
      if (!e) return null;
      const { claimedAt, ...rest } = e;
      return { ...rest, attemptLog: attempts.filter((a) => a.eventId === id) };
    },
    async listEvents({ endpointId, status, limit = 50 } = {}) {
      return events
        .filter((e) => (!endpointId || e.endpointId === endpointId) && (!status || e.status === status))
        .sort((a, b) => b.receivedAt.localeCompare(a.receivedAt))
        .slice(0, limit)
        .map(({ body, claimedAt, ...rest }) => ({ ...rest, size: body.length }));
    },
    async stats() {
      const out = { total: events.length, pending: 0, delivering: 0, delivered: 0, dead: 0 };
      for (const e of events) out[e.status] += 1;
      return out;
    },
  };
}

// -------------------------------------------------------------- postgres ----
const SCHEMA = `
CREATE TABLE IF NOT EXISTS endpoints (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  target_url  text NOT NULL,
  secret      text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS events (
  id              text PRIMARY KEY,
  endpoint_id     text NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  received_at     timestamptz NOT NULL DEFAULT now(),
  headers         jsonb NOT NULL DEFAULT '{}',
  body            text NOT NULL,
  status          text NOT NULL DEFAULT 'pending',
  attempts        int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  claimed_at      timestamptz,
  last_status     int,
  last_error      text,
  delivered_at    timestamptz
);
CREATE INDEX IF NOT EXISTS events_due_idx ON events (next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS events_received_idx ON events (received_at DESC);
CREATE TABLE IF NOT EXISTS attempts (
  id        bigserial PRIMARY KEY,
  event_id  text NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  at        timestamptz NOT NULL DEFAULT now(),
  ok        boolean NOT NULL,
  status    int,
  ms        int,
  snippet   text,
  error     text
);
CREATE INDEX IF NOT EXISTS attempts_event_idx ON attempts (event_id);
`;

const iso = (v) => (v instanceof Date ? v.toISOString() : v);
const mapEndpoint = (r) => ({ id: r.id, name: r.name, targetUrl: r.target_url, secret: r.secret, createdAt: iso(r.created_at) });
const mapEvent = (r) => ({
  id: r.id, endpointId: r.endpoint_id, receivedAt: iso(r.received_at), headers: r.headers, body: r.body,
  status: r.status, attempts: r.attempts, nextAttemptAt: iso(r.next_attempt_at),
  lastStatus: r.last_status, lastError: r.last_error, deliveredAt: iso(r.delivered_at),
});

export async function createPostgresStore(connectionString) {
  const { default: pg } = await import('pg');
  const ssl = /localhost|127\.0\.0\.1/.test(connectionString) ? false : { rejectUnauthorized: false };
  const pool = new pg.Pool({ connectionString, ssl, max: 5, connectionTimeoutMillis: 8000 });
  const q = (text, params) => pool.query(text, params);

  return {
    kind: 'postgres',
    async init() {
      await q(SCHEMA);
    },

    async createEndpoint({ name, targetUrl, secret }) {
      const { rows } = await q(
        'INSERT INTO endpoints (id, name, target_url, secret) VALUES ($1,$2,$3,$4) RETURNING *',
        [newId('ep'), name, targetUrl, secret || newSecret()],
      );
      return mapEndpoint(rows[0]);
    },
    async listEndpoints() {
      const { rows } = await q('SELECT * FROM endpoints ORDER BY created_at');
      return rows.map(mapEndpoint);
    },
    async getEndpoint(id) {
      const { rows } = await q('SELECT * FROM endpoints WHERE id = $1', [id]);
      return rows[0] ? mapEndpoint(rows[0]) : null;
    },
    async deleteEndpoint(id) {
      const { rowCount } = await q('DELETE FROM endpoints WHERE id = $1', [id]);
      return rowCount > 0;
    },

    async insertEvent({ endpointId, headers, body }) {
      const { rows } = await q(
        'INSERT INTO events (id, endpoint_id, headers, body) VALUES ($1,$2,$3,$4) RETURNING *',
        [newId('evt'), endpointId, JSON.stringify(headers), body],
      );
      // Keep the table small on a free instance.
      await q(
        'DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY received_at DESC OFFSET $1)',
        [MAX_EVENTS],
      );
      return mapEvent(rows[0]);
    },
    // SKIP LOCKED lets several workers pull from the same queue without
    // delivering an event twice.
    async claimDue(limit) {
      const { rows } = await q(
        `UPDATE events SET status = 'delivering', claimed_at = now()
         WHERE id IN (
           SELECT id FROM events
           WHERE status = 'pending' AND next_attempt_at <= now()
           ORDER BY next_attempt_at
           LIMIT $1
           FOR UPDATE SKIP LOCKED
         ) RETURNING *`,
        [limit],
      );
      return rows.map(mapEvent);
    },
    async requeueStale(olderThanMs) {
      const { rowCount } = await q(
        `UPDATE events SET status = 'pending'
         WHERE status = 'delivering' AND claimed_at < now() - ($1 || ' milliseconds')::interval`,
        [String(olderThanMs)],
      );
      return rowCount;
    },
    async recordAttempt(eventId, { ok, status, ms, snippet, error }, update) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(
          'INSERT INTO attempts (event_id, ok, status, ms, snippet, error) VALUES ($1,$2,$3,$4,$5,$6)',
          [eventId, ok, status ?? null, ms ?? null, snippet ?? null, error ?? null],
        );
        await client.query(
          `UPDATE events SET attempts = attempts + 1, status = $2, next_attempt_at = $3,
             last_status = $4, last_error = $5,
             delivered_at = CASE WHEN $2 = 'delivered' THEN now() ELSE delivered_at END
           WHERE id = $1`,
          [eventId, update.status, update.nextAttemptAt, status ?? null, error ?? null],
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    },
    async requeue(id) {
      const { rows } = await q(
        `UPDATE events SET status = 'pending', attempts = 0, next_attempt_at = now()
         WHERE id = $1 AND status <> 'delivering' RETURNING *`,
        [id],
      );
      return rows[0] ? mapEvent(rows[0]) : null;
    },
    async getEvent(id) {
      const { rows } = await q('SELECT * FROM events WHERE id = $1', [id]);
      if (!rows[0]) return null;
      const log = await q('SELECT at, ok, status, ms, snippet, error FROM attempts WHERE event_id = $1 ORDER BY id', [id]);
      return { ...mapEvent(rows[0]), attemptLog: log.rows.map((a) => ({ ...a, at: iso(a.at) })) };
    },
    async listEvents({ endpointId, status, limit = 50 } = {}) {
      const { rows } = await q(
        `SELECT *, length(body) AS size FROM events
         WHERE ($1::text IS NULL OR endpoint_id = $1) AND ($2::text IS NULL OR status = $2)
         ORDER BY received_at DESC LIMIT $3`,
        [endpointId || null, status || null, limit],
      );
      return rows.map(({ body, ...r }) => ({ ...mapEvent({ ...r, body: '' }), body: undefined, size: r.size }));
    },
    async stats() {
      const { rows } = await q('SELECT status, count(*)::int AS n FROM events GROUP BY status');
      const out = { total: 0, pending: 0, delivering: 0, delivered: 0, dead: 0 };
      for (const r of rows) {
        out[r.status] = r.n;
        out.total += r.n;
      }
      return out;
    },
  };
}
