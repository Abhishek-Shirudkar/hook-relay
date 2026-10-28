import { randomBytes } from 'node:crypto';

export const newId = (prefix) => `${prefix}_${randomBytes(5).toString('hex')}`;
export const newSecret = () => `whsec_${randomBytes(18).toString('hex')}`;

const MAX_EVENTS = 500;

// ---------------------------------------------------------------- memory ----
// Used when no MONGODB_URI is set (local dev, tests) and as a fallback if the
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

// ---------------------------------------------------------------- mongodb ----
const toIso = (v) => (v instanceof Date ? v.toISOString() : v ?? null);
const mapEndpoint = (d) => ({ id: d._id, name: d.name, targetUrl: d.targetUrl, secret: d.secret, createdAt: toIso(d.createdAt) });
const mapEvent = (d) => ({
  id: d._id, endpointId: d.endpointId, receivedAt: toIso(d.receivedAt), headers: d.headers, body: d.body,
  status: d.status, attempts: d.attempts, nextAttemptAt: toIso(d.nextAttemptAt),
  lastStatus: d.lastStatus ?? null, lastError: d.lastError ?? null, deliveredAt: toIso(d.deliveredAt),
});

export async function createMongoStore(uri, dbName) {
  const { MongoClient } = await import('mongodb');
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 8000, maxPoolSize: 5 });
  await client.connect();
  const db = dbName ? client.db(dbName) : client.db();
  const endpoints = db.collection('endpoints');
  const events = db.collection('events');
  const attempts = db.collection('attempts');

  return {
    kind: 'mongodb',
    async init() {
      await events.createIndex({ status: 1, nextAttemptAt: 1 });
      await events.createIndex({ receivedAt: -1 });
      await events.createIndex({ endpointId: 1 });
      await attempts.createIndex({ eventId: 1, at: 1 });
    },

    async createEndpoint({ name, targetUrl, secret }) {
      const doc = { _id: newId('ep'), name, targetUrl, secret: secret || newSecret(), createdAt: new Date() };
      await endpoints.insertOne(doc);
      return mapEndpoint(doc);
    },
    async listEndpoints() {
      return (await endpoints.find().sort({ createdAt: 1 }).toArray()).map(mapEndpoint);
    },
    async getEndpoint(id) {
      const d = await endpoints.findOne({ _id: id });
      return d ? mapEndpoint(d) : null;
    },
    async deleteEndpoint(id) {
      const { deletedCount } = await endpoints.deleteOne({ _id: id });
      const ids = (await events.find({ endpointId: id }, { projection: { _id: 1 } }).toArray()).map((e) => e._id);
      if (ids.length) {
        await events.deleteMany({ _id: { $in: ids } });
        await attempts.deleteMany({ eventId: { $in: ids } });
      }
      return deletedCount > 0;
    },

    async insertEvent({ endpointId, headers, body }) {
      const now = new Date();
      const doc = {
        _id: newId('evt'), endpointId, receivedAt: now, headers, body,
        status: 'pending', attempts: 0, nextAttemptAt: now, claimedAt: null,
        lastStatus: null, lastError: null, deliveredAt: null,
      };
      await events.insertOne(doc);
      // Keep the collection small on a free cluster.
      const old = await events.find({}, { projection: { _id: 1 } }).sort({ receivedAt: -1 }).skip(MAX_EVENTS).toArray();
      if (old.length) {
        const ids = old.map((e) => e._id);
        await events.deleteMany({ _id: { $in: ids } });
        await attempts.deleteMany({ eventId: { $in: ids } });
      }
      return mapEvent(doc);
    },
    // findOneAndUpdate is atomic per document, so several workers can pull from
    // the same queue without delivering an event twice.
    async claimDue(limit, now = Date.now()) {
      const out = [];
      for (let i = 0; i < limit; i++) {
        const d = await events.findOneAndUpdate(
          { status: 'pending', nextAttemptAt: { $lte: new Date(now) } },
          { $set: { status: 'delivering', claimedAt: new Date(now) } },
          { sort: { nextAttemptAt: 1 }, returnDocument: 'after' },
        );
        if (!d) break;
        out.push(mapEvent(d));
      }
      return out;
    },
    async requeueStale(olderThanMs) {
      const { modifiedCount } = await events.updateMany(
        { status: 'delivering', claimedAt: { $lt: new Date(Date.now() - olderThanMs) } },
        { $set: { status: 'pending' } },
      );
      return modifiedCount;
    },
    async recordAttempt(eventId, { ok, status, ms, snippet, error }, update) {
      await attempts.insertOne({ eventId, at: new Date(), ok, status: status ?? null, ms: ms ?? null, snippet: snippet ?? null, error: error ?? null });
      const set = { status: update.status, nextAttemptAt: new Date(update.nextAttemptAt), lastStatus: status ?? null, lastError: error || null };
      if (update.status === 'delivered') set.deliveredAt = new Date();
      await events.updateOne({ _id: eventId }, { $inc: { attempts: 1 }, $set: set });
    },
    async requeue(id) {
      const d = await events.findOneAndUpdate(
        { _id: id, status: { $ne: 'delivering' } },
        { $set: { status: 'pending', attempts: 0, nextAttemptAt: new Date() } },
        { returnDocument: 'after' },
      );
      return d ? mapEvent(d) : null;
    },
    async getEvent(id) {
      const d = await events.findOne({ _id: id });
      if (!d) return null;
      const log = await attempts.find({ eventId: id }).sort({ at: 1 }).toArray();
      return {
        ...mapEvent(d),
        attemptLog: log.map(({ at, ok, status, ms, snippet, error }) => ({ at: toIso(at), ok, status, ms, snippet, error })),
      };
    },
    async listEvents({ endpointId, status, limit = 50 } = {}) {
      const match = {};
      if (endpointId) match.endpointId = endpointId;
      if (status) match.status = status;
      const rows = await events.aggregate([
        { $match: match },
        { $sort: { receivedAt: -1 } },
        { $limit: limit },
        { $addFields: { size: { $strLenBytes: '$body' } } },
        { $project: { body: 0 } },
      ]).toArray();
      return rows.map((r) => ({ ...mapEvent({ ...r, body: undefined }), body: undefined, size: r.size }));
    },
    async stats() {
      const out = { total: 0, pending: 0, delivering: 0, delivered: 0, dead: 0 };
      for (const r of await events.aggregate([{ $group: { _id: '$status', n: { $sum: 1 } } }]).toArray()) {
        out[r._id] = r.n;
        out.total += r.n;
      }
      return out;
    },
  };
}
