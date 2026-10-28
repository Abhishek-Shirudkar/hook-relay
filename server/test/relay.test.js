import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createMemoryStore } from '../store.js';
import { deliver, createDemoTarget, retryDelaySeconds, startWorker } from '../relay.js';
import { checkTarget, isPrivateIp, sign, verify, createLimiter } from '../security.js';
import { createApp } from '../index.js';

const shut = (s) => { s.closeAllConnections?.(); s.close(); };
const listen = (server) => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port)));
const publicLookup = async () => [{ address: '93.184.216.34' }];

test('private and internal addresses are rejected', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:10.0.0.1']) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '93.184.216.34', '2606:4700::1111']) assert.equal(isPrivateIp(ip), false, ip);
});

test('checkTarget enforces scheme, credentials and resolved address', async () => {
  await assert.rejects(checkTarget('ftp://example.com'), /http/);
  await assert.rejects(checkTarget('http://user:pw@example.com'), /credentials/);
  await assert.rejects(checkTarget('http://127.0.0.1:8080/x'), /private/);
  await assert.rejects(checkTarget('http://internal.example', async () => [{ address: '10.0.0.5' }]), /private/);
  await assert.rejects(checkTarget('not a url'), /valid URL/);
  await checkTarget('https://example.com/hook', publicLookup);
});

test('signatures verify and detect tampering', () => {
  const sig = sign('s3cret', '{"a":1}');
  assert.ok(verify('s3cret', '{"a":1}', sig));
  assert.ok(!verify('s3cret', '{"a":2}', sig));
  assert.ok(!verify('other', '{"a":1}', sig));
  assert.ok(!verify('s3cret', '{"a":1}', undefined));
});

test('rate limiter blocks after the limit and resets after the window', () => {
  const allow = createLimiter(2, 1000);
  assert.ok(allow('a', 0) && allow('a', 10));
  assert.ok(!allow('a', 20));
  assert.ok(allow('b', 20));
  assert.ok(allow('a', 1500));
});

test('backoff grows and then holds at the last value', () => {
  assert.deepEqual([1, 2, 3, 4, 5, 9].map((n) => retryDelaySeconds(n)), [5, 15, 45, 120, 300, 300]);
});

async function setup(targetUrl) {
  const store = createMemoryStore();
  const ep = await store.createEndpoint({ name: 't', targetUrl });
  const ev = await store.insertEvent({ endpointId: ep.id, headers: { 'content-type': 'application/json' }, body: '{"hello":"world"}' });
  return { store, ep, ev };
}

test('successful delivery is signed and marks the event delivered', async () => {
  let seen;
  const dest = http.createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => { seen = { headers: req.headers, body: b }; res.writeHead(200); res.end('thanks'); });
  });
  const port = await listen(dest);
  const { store, ep, ev } = await setup(`http://127.0.0.1:${port}/in`);
  const [claimed] = await store.claimDue(5);
  const out = await deliver(store, claimed, ep, { checkTargetImpl: async () => {} });
  shut(dest);
  assert.equal(out.outcome, 'delivered');
  assert.ok(verify(ep.secret, seen.body, seen.headers['x-hookrelay-signature']));
  assert.equal(seen.headers['x-hookrelay-attempt'], '1');
  const saved = await store.getEvent(ev.id);
  assert.equal(saved.status, 'delivered');
  assert.equal(saved.attemptLog.length, 1);
});

test('failures retry with backoff, then the event is marked dead', async () => {
  const { store, ep, ev } = await setup('https://example.com/fail');
  const failing = async () => ({ status: 500, text: async () => 'boom' });
  let clock = Date.now();
  const opts = { fetchImpl: failing, checkTargetImpl: async () => {}, maxAttempts: 3, backoff: [5, 15], now: () => clock };
  const outcomes = [];
  for (let i = 0; i < 3; i++) {
    clock += 60_000; // jump past any retry delay
        const [claimed] = await store.claimDue(5, clock);
    assert.ok(claimed, `attempt ${i + 1} should be due`);
    outcomes.push((await deliver(store, claimed, ep, opts)).outcome);
  }
  assert.deepEqual(outcomes, ['pending', 'pending', 'dead']);
  assert.equal((await store.getEvent(ev.id)).attemptLog.length, 3);
  assert.equal((await store.claimDue(5)).length, 0, 'dead events are never claimed again');
});

test('a retry is not due before its delay has passed', async () => {
  const { store, ep } = await setup('https://example.com/x');
  const [claimed] = await store.claimDue(5);
  await deliver(store, claimed, ep, { fetchImpl: async () => ({ status: 503, text: async () => '' }), checkTargetImpl: async () => {} });
  assert.equal((await store.claimDue(5)).length, 0);
});

test('network errors and blocked destinations count as failed attempts', async () => {
  const { store, ep } = await setup('http://127.0.0.1:9/nope');
  const [claimed] = await store.claimDue(5);
  const out = await deliver(store, claimed, ep); // real SSRF check, no override
  assert.equal(out.ok, false);
  assert.match(out.error, /private/);
});

test('the demo destination fails or succeeds on command, and replay resets the event', async () => {
  const { store, ep, ev } = await setup('demo');
  const demo = createDemoTarget();
  demo.healthy = false;
  let [claimed] = await store.claimDue(5);
  assert.equal((await deliver(store, claimed, ep, { demo })).outcome, 'pending');
  demo.healthy = true;
  await store.requeue(ev.id);
  [claimed] = await store.claimDue(5);
  assert.equal((await deliver(store, claimed, ep, { demo })).outcome, 'delivered');
});

test('stale "delivering" events are returned to the queue', async () => {
  const { store } = await setup('demo');
  await store.claimDue(5);
  assert.equal((await store.claimDue(5)).length, 0);
  assert.equal(await store.requeueStale(-1), 1);
  assert.equal((await store.claimDue(5)).length, 1);
});

test('HTTP API: ingest, signature check, queue, worker delivery, replay, limits', async () => {
  const store = createMemoryStore();
  const demo = createDemoTarget();
  const server = createApp({ store, demo, ingestLimit: 5 });
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  const post = (p, body, headers = {}) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });

  // create endpoints
  const created = await (await post('/api/endpoints', { name: 'Demo', targetUrl: 'demo' })).json();
  assert.ok(created.id && created.secret.startsWith('whsec_'));
  const listed = await (await fetch(base + '/api/endpoints')).json();
  assert.ok(listed[0].secret.endsWith('…'), 'list hides the secret');
  assert.equal((await post('/api/endpoints', { name: 'Bad', targetUrl: 'http://127.0.0.1/x' })).status, 400);
  assert.equal((await post('/api/endpoints', { name: '', targetUrl: 'demo' })).status, 400);

  // ingest
  const payload = '{"type":"ping"}';
  assert.equal((await post('/hook/nope', payload)).status, 404);
  assert.equal((await post('/hook/' + created.id, payload, { 'x-signature': 'sha256=bad' })).status, 401);
  const ok = await post('/hook/' + created.id, payload, { 'x-signature': sign(created.secret, payload) });
  assert.equal(ok.status, 202);
  const { id } = await ok.json();
  assert.equal((await post('/hook/' + created.id, 'x'.repeat(200 * 1024))).status, 413);
  assert.equal((await fetch(base + '/hook/' + created.id)).status, 405);

  // worker delivers it
  const worker = startWorker(store, { demo });
  await worker.tick();
  worker.stop();
  const ev = await (await fetch(base + '/api/events/' + id)).json();
  assert.equal(ev.status, 'delivered');
  assert.equal(ev.attemptLog[0].status, 200);

  // replay
  assert.equal((await post(`/api/events/${id}/replay`, {})).status, 202);
  assert.equal((await (await fetch(base + '/api/stats')).json()).pending, 1);

  // rate limit on ingest (limit 5: 3 accepted above already counted)
  let limited = 0;
  for (let i = 0; i < 6; i++) if ((await post('/hook/' + created.id, payload)).status === 429) limited++;
  assert.ok(limited > 0);

  // delete cascades
  assert.equal((await fetch(base + '/api/endpoints/' + created.id, { method: 'DELETE' })).status, 200);
  assert.equal((await (await fetch(base + '/api/stats')).json()).total, 0);
  shut(server);
});

test('admin token protects the API but not the public ingest URL', async () => {
  const store = createMemoryStore();
  const server = createApp({ store, demo: createDemoTarget(), adminToken: 'letmein' });
  const port = await listen(server);
  const base = `http://127.0.0.1:${port}`;
  assert.equal((await fetch(base + '/api/stats')).status, 401);
  assert.equal((await fetch(base + '/api/stats', { headers: { authorization: 'Bearer letmein' } })).status, 200);
  assert.equal((await fetch(base + '/hook/unknown', { method: 'POST', body: 'x' })).status, 404); // reaches the handler, not 401
  assert.equal((await fetch(base + '/')).status, 200);
  shut(server);
});
