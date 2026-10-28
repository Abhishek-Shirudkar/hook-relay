import { checkTarget, sign } from './security.js';

export const DEFAULT_BACKOFF_SECONDS = [5, 15, 45, 120, 300];
export const DEFAULT_MAX_ATTEMPTS = 5;
const REQUEST_TIMEOUT_MS = 8000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// The built-in destination used by the demo endpoint. It can be switched
// between healthy and failing from the dashboard to show retries live.
export function createDemoTarget() {
  const state = {
    healthy: true,
    async handle() {
      await sleep(60 + Math.random() * 140);
      return state.healthy
        ? { status: 200, snippet: '{"received":true}' }
        : { status: 503, snippet: 'Service Unavailable (demo destination is set to failing)' };
    },
  };
  return state;
}

export function retryDelaySeconds(attemptNo, backoff = DEFAULT_BACKOFF_SECONDS) {
  return backoff[Math.min(attemptNo - 1, backoff.length - 1)];
}

// One delivery attempt for one claimed event. Records the attempt and moves the
// event to delivered / pending (retry later) / dead (gave up).
export async function deliver(store, ev, ep, opts = {}) {
  const {
    demo, fetchImpl = fetch, checkTargetImpl = checkTarget,
    backoff = DEFAULT_BACKOFF_SECONDS, maxAttempts = DEFAULT_MAX_ATTEMPTS, now = () => Date.now(),
  } = opts;
  const attemptNo = ev.attempts + 1;
  const started = now();
  let result;

  try {
    if (!ep) throw new Error('Endpoint no longer exists');
    if (ep.targetUrl === 'demo') {
      const r = await demo.handle(ev);
      result = { ok: r.status >= 200 && r.status < 300, status: r.status, snippet: r.snippet };
    } else {
      await checkTargetImpl(ep.targetUrl);
      const res = await fetchImpl(ep.targetUrl, {
        method: 'POST',
        redirect: 'manual', // a redirect could point at an internal address
        headers: {
          'content-type': ev.headers?.['content-type'] || 'application/json',
          'user-agent': 'HookRelay/1.0',
          'x-hookrelay-event': ev.id,
          'x-hookrelay-attempt': String(attemptNo),
          'x-hookrelay-signature': sign(ep.secret, ev.body),
        },
        body: ev.body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const text = (await res.text().catch(() => '')).slice(0, 200);
      result = { ok: res.status >= 200 && res.status < 300, status: res.status, snippet: text };
    }
  } catch (err) {
    const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
    result = { ok: false, status: null, snippet: '', error: timedOut ? 'Timed out after 8 s' : String(err.message || err).slice(0, 200) };
  }
  result.ms = now() - started;

  let update;
  if (result.ok) {
    update = { status: 'delivered', nextAttemptAt: new Date(now()).toISOString() };
  } else if (attemptNo >= maxAttempts) {
    update = { status: 'dead', nextAttemptAt: new Date(now()).toISOString() };
  } else {
    update = { status: 'pending', nextAttemptAt: new Date(now() + retryDelaySeconds(attemptNo, backoff) * 1000).toISOString() };
  }
  await store.recordAttempt(ev.id, result, update);
  return { ...result, outcome: update.status };
}

// Polls the queue once a second. A `busy` flag stops ticks from overlapping.
export function startWorker(store, opts = {}) {
  let busy = false;
  const tick = async () => {
    if (busy) return;
    busy = true;
    try {
      await store.requeueStale(60_000);
      const due = await store.claimDue(10);
      await Promise.allSettled(
        due.map(async (ev) => {
          const ep = await store.getEndpoint(ev.endpointId);
          return deliver(store, ev, ep, opts);
        }),
      );
    } catch (err) {
      console.error('worker error:', err.message);
    } finally {
      busy = false;
    }
  };
  const timer = setInterval(tick, 1000);
  return { stop: () => clearInterval(timer), tick };
}
