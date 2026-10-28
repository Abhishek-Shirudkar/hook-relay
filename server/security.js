import { createHmac, timingSafeEqual } from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';

// HMAC-SHA256 signature in the form "sha256=<hex>", like most webhook providers.
export function sign(secret, body) {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

export function verify(secret, body, header) {
  const expected = Buffer.from(sign(secret, body));
  const given = Buffer.from(String(header || ''));
  return expected.length === given.length && timingSafeEqual(expected, given);
}

export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  if (net.isIPv6(ip)) {
    const x = ip.toLowerCase();
    if (x === '::1' || x === '::') return true;
    if (/^f[cd]/.test(x) || /^fe[89ab]/.test(x)) return true;
    const mapped = x.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    return false;
  }
  return true; // not a valid IP: refuse
}

// SSRF guard: only public http(s) destinations. Checked when an endpoint is
// created and again right before every delivery.
export async function checkTarget(raw, lookup = dns.lookup) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('Destination must be a valid URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Destination must start with http:// or https://');
  if (url.username || url.password) throw new Error('Destination URL must not contain credentials');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  let addrs;
  try {
    addrs = net.isIP(host) ? [{ address: host }] : await lookup(host, { all: true });
  } catch {
    throw new Error('Destination host could not be resolved');
  }
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error('Destination resolves to a private or internal address, which is not allowed');
  }
  return url;
}

// Tiny fixed-window rate limiter, keyed by string (e.g. IP + bucket).
export function createLimiter(limit, windowMs) {
  const hits = new Map();
  return function allow(key, now = Date.now()) {
    const entry = hits.get(key);
    if (!entry || now - entry.start >= windowMs) {
      hits.set(key, { start: now, n: 1 });
      if (hits.size > 5000) for (const [k, v] of hits) if (now - v.start >= windowMs) hits.delete(k);
      return true;
    }
    entry.n += 1;
    return entry.n <= limit;
  };
}
