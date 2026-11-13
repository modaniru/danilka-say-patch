import { createPublicKey, verify } from 'node:crypto';

export class InvalidToken extends Error {}
export class JWKSUnavailable extends Error {}

const b64 = value => typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) &&
  Buffer.from(value, 'base64url').toString('base64url') === value;

export async function boundedJSON(response, maxBytes = 65536) {
  if (!response.ok) throw new Error('upstream rejected request');
  if (Number(response.headers.get('content-length')) > maxBytes) {
    await response.body?.cancel();
    throw new Error('response too large');
  }
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) throw new Error('response too large');
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export class Verifier {
  constructor({ url, fetcher = fetch, now = () => Date.now() / 1000, timeout = 3000, cacheTTL = 300, refreshInterval = 5 }) {
    this.url = url;
    this.fetcher = fetcher;
    this.now = now;
    this.timeout = timeout;
    this.cacheTTL = cacheTTL;
    this.refreshInterval = refreshInterval;
    this.keys = new Map();
    this.fetchedAt = -Infinity;
    this.attemptAt = -Infinity;
    this.pending = null;
  }

  async refresh() {
    if (this.pending) return this.pending;
    if (this.now() - this.attemptAt < this.refreshInterval) return;
    this.attemptAt = this.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);
    this.pending = (async () => {
      try {
        const response = await Promise.resolve().then(() => this.fetcher(this.url, { signal: controller.signal, redirect: 'error' }));
        const jwks = await boundedJSON(response);
        if (!jwks || !Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.length > 16) throw new Error('invalid JWKS');
        const keys = new Map();
        for (const key of jwks.keys) {
          if (!key || key.kty !== 'OKP' || key.crv !== 'Ed25519' || typeof key.kid !== 'string' ||
            !key.kid || key.kid.length > 128 || !b64(key.x) || Buffer.from(key.x, 'base64url').length !== 32 ||
            (key.alg !== undefined && key.alg !== 'EdDSA') || (key.use !== undefined && key.use !== 'sig') ||
            key.d !== undefined || keys.has(key.kid)) throw new Error('invalid JWK');
          keys.set(key.kid, createPublicKey({ key, format: 'jwk' }));
        }
        this.keys = keys;
        this.fetchedAt = this.now();
      } catch {
        throw new JWKSUnavailable('authentication keys unavailable');
      } finally {
        clearTimeout(timer);
        this.pending = null;
      }
    })();
    return this.pending;
  }

  async verify(raw) {
    if (typeof raw !== 'string' || raw.length > 8192) throw new InvalidToken();
    const parts = raw.split('.');
    if (parts.length !== 3 || !parts.every(b64)) throw new InvalidToken();
    let header, claims;
    try {
      header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
      claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch { throw new InvalidToken(); }
    if (!header || header.alg !== 'EdDSA' || typeof header.kid !== 'string' || !header.kid || header.kid.length > 128 ||
      (header.typ !== undefined && header.typ !== 'JWT')) throw new InvalidToken();
    if (!this.keys.has(header.kid) || this.now() - this.fetchedAt >= this.cacheTTL) await this.refresh();
    if (this.now() - this.fetchedAt >= this.cacheTTL) throw new JWKSUnavailable();
    const key = this.keys.get(header.kid);
    if (!key || !verify(null, Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url'))) throw new InvalidToken();
    if (!claims || claims.iss !== 'danysik-auth' || claims.aud !== 'banwords' ||
      typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 128 ||
      !Number.isSafeInteger(claims.exp) || claims.exp <= this.now() ||
      (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf) || claims.nbf > this.now())) ||
      (claims.iat !== undefined && (!Number.isSafeInteger(claims.iat) || claims.iat > this.now() + 5)) ||
      !Array.isArray(claims.perms) || claims.perms.length > 128 || claims.perms.some(permission =>
        typeof permission !== 'string' || permission.length > 128) ||
      (!claims.perms.includes('banwords:dictionaries:read') && !claims.perms.includes('superadmin'))) throw new InvalidToken();
    return claims;
  }
}
