import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Verifier, InvalidToken, JWKSUnavailable, boundedJSON } from '../src/auth.js';
import { signingKey, issue, rawIssue } from './helpers.js';
import { createServer } from 'node:http';
import { listen, close } from './helpers.js';

function verifierFor(key, options = {}) {
  return new Verifier({ url: 'http://fake/jwks', fetcher: async () => Response.json({ keys: [key.jwk] }), now: () => 1000, ...options });
}

test('Ed25519 JWT validates issuer, audience, time, exact permission and superadmin', async () => {
  const key = signingKey();
  const verifier = verifierFor(key);
  assert.equal((await verifier.verify(issue(key))).sub, '123');
  assert.equal((await verifier.verify(issue(key, { perms: ['superadmin'] }))).sub, '123');
  assert.equal((await verifier.verify(issue(key, { nbf: 1000 }, { typ: undefined }))).sub, '123');
  for (const override of [
    { iss: 'other' }, { aud: 'tts' }, { aud: ['banwords'] }, { sub: '' }, { sub: null }, { sub: 'x'.repeat(129) },
    { exp: undefined }, { exp: 1000 }, { exp: 999 }, { exp: '1100' }, { exp: 1100.1 },
    { nbf: 1001 }, { nbf: '1000' }, { iat: 1006 }, { iat: '1000' },
    { perms: null }, { perms: [] }, { perms: ['banwords'] }, { perms: ['banwords:dictionaries'] },
    { perms: ['banwords:dictionaries:read', null] }, { perms: Array(129).fill('superadmin') },
    { perms: ['banwords:dictionaries:read', 'x'.repeat(129)] },
  ]) await assert.rejects(verifier.verify(issue(key, override)), InvalidToken);
  for (const claims of [null, [], 'text']) await assert.rejects(verifier.verify(rawIssue(key, { alg: 'EdDSA', kid: key.kid }, claims)), InvalidToken);
});

test('malformed tokens, headers and tampered signatures fail before authorization', async () => {
  const key = signingKey();
  let fetches = 0;
  const verifier = verifierFor(key, { fetcher: async () => { fetches++; return Response.json({ keys: [key.jwk] }); } });
  for (const raw of [undefined, null, [], '', 'a'.repeat(8193), 'a.b', 'a.b.c.d', 'a=.b.c', '..', 'YQ.YQ.YQ', 'e30.bm90LWpzb24.YQ']) {
    await assert.rejects(verifier.verify(raw), InvalidToken);
  }
  for (const override of [{ alg: 'none' }, { alg: 'HS256' }, { kid: undefined }, { kid: '' }, { kid: 1 }, { kid: 'x'.repeat(129) }, { typ: 'other' }]) {
    await assert.rejects(verifier.verify(issue(key, {}, override)), InvalidToken);
  }
  await assert.rejects(verifier.verify(rawIssue(key, null, {})), InvalidToken);
  assert.equal(fetches, 0);
  const wrongKey = signingKey();
  await assert.rejects(verifier.verify(issue(wrongKey)), InvalidToken);
  const [header, payload] = issue(key).split('.');
  await assert.rejects(verifier.verify(`${header}.${payload}.YQ`), InvalidToken);
  await assert.rejects(verifier.verify(issue(key).replace(payload, Buffer.from('{"sub":"hacked"}').toString('base64url'))), InvalidToken);
});

test('JWKS cache, rotation, request coalescing and unknown-kid cooldown are bounded', async () => {
  const first = signingKey('first'), second = signingKey('second');
  let now = 1000, fetches = 0, keys = [first.jwk];
  const verifier = verifierFor(first, {
    now: () => now,
    fetcher: async (_url, options) => {
      assert.equal(options.redirect, 'error');
      assert.ok(options.signal instanceof AbortSignal);
      fetches++;
      await new Promise(resolve => setImmediate(resolve));
      return Response.json({ keys });
    },
  });
  await Promise.all(Array.from({ length: 10 }, () => verifier.verify(issue(first))));
  assert.equal(fetches, 1);
  await verifier.verify(issue(first));
  assert.equal(fetches, 1);
  keys = [first.jwk, second.jwk];
  now = 1001;
  await assert.rejects(verifier.verify(issue(second)), InvalidToken);
  assert.equal(fetches, 1);
  now = 1005;
  await verifier.verify(issue(second));
  assert.equal(fetches, 2);
  keys = [second.jwk];
  now = 1305;
  await verifier.verify(issue(second, { iat: now, exp: now + 100 }));
  assert.equal(fetches, 3);
  await assert.rejects(verifier.verify(issue(first, { iat: now, exp: now + 100 })), InvalidToken);
});

test('JWKS outage and expired cache fail closed, with retry after cooldown', async () => {
  const key = signingKey();
  let now = 1000, failed = false, fetches = 0;
  const verifier = verifierFor(key, { now: () => now, fetcher: () => {
    fetches++;
    if (failed) throw new Error('contains secret that must not reach client');
    return Promise.resolve(Response.json({ keys: [key.jwk] }));
  } });
  await verifier.verify(issue(key));
  failed = true;
  now = 1300;
  await assert.rejects(verifier.verify(issue(key, { iat: now, exp: now + 100 })), JWKSUnavailable);
  await assert.rejects(verifier.verify(issue(key, { iat: now, exp: now + 100 })), JWKSUnavailable);
  assert.equal(fetches, 2);
  failed = false;
  now = 1305;
  await verifier.verify(issue(key, { iat: now, exp: now + 100 }));
  assert.equal(fetches, 3);
});

test('JWKS timeout aborts fetch and permits a later recovery', async () => {
  const key = signingKey();
  let now = 1000, shouldHang = true, aborted = false;
  const verifier = verifierFor(key, { timeout: 10, now: () => now, fetcher: (_url, { signal }) => {
    if (!shouldHang) return Promise.resolve(Response.json({ keys: [key.jwk] }));
    return new Promise((_resolve, reject) => signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }));
  } });
  await assert.rejects(verifier.verify(issue(key)), JWKSUnavailable);
  assert.equal(aborted, true);
  now += 5;
  shouldHang = false;
  await verifier.verify(issue(key));
});

test('JWKS rejects malformed keys, duplicates, private material and oversized responses', async () => {
  const key = signingKey();
  const jwk = key.jwk;
  const invalid = [null, {}, { keys: [] }, { keys: null }, { keys: Array(17).fill(jwk) }, { keys: [jwk, jwk] }, { keys: [null] }];
  for (const override of [{ kty: 'RSA' }, { crv: 'X25519' }, { kid: null }, { kid: '' }, { kid: 'x'.repeat(129) },
    { x: 'bad=' }, { x: 'YQ' }, { alg: 'none' }, { use: 'enc' }, { d: 'private' }]) invalid.push({ keys: [{ ...jwk, ...override }] });
  for (const body of invalid) await assert.rejects(verifierFor(key, { fetcher: async () => Response.json(body) }).verify(issue(key)), JWKSUnavailable);
  for (const response of [new Response('oops', { status: 503 }), new Response('{'), new Response(null, { status: 204 }),
    new Response('x'.repeat(65537)), new Response('{}', { headers: { 'Content-Length': '65537' } })]) {
    await assert.rejects(verifierFor(key, { fetcher: async () => response }).verify(issue(key)), JWKSUnavailable);
  }
  const optional = { ...jwk };
  delete optional.alg;
  delete optional.use;
  await verifierFor(key, { fetcher: async () => Response.json({ keys: [optional] }) }).verify(issue(key));
});

test('bounded JSON streams reject oversized chunks and propagate read failures', async () => {
  assert.deepEqual(await boundedJSON(Response.json({ keys: [] })), { keys: [] });
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(65537)); controller.close(); } });
  await assert.rejects(boundedJSON(new Response(stream)), /response too large/);
  const broken = new ReadableStream({ start(controller) { controller.error(new Error('broken stream')); } });
  await assert.rejects(boundedJSON(new Response(broken)), /broken stream/);
});

test('default clock and HTTP fetch work against a local fake JWKS server', async t => {
  const key = signingKey();
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ keys: [key.jwk] }));
  });
  t.after(() => close(server));
  const url = await listen(server);
  const now = Math.floor(Date.now() / 1000);
  const verifier = new Verifier({ url });
  assert.equal((await verifier.verify(issue(key, { iat: now, exp: now + 60 }))).sub, '123');
});
