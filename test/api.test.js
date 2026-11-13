import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createAPI, RateLimiter, ROUTES } from '../src/api.js';
import { loadCatalog, prepareDictionary } from '../src/catalog.js';
import { Verifier, InvalidToken, JWKSUnavailable } from '../src/auth.js';
import { signingKey, issue, listen, close } from './helpers.js';

const specification = JSON.parse(await readFile(new URL('../openapi.json', import.meta.url), 'utf8'));
const seed = await loadCatalog(new URL('../data/', import.meta.url).pathname);

async function setup(t, overrides = {}) {
  const key = signingKey();
  const verifier = new Verifier({ url: 'http://fake/jwks', now: () => 1000, fetcher: async () => Response.json({ keys: [key.jwk] }) });
  const server = createAPI({ catalog: seed, verifier, openapi: specification, ...overrides });
  t.after(() => close(server));
  const base = await listen(server);
  return { key, server, base, request: (path, options = {}) => fetch(`${base}${path}`, { ...options, headers: { 'X-Auth-Token': issue(key), ...options.headers } }) };
}

test('catalog, historical lookup, OpenAPI and local docs implement the documented contract', async t => {
  const { request } = await setup(t);
  const catalog = await request(ROUTES.catalog);
  assert.equal(catalog.status, 200);
  assert.equal(catalog.headers.get('cache-control'), 'no-store');
  assert.equal(catalog.headers.get('x-content-type-options'), 'nosniff');
  assert.match(catalog.headers.get('content-type'), /application\/json/);
  assert.deepEqual(await catalog.json(), seed.catalog);
  const lookup = await request('/api/banwords/dictionaries/0dMf');
  assert.equal(lookup.status, 200);
  assert.deepEqual(await lookup.json(), { protocol: 'sp/1', id: '0dMf', dictionaries: seed.lookup('0dMf') });
  const openapi = await request(ROUTES.openapi);
  assert.equal(openapi.status, 200);
  assert.deepEqual(await openapi.json(), specification);
  assert.deepEqual(Object.keys(specification.paths).sort(), Object.values(ROUTES).sort());
  for (const [path, document] of Object.entries(specification.paths)) {
    assert.equal(Object.keys(document).join(), 'get', path);
    assert.ok(document.get.responses[path === '/healthz' ? '204' : '200']);
    assert.ok(document.get.responses['405']);
    if (path !== '/healthz') for (const status of ['404', '429', '500', '503']) assert.ok(document.get.responses[status]);
  }
  assert.ok(specification.paths[ROUTES.dictionary].get.responses['400']);
  const documentation = await request(ROUTES.docs);
  assert.equal(documentation.status, 200);
  assert.match(documentation.headers.get('content-type'), /text\/html/);
  assert.match(documentation.headers.get('content-security-policy'), /default-src 'none'/);
  const html = await documentation.text();
  assert.ok(html.includes(ROUTES.openapi));
  assert.ok(!html.includes('https://'));
});

test('authentication is mandatory; external bearer and client-controlled claims are insufficient', async t => {
  const { base, key } = await setup(t);
  for (const path of ['/api/banwords/catalog', '/api/banwords/dictionaries/0dMf', '/api/banwords/openapi.json', '/api/banwords/docs']) {
    for (const headers of [{}, { Authorization: 'Bearer bw_secret' }, { 'X-Auth-Token': 'garbage' },
      { 'X-Auth-Token': issue(key, { aud: 'tts' }) }, { 'X-Auth-Token': issue(key, { perms: ['banwords'] }) }]) {
      const response = await fetch(`${base}${path}`, { headers });
      assert.equal(response.status, 404);
      assert.deepEqual(await response.json(), { error: 'не найдено' });
    }
  }
  assert.equal((await fetch(`${base}/healthz`)).status, 204);
});

test('unknown and malformed identifiers and methods have explicit statuses', async t => {
  const { request, base } = await setup(t);
  assert.equal((await request('/api/banwords/dictionaries/zzzz')).status, 404);
  for (const id of ['abc', 'abcde', 'a%2Fb', '%0Aabc', 'abcd=']) assert.equal((await request(`/api/banwords/dictionaries/${id}`)).status, 400);
  assert.equal((await request('/api/banwords/dictionaries/0dMf?message=never-used')).status, 200);
  for (const path of ['/missing', '/api/banwords/dictionaries/', '/api/banwords/dictionaries/0dMf/extra', '/api/banwords/catalog/']) {
    assert.equal((await fetch(`${base}${path}`)).status, 404);
  }
  for (const path of [ROUTES.health, ROUTES.catalog, ROUTES.openapi, ROUTES.docs, '/api/banwords/dictionaries/0dMf']) {
    const response = await request(path, { method: 'POST', body: '{}' });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get('allow'), 'GET');
  }
});

test('lookup returns all collision candidates without guessing', async t => {
  const dictionaries = [prepareDictionary(['a']), prepareDictionary(['b'])];
  const { request } = await setup(t, { catalog: { catalog: seed.catalog, lookup: () => dictionaries } });
  const response = await request('/api/banwords/dictionaries/abcd');
  assert.equal(response.status, 200);
  assert.deepEqual((await response.json()).dictionaries, dictionaries);
});

test('rate limiting is per subject, fixed-window, memory-bounded and returns Retry-After', async t => {
  let now = 1000;
  const limiter = new RateLimiter({ now: () => now, limit: 1, maxUsers: 2 });
  const { request, key } = await setup(t, { limiter });
  assert.equal((await request(ROUTES.catalog)).status, 200);
  const blocked = await request(ROUTES.catalog);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.headers.get('retry-after'), '60');
  assert.equal((await request(ROUTES.catalog, { headers: { 'X-Auth-Token': issue(key, { sub: '456' }) } })).status, 200);
  assert.equal((await request(ROUTES.catalog, { headers: { 'X-Auth-Token': issue(key, { sub: '789' }) } })).status, 429);
  assert.equal(limiter.users.size, 2);
  now = 1060;
  assert.equal((await request(ROUTES.catalog, { headers: { 'X-Auth-Token': issue(key, { sub: '789' }) } })).status, 200);
  assert.equal(limiter.users.size, 1);
  const own = new RateLimiter({ now: () => now, limit: 1, maxUsers: 1 });
  assert.equal(own.take('x'), 0);
  now += 60;
  assert.equal(own.take('x'), 0);
});

test('auth outages and unexpected errors return sanitized responses', async t => {
  const logged = [];
  for (const [error, status] of [[new InvalidToken('secret'), 404], [new JWKSUnavailable('secret'), 503], [new Error('secret'), 500]]) {
    const { request } = await setup(t, { verifier: { verify: async () => { throw error; } }, log: { error: line => logged.push(line) } });
    const response = await request(ROUTES.catalog);
    assert.equal(response.status, status);
    assert.equal(response.headers.get('retry-after'), status === 503 ? '5' : null);
    assert.ok(!(await response.text()).includes('secret'));
  }
  assert.deepEqual(logged.map(JSON.parse), [{ level: 'error', message: 'request failed' }]);
});
