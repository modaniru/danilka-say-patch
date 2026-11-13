import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { config } from '../src/config.js';

test('default and explicit configuration', () => {
  const defaults = config({});
  assert.equal(defaults.port, 8080);
  assert.equal(defaults.jwksURL, 'http://auth:8080/.well-known/jwks.json');
  assert.equal(isAbsolute(defaults.dataDirectory), true);
  assert.equal(existsSync(join(defaults.dataDirectory, 'manifest.json')), true);
  assert.deepEqual(config({ PORT: '9876', BANWORDS_JWKS_URL: 'https://auth.test/keys', BANWORDS_DATA_DIR: '/data' }), {
    port: 9876, jwksURL: 'https://auth.test/keys', dataDirectory: '/data',
  });
});

test('invalid ports and JWKS URLs fail startup', () => {
  for (const port of ['0', '65536', '-1', 'x', '3.5', '']) assert.throws(() => config({ PORT: port }), /invalid PORT/);
  for (const url of ['file:///tmp/keys', 'ftp://auth/keys', 'http://user:pass@auth/keys', 'http://user@auth/keys', 'not-url']) {
    assert.throws(() => config({ BANWORDS_JWKS_URL: url }));
  }
});
