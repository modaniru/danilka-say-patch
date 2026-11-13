import { generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';

export function signingKey(kid = 'v1') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { kid, privateKey, jwk: { ...publicKey.export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' } };
}

export function issue(key, overrides = {}, headerOverrides = {}) {
  const header = { alg: 'EdDSA', typ: 'JWT', kid: key.kid, ...headerOverrides };
  const claims = { iss: 'danysik-auth', sub: '123', aud: 'banwords', iat: 1000, exp: 1100, perms: ['banwords:dictionaries:read'], ...overrides };
  return rawIssue(key, header, claims);
}

export function rawIssue(key, header, claims) {
  const body = [header, claims].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
  return `${body}.${sign(null, Buffer.from(body), key.privateKey).toString('base64url')}`;
}

export async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}

export async function close(server) {
  const closed = once(server, 'close');
  server.close();
  server.closeAllConnections();
  await closed;
}
