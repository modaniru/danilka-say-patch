export function config(env = process.env) {
  const port = env.PORT === undefined ? 8080 : Number(env.PORT);
  const jwksURL = new URL(env.BANWORDS_JWKS_URL || 'http://auth:8080/.well-known/jwks.json');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid PORT');
  if (!['http:', 'https:'].includes(jwksURL.protocol) || jwksURL.username || jwksURL.password) throw new Error('invalid BANWORDS_JWKS_URL');
  return {
    port,
    jwksURL: jwksURL.href,
    dataDirectory: env.BANWORDS_DATA_DIR || new URL('../data/', import.meta.url).pathname,
  };
}
