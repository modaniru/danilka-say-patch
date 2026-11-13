import { createServer } from 'node:http';
import { InvalidToken, JWKSUnavailable } from './auth.js';
import { validID } from './catalog.js';

const PREFIX = '/api/banwords';
export const ROUTES = Object.freeze({
  catalog: `${PREFIX}/catalog`,
  dictionary: `${PREFIX}/dictionaries/{id}`,
  openapi: `${PREFIX}/openapi.json`,
  docs: `${PREFIX}/docs`,
  health: '/healthz',
});

export class RateLimiter {
  constructor({ limit = 60, period = 60, maxUsers = 10000, now = () => Date.now() / 1000 } = {}) {
    this.limit = limit;
    this.period = period;
    this.maxUsers = maxUsers;
    this.now = now;
    this.users = new Map();
  }
  take(user) {
    const now = this.now();
    let entry = this.users.get(user);
    if (!entry || entry.until <= now) {
      if (this.users.size >= this.maxUsers) {
        for (const [id, state] of this.users) if (state.until <= now) this.users.delete(id);
        if (!this.users.has(user) && this.users.size >= this.maxUsers) return this.period;
      }
      entry = { count: 0, until: now + this.period };
      this.users.set(user, entry);
    }
    if (entry.count >= this.limit) return Math.max(1, Math.ceil(entry.until - now));
    entry.count++;
    return 0;
  }
}

function json(response, status, value) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(value));
}

const docs = `<!doctype html><html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Banwords API — OpenAPI</title>
<style>body{font:16px system-ui;max-width:880px;margin:3rem auto;padding:0 1rem;line-height:1.6}code{background:#eee;padding:.2rem}table{border-collapse:collapse}td,th{padding:.6rem;text-align:left;border-bottom:1px solid #ccc}</style>
<h1>Banwords API</h1><p>Спецификация <a href="/api/banwords/openapi.json">OpenAPI 3.1 (Swagger)</a> доступна без внешних ресурсов.</p>
<p>Клиент передаёт <code>Authorization: Bearer bw_…</code> в Caddy. Auth проверяет токен и текущие права владельца, а сервис проверяет внутренний JWT. Нужно право <code>banwords:dictionaries:read</code>.</p>
<table><tr><th>Метод</th><th>Путь</th><th>Ответ</th></tr>
<tr><td>GET</td><td><a href="/api/banwords/catalog">/api/banwords/catalog</a></td><td>Текущий каталог saypatch-rules</td></tr>
<tr><td>GET</td><td>/api/banwords/dictionaries/{id}</td><td>Все словари с коротким hash1; коллизия не выбирается автоматически</td></tr>
</table><p>Неизвестный словарь: 404; неверный hash1: 400; лимит: 429; временно недоступный auth: 503. Слова и текст сообщений не передаются в запросе.</p></html>`;

export function createAPI({ catalog, verifier, openapi, limiter = new RateLimiter(), log = console }) {
  const handler = async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    const path = new URL(request.url, 'http://localhost').pathname;
    const match = /^\/api\/banwords\/dictionaries\/([^/]+)$/.exec(path);
    if (path === ROUTES.health) {
      if (request.method !== 'GET') {
        response.setHeader('Allow', 'GET');
        return json(response, 405, { error: 'метод не поддерживается' });
      }
      response.writeHead(204);
      return response.end();
    }
    if (!match && ![ROUTES.catalog, ROUTES.openapi, ROUTES.docs].includes(path)) return json(response, 404, { error: 'не найдено' });
    let user;
    try {
      user = await verifier.verify(request.headers['x-auth-token']);
    } catch (error) {
      if (error instanceof InvalidToken) return json(response, 404, { error: 'не найдено' });
      if (error instanceof JWKSUnavailable) {
        response.setHeader('Retry-After', '5');
        return json(response, 503, { error: 'авторизация временно недоступна' });
      }
      throw error;
    }
    const retry = limiter.take(user.sub);
    if (retry) {
      response.setHeader('Retry-After', String(retry));
      return json(response, 429, { error: 'слишком много запросов' });
    }
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return json(response, 405, { error: 'метод не поддерживается' });
    }
    if (match) {
      const id = match[1];
      if (!validID(id)) return json(response, 400, { error: 'некорректный идентификатор словаря' });
      const dictionaries = catalog.lookup(id);
      if (!dictionaries.length) return json(response, 404, { error: 'не найдено' });
      return json(response, 200, { protocol: 'sp/1', id, dictionaries });
    }
    if (path === ROUTES.catalog) return json(response, 200, catalog.catalog);
    if (path === ROUTES.openapi) return json(response, 200, openapi);
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" });
    response.end(docs);
  };
  const server = createServer({ maxHeaderSize: 16384, requestTimeout: 15000, headersTimeout: 10000 }, (request, response) => {
    handler(request, response).catch(() => {
      log.error(JSON.stringify({ level: 'error', message: 'request failed' }));
      json(response, 500, { error: 'внутренняя ошибка' });
    });
  });
  server.maxRequestsPerSocket = 1000;
  return server;
}
