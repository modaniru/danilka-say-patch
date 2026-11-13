import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { connect } from 'node:net';
import { listen, close } from './helpers.js';

const root = new URL('../', import.meta.url).pathname;

function child(args = [], env = {}) {
  const process = spawn('node', ['src/main.js', ...args], { cwd: root, env: { ...globalThis.process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  process.stdout.on('data', chunk => { output += chunk; });
  process.stderr.on('data', chunk => { output += chunk; });
  return { process, done: once(process, 'exit').then(([code, signal]) => ({ code, signal, output })) };
}

test('CLI serves health, healthcheck succeeds and SIGTERM shuts down', async t => {
  const reserved = createServer();
  const base = await listen(reserved);
  const port = new URL(base).port;
  await close(reserved);
  const { process, done } = child([], { PORT: port });
  t.after(() => { if (process.exitCode === null) process.kill('SIGKILL'); });
  await once(process.stdout, 'data');
  assert.equal((await fetch(`${base}/healthz`)).status, 204);
  assert.equal((await fetch(`${base}/api/banwords/catalog`)).status, 404);
  const checked = await child(['healthcheck'], { PORT: port }).done;
  assert.equal(checked.code, 0, checked.output);
  process.kill('SIGTERM');
  assert.equal((await done).code, 0);
});

test('CLI reports invalid config, missing data, occupied port and unhealthy target safely', { timeout: 10000 }, async () => {
  for (const env of [{ PORT: 'invalid' }, { BANWORDS_DATA_DIR: '/missing-sensitive-path' }]) {
    const result = await child([], env).done;
    assert.equal(result.code, 1);
    assert.ok(!result.output.includes('sensitive'));
    assert.match(result.output, /startup or healthcheck failed/);
  }
  const occupied = createServer((_req, response) => { response.writeHead(500); response.end(); });
  occupied.listen(0, '0.0.0.0');
  await once(occupied, 'listening');
  const base = `http://127.0.0.1:${occupied.address().port}`;
  try {
    const env = { PORT: new URL(base).port };
    const failed = await child([], env).done;
    assert.equal(failed.code, 1);
    assert.match(failed.output, /server failed/);
    assert.equal((await child(['healthcheck'], env).done).code, 1);
  } finally { await close(occupied); }
  const result = await child(['healthcheck'], { PORT: new URL(base).port }).done;
  assert.equal(result.code, 1);
});

test('CLI bounds graceful shutdown even when a client leaves an incomplete request', { timeout: 15000 }, async t => {
  const reserved = createServer();
  const base = await listen(reserved);
  const port = new URL(base).port;
  await close(reserved);
  const { process, done } = child([], { PORT: port });
  t.after(() => { if (process.exitCode === null) process.kill('SIGKILL'); });
  await once(process.stdout, 'data');
  const socket = connect(Number(port), '127.0.0.1');
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  socket.write('GET /healthz HTTP/1.1\r\nHost: localhost\r\n');
  await new Promise(resolve => setTimeout(resolve, 20));
  process.kill('SIGINT');
  assert.equal((await done).code, 1);
});
