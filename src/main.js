import { readFile } from 'node:fs/promises';
import { config } from './config.js';
import { loadCatalog } from './catalog.js';
import { Verifier } from './auth.js';
import { createAPI } from './api.js';

try {
  const settings = config();
  if (process.argv[2] === 'healthcheck') {
    const response = await fetch(`http://127.0.0.1:${settings.port}/healthz`, { signal: AbortSignal.timeout(3000) });
    process.exitCode = response.status === 204 ? 0 : 1;
  } else {
    const catalog = await loadCatalog(settings.dataDirectory);
    const openapi = JSON.parse(await readFile(new URL('../openapi.json', import.meta.url), 'utf8'));
    const server = createAPI({ catalog, openapi, verifier: new Verifier({ url: settings.jwksURL }) });
    server.listen(settings.port, '0.0.0.0', () => {
      console.info(JSON.stringify({ level: 'info', message: 'banwords listening', port: settings.port }));
    });
    server.on('error', () => {
      console.error(JSON.stringify({ level: 'error', message: 'server failed' }));
      process.exitCode = 1;
    });
    const stop = () => {
      const timer = setTimeout(() => process.exit(1), 10000);
      timer.unref();
      server.close(() => clearTimeout(timer));
    };
    process.once('SIGTERM', stop);
    process.once('SIGINT', stop);
  }
} catch {
  console.error(JSON.stringify({ level: 'error', message: 'startup or healthcheck failed' }));
  process.exitCode = 1;
}
