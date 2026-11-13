import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { loadCatalog, prepareDictionary, validID, indexDictionaries } from '../src/catalog.js';

const dataDirectory = new URL('../data/', import.meta.url).pathname;
const seed = JSON.parse(await readFile(new URL('../data/versions/v1.json', import.meta.url), 'utf8'));
const catalogFor = word => ({ format: 'saypatch-rules', version: 1, variants: ['replacement'], rules: [{ word, category: 'banword', variantIds: [0] }] });

async function fixture(t, manifest, versions) {
  const directory = await mkdtemp(join(tmpdir(), 'banwords-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(join(directory, 'versions'));
  await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest));
  for (const [version, value] of Object.entries(versions)) {
    await writeFile(join(directory, 'versions', `${version}.json`), typeof value === 'string' ? value : JSON.stringify(value));
  }
  return directory;
}

test('seed preserves complete 22-rule composition and stable sp/1 id', async () => {
  const loaded = await loadCatalog(dataDirectory);
  assert.deepEqual(loaded.catalog, seed);
  assert.equal(seed.rules.length, 22);
  assert.equal(seed.rules.filter(rule => rule.category === 'banword').length, 21);
  assert.deepEqual(seed.rules.find(rule => rule.word === 'жид'), { word: 'жид', category: 'banword', matchMode: 'word', variantIds: [10] });
  const dictionary = prepareDictionary(seed.rules.map(rule => rule.word));
  assert.equal(dictionary.id, '0dMf');
  assert.equal(dictionary.digest.length, 64);
  assert.deepEqual(loaded.lookup(dictionary.id), [dictionary]);
  assert.deepEqual(loaded.lookup('zzzz'), []);
  assert.ok(dictionary.words.includes('денчик'));
});

test('sp/1 canonicalization uses JS lowercase, NFC, dedup and UTF16 sort', () => {
  const dictionary = prepareDictionary(['É', 'E\u0301', 'İ', 'ΟΣ', '𐐀', 'ﬀ', 'A']);
  assert.deepEqual(dictionary.words, ['a', 'i\u0307', 'é', 'ος', '𐐨', 'ﬀ']);
  const canonical = JSON.stringify(['sp', 1, 'dictionary', dictionary.words]);
  const digest = createHash('sha256').update(canonical, 'utf8').digest();
  assert.equal(dictionary.digest, digest.toString('hex'));
  assert.equal(dictionary.id, digest.subarray(0, 3).toString('base64url'));
  assert.deepEqual(prepareDictionary(['A', 'É']), prepareDictionary(['é', 'a', 'A']));
  assert.ok(Object.isFrozen(dictionary));
  assert.ok(Object.isFrozen(dictionary.words));
});

test('dictionary rejects invalid or unbounded words and validates short IDs', () => {
  for (const words of [null, [], Array(51).fill('a'), [''], [null], ['a'.repeat(101)], ['a b'], ['[x]'], ['\ud800']]) {
    assert.throws(() => prepareDictionary(words), /invalid dictionary/);
  }
  assert.equal(prepareDictionary(['a'.repeat(100)]).words[0].length, 100);
  for (const id of [null, '', 'aaa', 'aaaaa', 'AAAA\n', 'abcd=', 'ab/c', 'éééé']) assert.equal(validID(id), false);
  for (const id of ['abcd', '0dMf', '_-AZ']) assert.equal(validID(id), true);
});

test('previous versions remain readable and identical canonical dictionaries deduplicate', async t => {
  const directory = await fixture(t, { current: 'v2', versions: ['v1', 'v2', 'v3'] }, {
    v1: catalogFor('old'), v2: catalogFor('new'), v3: catalogFor('OLD'),
  });
  const loaded = await loadCatalog(directory);
  assert.equal(loaded.catalog.rules[0].word, 'new');
  assert.deepEqual(loaded.lookup(prepareDictionary(['old']).id), [prepareDictionary(['old'])]);
  assert.deepEqual(loaded.lookup(prepareDictionary(['new']).id), [prepareDictionary(['new'])]);
});

test('actual SHA24 collision returns both distinct canonical dictionaries', async t => {
  // A fixed birthday search avoids relying on a mocked hash implementation.
  const seen = new Map();
  let collision;
  for (let index = 0; index < 30000 && !collision; index++) {
    const word = `collision${index}`;
    const dictionary = prepareDictionary([word]);
    if (seen.has(dictionary.id)) collision = [seen.get(dictionary.id), word, dictionary.id];
    else seen.set(dictionary.id, word);
  }
  assert.ok(collision);
  const [first, second, id] = collision;
  const directory = await fixture(t, { current: 'v2', versions: ['v1', 'v2'] }, { v1: catalogFor(first), v2: catalogFor(second) });
  const loaded = await loadCatalog(directory);
  assert.equal(loaded.lookup(id).length, 2);
  assert.notEqual(loaded.lookup(id)[0].digest, loaded.lookup(id)[1].digest);
  assert.deepEqual(loaded.lookup(id).map(d => d.words), [[first], [second]]);
});

test('publication rejects more than eight different dictionaries per short identifier', () => {
  // Exercise the collision bucket independently of SHA256: a nine-way real
  // SHA24 collision is not a practical unit-test fixture.
  const dictionaries = Array.from({ length: 9 }, (_, index) => ({ ...prepareDictionary([`word${index}`]), id: 'AAAA' }));
  assert.equal(indexDictionaries(dictionaries.slice(0, 8)).get('AAAA').length, 8);
  assert.equal(indexDictionaries([...dictionaries.slice(0, 8), dictionaries[0]]).get('AAAA').length, 8);
  assert.throws(() => indexDictionaries(dictionaries), /too many dictionaries/);
});

test('invalid manifests, seed JSON and seed limits fail startup', async t => {
  for (const manifest of [ {}, { current: 'v1', versions: [] }, { current: 'v1', versions: ['../escape'] },
    { current: 'v2', versions: ['v1'] }, { current: 'v1', versions: ['v1', 'v1'] },
    { current: 'v1', versions: Array(65).fill('v1') }, { current: 'v1', versions: [null] } ]) {
    const directory = await fixture(t, manifest, {});
    await assert.rejects(loadCatalog(directory), /invalid manifest/);
  }
  for (const value of ['{', ' '.repeat(65537)]) {
    const directory = await fixture(t, { current: 'v1', versions: ['v1'] }, { v1: value });
    await assert.rejects(loadCatalog(directory));
  }
  const missing = await fixture(t, { current: 'v1', versions: ['v1'] }, {});
  await assert.rejects(loadCatalog(missing), /ENOENT/);
});

test('catalog rule fields and limits are validated before serving', async t => {
  const valid = catalogFor('word');
  for (const value of [null, { ...valid, format: 'other' }, { ...valid, version: 2 }, { ...valid, variants: null },
    { ...valid, variants: [] }, { ...valid, variants: [''] }, { ...valid, variants: [null] },
    { ...valid, variants: ['x'.repeat(101)] }, { ...valid, variants: Array(2501).fill('x') }, { ...valid, rules: {} },
    { ...valid, rules: [null] }, { ...valid, rules: [] } ]) {
    const directory = await fixture(t, { current: 'v1', versions: ['v1'] }, { v1: value });
    await assert.rejects(loadCatalog(directory));
  }
  for (const override of [{ word: 'x'.repeat(51) }, { category: 'other' }, { variantIds: null }, { variantIds: [] },
    { variantIds: Array(51).fill(0) }, { variantIds: [-1] }, { variantIds: [0.1] }, { variantIds: [1] },
    { matchMode: 'other' }, { replaceMode: 'other' }, { encode: 'true' }]) {
    const directory = await fixture(t, { current: 'v1', versions: ['v1'] }, { v1: { ...valid, rules: [{ ...valid.rules[0], ...override }] } });
    await assert.rejects(loadCatalog(directory));
  }
  const directory = await fixture(t, { current: 'v1', versions: ['v1'] }, { v1: {
    ...valid, rules: [{ ...valid.rules[0], matchMode: 'substring', replaceMode: 'match', encode: false }],
  } });
  assert.equal((await loadCatalog(directory)).catalog.rules[0].encode, false);
});
