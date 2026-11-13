import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

export const MAX_FILE_BYTES = 64 * 1024;
const identifier = /^[A-Za-z0-9_-]{4}$/;
const wordPattern = /^[\p{L}\p{M}\p{N}_]+$/u;

// This is the sp/1 wire format from extension/core.js. In particular Array.sort
// compares UTF-16 code units, and lowercase is JavaScript Unicode lowercase.
export function prepareDictionary(input) {
  if (!Array.isArray(input) || !input.length || input.length > 50 || input.some(word =>
    typeof word !== 'string' || !word.length || word.length > 100 || !wordPattern.test(word))) {
    throw new Error('invalid dictionary');
  }
  const words = [...new Set(input.map(word => word.normalize('NFC').toLowerCase().normalize('NFC')))].sort();
  const canonical = JSON.stringify(['sp', 1, 'dictionary', words]);
  const hash = createHash('sha256').update(canonical).digest();
  return Object.freeze({ id: hash.subarray(0, 3).toString('base64url'), digest: hash.toString('hex'), words: Object.freeze(words) });
}

export function validID(id) {
  return typeof id === 'string' && id.length === 4 && identifier.test(id);
}

function validateCatalog(value) {
  if (!value || value.format !== 'saypatch-rules' || value.version !== 1 || !Array.isArray(value.variants) ||
    !value.variants.length || value.variants.length > 2500 || value.variants.some(v =>
      typeof v !== 'string' || !v.trim() || v.length > 100) || !Array.isArray(value.rules)) throw new Error('invalid catalog');
  prepareDictionary(value.rules.map(rule => rule?.word));
  for (const rule of value.rules) {
    if (!rule || rule.word.length > 50 || !['safe', 'banword'].includes(rule.category) || !Array.isArray(rule.variantIds) ||
      !rule.variantIds.length || rule.variantIds.length > 50 || rule.variantIds.some(id =>
        !Number.isInteger(id) || id < 0 || id >= value.variants.length) ||
      (rule.matchMode !== undefined && !['word', 'substring'].includes(rule.matchMode)) ||
      (rule.replaceMode !== undefined && !['word', 'match'].includes(rule.replaceMode)) ||
      (rule.encode !== undefined && typeof rule.encode !== 'boolean')) throw new Error('invalid rule');
  }
  return value;
}

async function readJSON(path) {
  const raw = await readFile(path);
  if (raw.length > MAX_FILE_BYTES) throw new Error('seed file too large');
  return JSON.parse(raw.toString('utf8'));
}

export function indexDictionaries(dictionaries) {
  const index = new Map();
  for (const dictionary of dictionaries) {
    const matches = index.get(dictionary.id) || [];
    if (!matches.some(existing => existing.digest === dictionary.digest)) {
      if (matches.length >= 8) throw new Error('too many dictionaries with the same id');
      matches.push(dictionary);
    }
    index.set(dictionary.id, matches);
  }
  return index;
}

export async function loadCatalog(directory) {
  const manifest = await readJSON(join(directory, 'manifest.json'));
  if (!Array.isArray(manifest.versions) || !manifest.versions.length || manifest.versions.length > 64 ||
    manifest.versions.some(version => typeof version !== 'string' || !/^v[1-9][0-9]{0,5}$/.test(version)) ||
    new Set(manifest.versions).size !== manifest.versions.length || !manifest.versions.includes(manifest.current)) {
    throw new Error('invalid manifest');
  }
  const catalogs = await Promise.all(manifest.versions.map(async version =>
    [version, validateCatalog(await readJSON(join(directory, 'versions', `${version}.json`)))]));
  const index = indexDictionaries(catalogs.map(([, catalog]) => prepareDictionary(catalog.rules.map(rule => rule.word))));
  return {
    catalog: catalogs.find(([version]) => version === manifest.current)[1],
    lookup: id => index.get(id) || [],
  };
}
