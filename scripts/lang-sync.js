#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');

const LANG_DIR = path.join(__dirname, '..', 'public', 'lang');
const SOURCE_FILE = path.join(LANG_DIR, 'english.json');
const DELIMITER = '\n@@__CPANEL_SPLIT__@@\n';
const DEFAULT_CHUNK_SIZE = Number.parseInt(process.env.LANG_SYNC_CHUNK || '20', 10);
const DEFAULT_SLEEP_MS = Number.parseInt(process.env.LANG_SYNC_SLEEP_MS || '120', 10);
const DEFAULT_RETRIES = Number.parseInt(process.env.LANG_SYNC_RETRIES || '4', 10);

const TARGETS = [
    { code: 'es', fileName: 'espanol.json', label: 'Spanish' },
    { code: 'ro', fileName: 'romana.json', label: 'Romanian' }
];

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseArgs(argv) {
    const args = {
        force: false,
        only: null,
        limit: null,
        help: false
    };

    for (const token of argv) {
        if (token === '--force') {
            args.force = true;
            continue;
        }
        if (token === '--help' || token === '-h') {
            args.help = true;
            continue;
        }
        if (token.startsWith('--only=')) {
            args.only = token.slice('--only='.length).trim().toLowerCase() || null;
            continue;
        }
        if (token.startsWith('--limit=')) {
            const parsed = Number.parseInt(token.slice('--limit='.length).trim(), 10);
            args.limit = Number.isInteger(parsed) && parsed > 0 ? parsed : null;
            continue;
        }
    }

    return args;
}

function printHelp() {
    console.log('Usage: npm run lang:sync -- [options]');
    console.log('');
    console.log('Options:');
    console.log('  --force        Re-translate all keys, even if target values already exist.');
    console.log('  --only=es|ro   Translate only one target language.');
    console.log('  --limit=NUMBER Translate only first N pending keys (debug/testing).');
    console.log('  -h, --help     Show this help.');
    console.log('');
    console.log('Environment:');
    console.log('  LANG_SYNC_CHUNK      Batch size per request (default: 20)');
    console.log('  LANG_SYNC_SLEEP_MS   Delay between requests (default: 120)');
    console.log('  LANG_SYNC_RETRIES    Retries per failed request (default: 4)');
}

function readJsonObject(filePath, fallback = {}) {
    try {
        const raw = fs.readFileSync(filePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            return fallback;
        }
        return parsed;
    } catch {
        return fallback;
    }
}

function writeJsonObject(filePath, objectValue) {
    fs.writeFileSync(filePath, `${JSON.stringify(objectValue, null, 2)}\n`, 'utf8');
}

function decodeTranslateResponse(payload) {
    const parsed = JSON.parse(payload);
    if (!Array.isArray(parsed) || !Array.isArray(parsed[0])) {
        throw new Error('Unexpected translate response format.');
    }
    return parsed[0].map((part) => (Array.isArray(part) ? String(part[0] || '') : '')).join('');
}

function requestTranslate(text, targetLanguage) {
    return new Promise((resolve, reject) => {
        const params = new URLSearchParams({
            client: 'gtx',
            sl: 'en',
            tl: targetLanguage,
            dt: 't',
            q: text
        });

        const url = `https://translate.googleapis.com/translate_a/single?${params.toString()}`;

        https
            .get(url, { timeout: 25000 }, (response) => {
                if (response.statusCode && response.statusCode >= 400) {
                    response.resume();
                    reject(new Error(`HTTP ${response.statusCode}`));
                    return;
                }

                let body = '';
                response.setEncoding('utf8');
                response.on('data', (chunk) => {
                    body += chunk;
                });
                response.on('end', () => {
                    try {
                        resolve(decodeTranslateResponse(body));
                    } catch (error) {
                        reject(error);
                    }
                });
            })
            .on('timeout', function onTimeout() {
                this.destroy(new Error('Translate request timeout.'));
            })
            .on('error', (error) => reject(error));
    });
}

function normalizeForTranslate(value) {
    return String(value === undefined || value === null ? '' : value).replace(/\r\n/g, '\n');
}

function shouldTranslate(sourceValue, currentValue, force) {
    if (force) return true;
    if (typeof currentValue !== 'string') return true;
    if (!currentValue.trim()) return true;
    if (currentValue === sourceValue && /[a-z]{2,}/i.test(sourceValue)) return true;
    return false;
}

async function translateUniqueValues(pendingValues, targetCode, chunkSize, sleepMs, retries) {
    const uniqueValues = [];
    const seen = new Set();

    for (const value of pendingValues) {
        if (seen.has(value)) continue;
        seen.add(value);
        uniqueValues.push(value);
    }

    const translatedMap = new Map();
    const total = uniqueValues.length;
    if (!total) return translatedMap;

    console.log(`[lang-sync] ${targetCode}: translating ${total} unique values...`);

    for (let index = 0; index < total; index += chunkSize) {
        const chunk = uniqueValues.slice(index, index + chunkSize);
        const payload = chunk.join(DELIMITER);
        let translatedPayload = null;
        let lastError = null;

        for (let attempt = 1; attempt <= retries; attempt += 1) {
            try {
                translatedPayload = await requestTranslate(payload, targetCode);
                lastError = null;
                break;
            } catch (error) {
                lastError = error;
                console.warn(
                    `[lang-sync] ${targetCode}: retry ${attempt}/${retries} for chunk ${index} (${error.message})`
                );
                await sleep(600 * attempt);
            }
        }

        if (lastError || translatedPayload === null) {
            throw new Error(
                `Translation failed for ${targetCode} at chunk ${index}: ${lastError ? lastError.message : 'unknown error'}`
            );
        }

        const translatedParts = translatedPayload.split(DELIMITER);
        if (translatedParts.length !== chunk.length) {
            throw new Error(
                `Delimiter mismatch for ${targetCode} at chunk ${index}: expected ${chunk.length}, got ${translatedParts.length}`
            );
        }

        for (let i = 0; i < chunk.length; i += 1) {
            translatedMap.set(chunk[i], translatedParts[i]);
        }

        if (index % Math.max(chunkSize * 10, 200) === 0 || index + chunk.length >= total) {
            console.log(`[lang-sync] ${targetCode}: ${Math.min(index + chunk.length, total)}/${total}`);
        }

        if (sleepMs > 0) {
            await sleep(sleepMs);
        }
    }

    return translatedMap;
}

async function syncLanguage(englishObject, target, options) {
    const targetPath = path.join(LANG_DIR, target.fileName);
    const targetObject = readJsonObject(targetPath, {});
    const outputObject = {};
    const pendingKeys = [];

    const englishKeys = Object.keys(englishObject);
    for (const key of englishKeys) {
        const sourceValue = normalizeForTranslate(englishObject[key]);
        const currentValue = targetObject[key];

        if (shouldTranslate(sourceValue, currentValue, options.force)) {
            pendingKeys.push(key);
            continue;
        }

        outputObject[key] = String(currentValue);
    }

    let limitedPendingKeys = pendingKeys;
    if (Number.isInteger(options.limit) && options.limit > 0) {
        limitedPendingKeys = pendingKeys.slice(0, options.limit);
    }

    const pendingValues = limitedPendingKeys.map((key) => normalizeForTranslate(englishObject[key]));
    const translatedMap = await translateUniqueValues(
        pendingValues,
        target.code,
        options.chunkSize,
        options.sleepMs,
        options.retries
    );

    for (const key of limitedPendingKeys) {
        const sourceValue = normalizeForTranslate(englishObject[key]);
        const translated = translatedMap.get(sourceValue);
        outputObject[key] = typeof translated === 'string' && translated.length > 0
            ? translated
            : sourceValue;
    }

    if (limitedPendingKeys.length < pendingKeys.length) {
        for (let i = limitedPendingKeys.length; i < pendingKeys.length; i += 1) {
            const key = pendingKeys[i];
            const existing = targetObject[key];
            outputObject[key] = typeof existing === 'string' && existing.length > 0
                ? existing
                : normalizeForTranslate(englishObject[key]);
        }
    }

    writeJsonObject(targetPath, outputObject);

    console.log(
        `[lang-sync] ${target.fileName}: total=${englishKeys.length}, translated_now=${limitedPendingKeys.length}, kept=${englishKeys.length - limitedPendingKeys.length}`
    );
}

async function main() {
    const cli = parseArgs(process.argv.slice(2));
    if (cli.help) {
        printHelp();
        return;
    }

    if (!fs.existsSync(SOURCE_FILE)) {
        throw new Error(`Missing source language file: ${SOURCE_FILE}`);
    }

    const englishObject = readJsonObject(SOURCE_FILE, null);
    if (!englishObject || typeof englishObject !== 'object' || Array.isArray(englishObject)) {
        throw new Error('english.json must be a flat JSON object.');
    }

    const selectedTargets = cli.only
        ? TARGETS.filter((target) => target.code === cli.only || target.fileName === cli.only)
        : TARGETS.slice();

    if (!selectedTargets.length) {
        throw new Error(`Invalid --only value "${cli.only}". Use "es" or "ro".`);
    }

    const options = {
        force: cli.force,
        limit: cli.limit,
        chunkSize: Number.isInteger(DEFAULT_CHUNK_SIZE) && DEFAULT_CHUNK_SIZE > 0 ? DEFAULT_CHUNK_SIZE : 20,
        sleepMs: Number.isInteger(DEFAULT_SLEEP_MS) && DEFAULT_SLEEP_MS >= 0 ? DEFAULT_SLEEP_MS : 120,
        retries: Number.isInteger(DEFAULT_RETRIES) && DEFAULT_RETRIES > 0 ? DEFAULT_RETRIES : 4
    };

    console.log('[lang-sync] source:', SOURCE_FILE);
    console.log('[lang-sync] targets:', selectedTargets.map((t) => t.fileName).join(', '));
    console.log('[lang-sync] options:', JSON.stringify(options));

    for (const target of selectedTargets) {
        await syncLanguage(englishObject, target, options);
    }

    console.log('[lang-sync] done.');
}

main().catch((error) => {
    console.error('[lang-sync] failed:', error.message);
    process.exit(1);
});
