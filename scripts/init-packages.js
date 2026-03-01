require('dotenv').config();
const fs = require('fs');
const path = require('path');

const { sequelize, Package, Image } = require('../core/db');
const { createLegacyStartupHelpers } = require('../core/helpers/legacy/startup-migration-helpers');

const { parseImportedImageJson } = createLegacyStartupHelpers({});
const CONFIG_PATH = path.join(__dirname, 'init-packages.config.json');

function isJsonFile(filename) {
    return String(filename || '').toLowerCase().endsWith('.json');
}

function collectJsonFiles(sourcePath) {
    const resolved = path.resolve(__dirname, sourcePath);
    if (!fs.existsSync(resolved)) return [];
    const stats = fs.statSync(resolved);
    if (stats.isFile()) {
        return isJsonFile(resolved) ? [resolved] : [];
    }
    if (!stats.isDirectory()) return [];

    const collected = [];
    const walk = (dir) => {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        entries.forEach((entry) => {
            const target = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walk(target);
                return;
            }
            if (entry.isFile() && isJsonFile(entry.name)) {
                collected.push(target);
            }
        });
    };
    walk(resolved);
    return collected;
}

function parseJsonCandidates(rawPayload) {
    if (Array.isArray(rawPayload)) {
        return rawPayload.filter((entry) => entry && typeof entry === 'object' && !Array.isArray(entry));
    }
    if (rawPayload && typeof rawPayload === 'object') {
        return [rawPayload];
    }
    return [];
}

async function upsertImageForPackage(imagePayload, packageId, sourceTag) {
    const normalized = parseImportedImageJson(imagePayload);
    normalized.packageId = packageId;
    normalized.configPath = sourceTag;

    const [image, created] = await Image.findOrCreate({
        where: { name: normalized.name },
        defaults: normalized
    });
    if (!created) {
        await image.update(normalized);
    }
    return { created, name: normalized.name };
}

async function ensurePackage(entry) {
    const name = String(entry.package || '').trim();
    if (!name) {
        throw new Error('Each import entry must include "package".');
    }
    const description = String(entry.description || '').trim() || `Auto-created by init:packages for ${name}`;
    const [pkg] = await Package.findOrCreate({
        where: { name },
        defaults: { name, description }
    });
    return pkg;
}

async function run() {
    if (!fs.existsSync(CONFIG_PATH)) {
        throw new Error(`Config file not found: ${CONFIG_PATH}`);
    }

    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    const imports = Array.isArray(config.imports) ? config.imports : [];
    if (imports.length === 0) {
        console.log('No imports configured in init-packages.config.json');
        return;
    }

    let totalCreated = 0;
    let totalUpdated = 0;
    let totalFailed = 0;

    for (const importEntry of imports) {
        const pkg = await ensurePackage(importEntry);
        const sources = Array.isArray(importEntry.sources) ? importEntry.sources : [];
        if (sources.length === 0) {
            console.log(`[init:packages] package=${pkg.name} has no sources, skipping.`);
            continue;
        }

        const files = Array.from(new Set(sources.flatMap((source) => collectJsonFiles(source))));
        if (files.length === 0) {
            console.log(`[init:packages] package=${pkg.name} no JSON files found in configured sources.`);
            continue;
        }

        console.log(`[init:packages] package=${pkg.name} files=${files.length}`);

        for (const filePath of files) {
            try {
                const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                const candidates = parseJsonCandidates(raw);
                if (candidates.length === 0) {
                    console.log(`[init:packages] skip (no object payload): ${filePath}`);
                    continue;
                }

                for (const candidate of candidates) {
                    try {
                        const sourceTag = `seed:${path.relative(path.join(__dirname, '..'), filePath)}`;
                        const result = await upsertImageForPackage(candidate, pkg.id, sourceTag);
                        if (result.created) {
                            totalCreated += 1;
                            console.log(`[init:packages] created: ${result.name}`);
                        } else {
                            totalUpdated += 1;
                            console.log(`[init:packages] updated: ${result.name}`);
                        }
                    } catch (entryError) {
                        totalFailed += 1;
                        const label = String(candidate && (candidate.name || (candidate.attributes && candidate.attributes.name)) || path.basename(filePath));
                        console.log(`[init:packages] failed entry=${label}: ${entryError.message}`);
                    }
                }
            } catch (fileError) {
                totalFailed += 1;
                console.log(`[init:packages] failed file=${filePath}: ${fileError.message}`);
            }
        }
    }

    console.log(`[init:packages] complete created=${totalCreated} updated=${totalUpdated} failed=${totalFailed}`);
}

run()
    .catch((error) => {
        console.error('[init:packages] fatal:', error.message || error);
        process.exitCode = 1;
    })
    .finally(async () => {
        try {
            await sequelize.close();
        } catch {
            // ignore close errors
        }
    });
