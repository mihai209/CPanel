const fs = require('fs');
const path = require('path');

const LANG_DIR = path.join(process.cwd(), 'public', 'lang');
const FALLBACK_LANGUAGE = 'english';
const LANGUAGE_ALIASES = {
    en: 'english',
    'en-us': 'english',
    'en-gb': 'english',
    ro: 'romana',
    'ro-ro': 'romana',
    es: 'espanol',
    'es-es': 'espanol',
    'es-419': 'espanol'
};

let cache = {
    loadedAt: 0,
    ttlMs: 5000,
    byCode: {},
    codes: [FALLBACK_LANGUAGE],
    englishReverseRaw: new Map(),
    englishReverseNormalized: new Map()
};

function normalizeText(value) {
    return String(value === undefined || value === null ? '' : value)
        .replace(/\s+/g, ' ')
        .trim();
}

function sanitizeLanguageCode(raw) {
    const normalized = String(raw || '')
        .trim()
        .toLowerCase()
        .replace(/\.json$/i, '');
    if (!normalized) return '';
    if (/^[a-z0-9_-]{2,40}$/.test(normalized)) return normalized;
    return '';
}

function buildEnglishReverseMaps(englishDictionary) {
    const reverseRaw = new Map();
    const reverseNormalized = new Map();

    for (const [key, value] of Object.entries(englishDictionary || {})) {
        if (typeof value !== 'string') continue;
        if (!reverseRaw.has(value)) {
            reverseRaw.set(value, key);
        }
        const normalized = normalizeText(value);
        if (normalized && !reverseNormalized.has(normalized)) {
            reverseNormalized.set(normalized, key);
        }
    }

    return { reverseRaw, reverseNormalized };
}

function loadLanguageCache(force = false) {
    const now = Date.now();
    if (!force && now - cache.loadedAt < cache.ttlMs) {
        return cache;
    }

    const byCode = {};
    const codes = [];

    try {
        if (!fs.existsSync(LANG_DIR)) {
            fs.mkdirSync(LANG_DIR, { recursive: true });
        }
        const entries = fs.readdirSync(LANG_DIR, { withFileTypes: true });
        const files = entries
            .filter((entry) => entry && entry.isFile() && /\.json$/i.test(entry.name))
            .map((entry) => entry.name)
            .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

        for (const fileName of files) {
            const code = sanitizeLanguageCode(fileName);
            if (!code) continue;
            const filePath = path.join(LANG_DIR, fileName);
            try {
                const payload = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                if (!payload || typeof payload !== 'object' || Array.isArray(payload)) continue;
                byCode[code] = payload;
                codes.push(code);
            } catch {
                // Ignore invalid language file.
            }
        }
    } catch {
        // Keep fallback below.
    }

    if (!byCode[FALLBACK_LANGUAGE]) {
        byCode[FALLBACK_LANGUAGE] = {};
        if (!codes.includes(FALLBACK_LANGUAGE)) {
            codes.unshift(FALLBACK_LANGUAGE);
        }
    }

    const englishDictionary = byCode[FALLBACK_LANGUAGE] || {};
    const { reverseRaw, reverseNormalized } = buildEnglishReverseMaps(englishDictionary);

    cache = {
        ...cache,
        loadedAt: now,
        byCode,
        codes: Array.from(new Set(codes.length ? codes : [FALLBACK_LANGUAGE])),
        englishReverseRaw: reverseRaw,
        englishReverseNormalized: reverseNormalized
    };

    return cache;
}

function getAvailableLanguageCodes() {
    return loadLanguageCache().codes.slice();
}

function resolveLanguageCode(rawCode) {
    const current = loadLanguageCache();
    const sanitized = sanitizeLanguageCode(rawCode);
    const alias = LANGUAGE_ALIASES[sanitized] || sanitized;
    if (alias && current.byCode[alias]) {
        return alias;
    }
    return FALLBACK_LANGUAGE;
}

function parseCookieValue(req, key) {
    const cookieHeader = String((req && req.headers && req.headers.cookie) || '');
    if (!cookieHeader) return '';
    const parts = cookieHeader.split(';');
    for (const part of parts) {
        const [name, ...rest] = part.split('=');
        if (!name || !rest.length) continue;
        if (name.trim() !== key) continue;
        return decodeURIComponent(rest.join('=').trim());
    }
    return '';
}

function parseAcceptLanguage(req) {
    const raw = String((req && req.headers && req.headers['accept-language']) || '').trim();
    if (!raw) return '';
    const first = raw.split(',')[0] || '';
    const base = first.split(';')[0] || '';
    return base.trim().toLowerCase();
}

function resolveRequestLanguage(req) {
    const candidates = [
        req && req.query ? req.query.lang : null,
        req && req.body ? req.body.lang : null,
        req && req.session ? req.session.uiLanguage : null,
        parseCookieValue(req, 'cpanel_lang'),
        parseAcceptLanguage(req)
    ];

    for (const candidate of candidates) {
        const resolved = resolveLanguageCode(candidate);
        if (resolved && resolved !== FALLBACK_LANGUAGE) {
            return resolved;
        }
    }

    return resolveLanguageCode(candidates[0]) || FALLBACK_LANGUAGE;
}

function getLanguageDictionary(languageCode) {
    const current = loadLanguageCache();
    const resolved = resolveLanguageCode(languageCode);
    return {
        code: resolved,
        dictionary: current.byCode[resolved] || {},
        fallbackDictionary: current.byCode[FALLBACK_LANGUAGE] || {}
    };
}

function translateByKey(languageCode, key, fallback = '') {
    const { dictionary, fallbackDictionary } = getLanguageDictionary(languageCode);
    if (dictionary && typeof dictionary[key] === 'string' && dictionary[key].length > 0) {
        return dictionary[key];
    }
    if (fallbackDictionary && typeof fallbackDictionary[key] === 'string' && fallbackDictionary[key].length > 0) {
        return fallbackDictionary[key];
    }
    if (fallback) return fallback;
    return key;
}

function translateText(languageCode, text) {
    if (text === undefined || text === null) return text;
    const rawText = String(text);
    const resolvedCode = resolveLanguageCode(languageCode);
    if (resolvedCode === FALLBACK_LANGUAGE) return rawText;

    const current = loadLanguageCache();
    const targetDictionary = current.byCode[resolvedCode] || {};
    const fallbackDictionary = current.byCode[FALLBACK_LANGUAGE] || {};

    const directKey = current.englishReverseRaw.get(rawText);
    let translationKey = directKey;
    if (!translationKey) {
        const normalized = normalizeText(rawText);
        if (normalized) {
            translationKey = current.englishReverseNormalized.get(normalized);
        }
    }

    if (!translationKey) return rawText;

    const translated = targetDictionary[translationKey] || fallbackDictionary[translationKey];
    if (typeof translated !== 'string' || !translated.length) {
        return rawText;
    }

    return translated;
}

module.exports = {
    FALLBACK_LANGUAGE,
    getAvailableLanguageCodes,
    resolveLanguageCode,
    resolveRequestLanguage,
    getLanguageDictionary,
    translateByKey,
    translateText,
    loadLanguageCache
};
