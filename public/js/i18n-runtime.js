(() => {
    if (window.__cpanelI18nRuntimeLoaded) return;
    window.__cpanelI18nRuntimeLoaded = true;

    const SKIP_TEXT_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'CODE', 'PRE']);
    const TRANSLATABLE_ATTRS = ['placeholder', 'title', 'aria-label'];
    let dictionariesPromise = null;
    let dictionariesLanguage = null;

    function getConfig() {
        const base = window.__CPANEL_I18N || {};
        return {
            lang: String(base.lang || 'english'),
            fallback: String(base.fallback || 'english')
        };
    }

    function normalize(value) {
        return String(value === undefined || value === null ? '' : value)
            .replace(/\s+/g, ' ')
            .trim();
    }

    function fetchJson(url) {
        return fetch(url, { cache: 'no-store', credentials: 'same-origin' })
            .then((response) => {
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return response.json();
            })
            .then((payload) => (payload && typeof payload === 'object' ? payload : {}))
            .catch(() => ({}));
    }

    function loadDictionaries() {
        const config = getConfig();
        if (dictionariesPromise && dictionariesLanguage === config.lang) return dictionariesPromise;
        dictionariesLanguage = config.lang;
        dictionariesPromise = (async () => {
            const english = await fetchJson('/lang/english.json');
            if (config.lang === 'english') {
                return {
                    lang: config.lang,
                    english,
                    target: english,
                    reverseRaw: new Map(),
                    reverseNormalized: new Map()
                };
            }

            const target = await fetchJson(`/lang/${encodeURIComponent(config.lang)}.json`);
            const reverseRaw = new Map();
            const reverseNormalized = new Map();

            for (const [key, value] of Object.entries(english)) {
                if (typeof value !== 'string') continue;
                if (!reverseRaw.has(value)) reverseRaw.set(value, key);
                const normalized = normalize(value);
                if (normalized && !reverseNormalized.has(normalized)) {
                    reverseNormalized.set(normalized, key);
                }
            }

            return {
                lang: config.lang,
                english,
                target,
                reverseRaw,
                reverseNormalized
            };
        })();
        return dictionariesPromise;
    }

    function translateLiteral(state, value) {
        const raw = String(value === undefined || value === null ? '' : value);
        if (!raw || state.lang === 'english') return raw;

        const directKey = state.reverseRaw.get(raw);
        const key = directKey || state.reverseNormalized.get(normalize(raw));
        if (!key) return raw;

        const translated = state.target[key] || state.english[key];
        return typeof translated === 'string' && translated.length ? translated : raw;
    }

    function translateTextNode(state, node) {
        if (!node || node.nodeType !== Node.TEXT_NODE) return;
        const parent = node.parentElement;
        if (!parent || SKIP_TEXT_TAGS.has(parent.tagName) || parent.closest('[data-no-i18n="true"]')) return;

        const original = node.nodeValue;
        if (!original || !original.trim()) return;
        const translated = translateLiteral(state, original.trim());
        if (!translated || translated === original.trim()) return;

        const leading = original.match(/^\s*/)?.[0] || '';
        const trailing = original.match(/\s*$/)?.[0] || '';
        node.nodeValue = `${leading}${translated}${trailing}`;
    }

    function translateAttributes(state, root) {
        const elements = root.querySelectorAll('*');
        for (const element of elements) {
            if (element.closest('[data-no-i18n="true"]')) continue;

            for (const attr of TRANSLATABLE_ATTRS) {
                const current = element.getAttribute(attr);
                if (!current || !current.trim()) continue;
                const translated = translateLiteral(state, current);
                if (translated && translated !== current) {
                    element.setAttribute(attr, translated);
                }
            }

            if (element.hasAttribute('value')) {
                const tag = element.tagName;
                const type = String((element.getAttribute('type') || '')).toLowerCase();
                const isButtonLike = tag === 'BUTTON'
                    || (tag === 'INPUT' && ['button', 'submit', 'reset'].includes(type));
                if (isButtonLike) {
                    const value = element.getAttribute('value') || '';
                    const translated = translateLiteral(state, value);
                    if (translated && translated !== value) {
                        element.setAttribute('value', translated);
                    }
                }
            }
        }
    }

    function translateByKeys(state, root) {
        const keyedNodes = root.querySelectorAll('[data-i18n-key]');
        for (const node of keyedNodes) {
            const key = String(node.getAttribute('data-i18n-key') || '').trim();
            if (!key) continue;
            const translated = state.target[key] || state.english[key];
            if (typeof translated !== 'string' || !translated.length) continue;
            node.textContent = translated;
        }
    }

    async function applyTranslations() {
        const state = await loadDictionaries();
        if (!state || state.lang === 'english') {
            const english = state && state.english && typeof state.english === 'object' ? state.english : {};
            window.cpanelI18n = {
                getLanguage: () => 'english',
                t: (key, fallback = '') => {
                    const translated = english[key];
                    if (typeof translated === 'string' && translated.length) return translated;
                    return fallback || key;
                },
                translateText: (text) => String(text === undefined || text === null ? '' : text)
            };
            document.dispatchEvent(new Event('cpanel:i18n-ready'));
            return;
        }

        const root = document.body || document.documentElement;
        if (!root) return;

        translateByKeys(state, root);
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
            translateTextNode(state, walker.currentNode);
        }
        translateAttributes(state, root);

        if (document.title) {
            document.title = translateLiteral(state, document.title);
        }

        window.cpanelI18n = {
            getLanguage: () => state.lang,
            t: (key, fallback = '') => {
                const translated = state.target[key] || state.english[key];
                if (typeof translated === 'string' && translated.length) return translated;
                return fallback || key;
            },
            translateText: (text) => translateLiteral(state, text)
        };

        document.dispatchEvent(new Event('cpanel:i18n-ready'));
    }

    function queueApplyTranslations() {
        applyTranslations().catch(() => {
            // Fail safe: keep original language if runtime translation fails.
        });
    }

    document.addEventListener('cpanel:page-load', queueApplyTranslations);
    document.addEventListener('turbo:load', queueApplyTranslations);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', queueApplyTranslations, { once: true });
    } else {
        queueApplyTranslations();
    }
})();
