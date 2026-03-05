function createLegacyStartupHelpers(deps) {
    const { Settings, Server, Allocation, Op, axios } = deps;
    const INTERNAL_ENV_KEYS = ['SERVER_MEMORY', 'SERVER_IP', 'SERVER_PORT'];
    const DEFAULT_IMAGE_PORTS = [{ container: 25565, protocol: 'tcp' }];
    const STARTUP_SINGLE_PLACEHOLDER_REGEX = /\{([A-Za-z0-9_]+)\}/g;
    const STARTUP_DOUBLE_PLACEHOLDER_REGEX = /\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g;

function normalizeClientVariables(rawVariables) {
    if (!rawVariables || typeof rawVariables !== 'object' || Array.isArray(rawVariables)) {
        return {};
    }

    const normalized = {};
    Object.entries(rawVariables).forEach(([key, value]) => {
        normalized[key] = value === null || value === undefined ? '' : String(value);
    });
    return normalized;
}

function resolveImagePorts(imagePorts) {
    if (imagePorts === null || imagePorts === undefined) {
        return DEFAULT_IMAGE_PORTS.map(port => ({ ...port }));
    }

    if (typeof imagePorts === 'string') {
        try {
            imagePorts = JSON.parse(imagePorts);
        } catch (error) {
            throw new Error('Image ports configuration is invalid JSON.');
        }
    }

    if (!Array.isArray(imagePorts)) {
        throw new Error('Image ports configuration is invalid.');
    }

    if (imagePorts.length !== 1) {
        throw new Error('Image ports policy violation: single-port strict supports exactly one port.');
    }

    return imagePorts.map((port, index) => {
        if (!port || typeof port !== 'object') {
            throw new Error(`Image port at index ${index} is invalid.`);
        }

        const containerPort = Number.parseInt(port.container, 10);
        if (!Number.isInteger(containerPort) || containerPort < 1 || containerPort > 65535) {
            throw new Error(`Image port at index ${index} has an invalid container port.`);
        }

        const protocol = (port.protocol || 'tcp').toString().toLowerCase();
        if (!['tcp', 'udp'].includes(protocol)) {
            throw new Error(`Image port at index ${index} uses unsupported protocol "${protocol}".`);
        }

        return { container: containerPort, protocol };
    });
}

function buildDeploymentPorts(input) {
    const source = input && typeof input === 'object' ? input : {};
    const imagePorts = Array.isArray(source.imagePorts)
        ? source.imagePorts
        : resolveImagePorts(source.imagePorts);
    const env = source.env && typeof source.env === 'object' ? source.env : {};

    const primaryAllocation = source.primaryAllocation && typeof source.primaryAllocation === 'object'
        ? source.primaryAllocation
        : null;
    const extraAllocations = Array.isArray(source.allocations)
        ? source.allocations.filter((entry) => entry && typeof entry === 'object')
        : [];

    const allocations = [];
    if (primaryAllocation && Number.isInteger(Number.parseInt(primaryAllocation.port, 10))) {
        allocations.push(primaryAllocation);
    }
    extraAllocations.forEach((allocation) => {
        const id = Number.parseInt(allocation.id, 10);
        const port = Number.parseInt(allocation.port, 10);
        if (!Number.isInteger(port) || port < 1 || port > 65535) return;
        if (Number.isInteger(id) && allocations.some((entry) => Number.parseInt(entry.id, 10) === id)) return;
        if (!Number.isInteger(id) && allocations.some((entry) => Number.parseInt(entry.port, 10) === port && String(entry.ip || '') === String(allocation.ip || ''))) return;
        allocations.push(allocation);
    });

    if (allocations.length === 0) {
        return [];
    }

    const protocols = Array.from(new Set(
        imagePorts
            .map((port) => String((port && port.protocol) || 'tcp').toLowerCase())
            .filter((protocol) => protocol === 'tcp' || protocol === 'udp')
    ));
    if (protocols.length === 0) {
        protocols.push('tcp');
    }

    const primaryPort = primaryAllocation
        ? (Number.parseInt(env.SERVER_PORT, 10) || Number.parseInt(primaryAllocation.port, 10))
        : 0;
    const deploymentPorts = [];

    allocations.forEach((allocation) => {
        const hostPort = Number.parseInt(allocation.port, 10);
        if (!Number.isInteger(hostPort) || hostPort < 1 || hostPort > 65535) return;
        const isPrimary = primaryAllocation && Number.parseInt(primaryAllocation.id, 10) === Number.parseInt(allocation.id, 10);
        const containerPort = isPrimary
            ? (Number.isInteger(primaryPort) && primaryPort > 0 ? primaryPort : hostPort)
            : hostPort;
        const ip = String(allocation.ip || '').trim();
        protocols.forEach((protocol) => {
            deploymentPorts.push({
                container: containerPort,
                ip,
                host: hostPort,
                protocol
            });
        });
    });

    return deploymentPorts;
}

function resolveImageDockerChoices(image) {
    const choices = [];
    const seen = new Set();

    if (image && image.dockerImages && typeof image.dockerImages === 'object' && !Array.isArray(image.dockerImages)) {
        Object.entries(image.dockerImages).forEach(([label, tag]) => {
            const normalizedTag = typeof tag === 'string' ? tag.trim() : '';
            if (!normalizedTag || seen.has(normalizedTag)) return;
            seen.add(normalizedTag);
            choices.push({
                label: String(label || normalizedTag).trim() || normalizedTag,
                tag: normalizedTag
            });
        });
    }

    const fallbackTag = image && typeof image.dockerImage === 'string' ? image.dockerImage.trim() : '';
    if (fallbackTag && !seen.has(fallbackTag)) {
        choices.unshift({ label: 'Default', tag: fallbackTag });
    }

    return choices;
}

function resolveImageVariableDefinitions(image) {
    if (Array.isArray(image.eggVariables) && image.eggVariables.length > 0) {
        return image.eggVariables.map((entry) => ({
            env_variable: entry.env_variable,
            default_value: entry.default_value,
            name: entry.name,
            description: entry.description,
            rules: entry.rules,
            user_viewable: entry.user_viewable,
            user_editable: entry.user_editable
        }));
    }

    const definitions = [];
    const envMap = image && image.environment && typeof image.environment === 'object' && !Array.isArray(image.environment)
        ? image.environment
        : {};
    const metaMap = image && image.environmentMeta && typeof image.environmentMeta === 'object' && !Array.isArray(image.environmentMeta)
        ? image.environmentMeta
        : {};

    Object.entries(envMap).forEach(([key, value]) => {
        const meta = metaMap[key] || {};
        definitions.push({
            env_variable: key,
            default_value: value,
            name: meta.name || key,
            description: meta.description || '',
            rules: meta.rules || '',
            user_viewable: meta.userViewable === false ? 0 : 1,
            user_editable: meta.userEditable === false ? 0 : 1
        });
    });

    return definitions;
}

function buildServerEnvironment(image, rawVariables, runtimeValues) {
    const userVariables = normalizeClientVariables(rawVariables);
    const isLegacy = !image.eggVariables || image.eggVariables.length === 0;

    let variablesArray = isLegacy ? [] : image.eggVariables;
    if (isLegacy && image.environment) {
        for (const [key, val] of Object.entries(image.environment)) {
            variablesArray.push({
                env_variable: key,
                default_value: val,
                user_editable: image.environmentMeta?.[key]?.userEditable !== false ? 1 : 0,
                rules: image.environmentMeta?.[key]?.rules || ''
            });
        }
    }

    const allowedKeys = new Set(variablesArray.map(v => v.env_variable));
    const invalidKeys = Object.keys(userVariables).filter(key => !allowedKeys.has(key));

    if (invalidKeys.length > 0) {
        throw new Error(`Invalid environment variables: ${invalidKeys.join(', ')}`);
    }

    const resolvedVariables = {};
    for (const v of variablesArray) {
        const key = v.env_variable;
        const defaultValue = v.default_value;
        const hasOverride = Object.prototype.hasOwnProperty.call(userVariables, key);
        const resolvedValue = hasOverride ? userVariables[key] : defaultValue;
        const asString = resolvedValue === null || resolvedValue === undefined ? '' : String(resolvedValue);
        const defaultString = defaultValue === null || defaultValue === undefined ? '' : String(defaultValue);

        const isEditable = v.user_editable == 1 || v.user_editable === true;

        if (hasOverride && !isEditable && asString !== defaultString) {
            throw new Error(`Variable "${key}" cannot be modified for this image.`);
        }

        validateEnvironmentValue(key, asString, v.rules || '');
        resolvedVariables[key] = asString;
    }

    const env = { ...resolvedVariables };
    INTERNAL_ENV_KEYS.forEach((key) => {
        const rawValue = runtimeValues[key];
        const asString = rawValue === null || rawValue === undefined ? '' : String(rawValue);
        if (!asString.trim()) {
            throw new Error(`Internal environment value "${key}" is missing.`);
        }
        env[key] = asString;
    });

    return { resolvedVariables, env };
}

function parseRuleTokens(rulesString) {
    if (typeof rulesString !== 'string' || !rulesString.trim()) {
        return [];
    }

    const regexTokens = [];
    const placeholderSafe = rulesString.replace(/regex:\/(?:\\.|[^/])+\/[a-z]*/gi, (match) => {
        const tokenId = regexTokens.length;
        regexTokens.push(match);
        return `__REGEX_TOKEN_${tokenId}__`;
    });

    return placeholderSafe
        .split('|')
        .map((token) => token.trim())
        .filter(Boolean)
        .map((token) => {
            const placeholderMatch = token.match(/^__REGEX_TOKEN_(\d+)__$/);
            if (!placeholderMatch) return token;
            const index = Number.parseInt(placeholderMatch[1], 10);
            return regexTokens[index] || token;
        });
}

function validateEnvironmentValue(key, value, rulesString) {
    const tokens = parseRuleTokens(rulesString);
    if (tokens.length === 0) return;

    const hasRequired = tokens.includes('required');
    const hasNullable = tokens.includes('nullable');
    const trimmed = value.trim();

    if (!trimmed) {
        if (hasRequired && !hasNullable) {
            throw new Error(`Variable "${key}" is required and cannot be empty.`);
        }
        return;
    }

    const hasInteger = tokens.includes('integer');
    const hasNumeric = tokens.includes('numeric');
    const parsedNumber = Number.parseFloat(value);
    const isNumberValid = Number.isFinite(parsedNumber);

    for (const token of tokens) {
        if (token === 'required' || token === 'nullable' || token === 'string') {
            continue;
        }

        if (token === 'integer') {
            if (!/^-?\d+$/.test(value)) {
                throw new Error(`Variable "${key}" must be an integer.`);
            }
            continue;
        }

        if (token === 'numeric') {
            if (!/^-?\d+(\.\d+)?$/.test(value)) {
                throw new Error(`Variable "${key}" must be numeric.`);
            }
            continue;
        }

        if (token === 'boolean') {
            if (!/^(true|false|1|0|yes|no|on|off)$/i.test(value)) {
                throw new Error(`Variable "${key}" must be a boolean value.`);
            }
            continue;
        }

        if (token === 'alpha_num') {
            if (!/^[a-z0-9]+$/i.test(value)) {
                throw new Error(`Variable "${key}" must be alphanumeric.`);
            }
            continue;
        }

        if (token.startsWith('in:')) {
            const allowed = token.slice(3).split(',').map((entry) => entry.trim()).filter(Boolean);
            if (allowed.length > 0 && !allowed.includes(value)) {
                throw new Error(`Variable "${key}" must be one of: ${allowed.join(', ')}.`);
            }
            continue;
        }

        if (token.startsWith('min:')) {
            const minValue = Number.parseFloat(token.slice(4));
            if (!Number.isFinite(minValue)) continue;

            if ((hasInteger || hasNumeric) && isNumberValid) {
                if (parsedNumber < minValue) {
                    throw new Error(`Variable "${key}" must be >= ${minValue}.`);
                }
            } else if (value.length < minValue) {
                throw new Error(`Variable "${key}" must have at least ${minValue} characters.`);
            }
            continue;
        }

        if (token.startsWith('max:')) {
            const maxValue = Number.parseFloat(token.slice(4));
            if (!Number.isFinite(maxValue)) continue;

            if ((hasInteger || hasNumeric) && isNumberValid) {
                if (parsedNumber > maxValue) {
                    throw new Error(`Variable "${key}" must be <= ${maxValue}.`);
                }
            } else if (value.length > maxValue) {
                throw new Error(`Variable "${key}" must have at most ${maxValue} characters.`);
            }
            continue;
        }

        if (token.startsWith('between:')) {
            const bounds = token.slice(8).split(',').map((entry) => Number.parseFloat(entry.trim()));
            if (bounds.length !== 2 || !Number.isFinite(bounds[0]) || !Number.isFinite(bounds[1])) continue;
            const [minValue, maxValue] = bounds;

            if ((hasInteger || hasNumeric) && isNumberValid) {
                if (parsedNumber < minValue || parsedNumber > maxValue) {
                    throw new Error(`Variable "${key}" must be between ${minValue} and ${maxValue}.`);
                }
            } else if (value.length < minValue || value.length > maxValue) {
                throw new Error(`Variable "${key}" length must be between ${minValue} and ${maxValue}.`);
            }
            continue;
        }

        if (token.startsWith('regex:')) {
            const ruleBody = token.slice(6);
            const firstSlash = ruleBody.indexOf('/');
            const lastSlash = ruleBody.lastIndexOf('/');
            if (firstSlash !== 0 || lastSlash <= 0) continue;

            const pattern = ruleBody.slice(1, lastSlash);
            const flags = ruleBody.slice(lastSlash + 1);
            let regex = null;
            try {
                regex = new RegExp(pattern, flags);
            } catch (regexError) {
                // Ignore invalid regex rules from imported eggs instead of hard-crashing deploy.
                continue;
            }

            if (!regex.test(value)) {
                throw new Error(`Variable "${key}" does not match required format.`);
            }
        }
    }
}

function buildStartupCommand(startupTemplate, env) {
    if (typeof startupTemplate !== 'string' || !startupTemplate.trim()) {
        throw new Error('Image startup command is missing.');
    }

    const replaceValue = (fullMatch, key) => {
        if (!Object.prototype.hasOwnProperty.call(env, key)) {
            return fullMatch;
        }
        return env[key];
    };

    let startup = startupTemplate
        .replace(STARTUP_DOUBLE_PLACEHOLDER_REGEX, replaceValue)
        .replace(STARTUP_SINGLE_PLACEHOLDER_REGEX, replaceValue);

    const unresolved = [
        ...Array.from(startup.matchAll(STARTUP_DOUBLE_PLACEHOLDER_REGEX)).map((match) => match[1]),
        ...Array.from(startup.matchAll(STARTUP_SINGLE_PLACEHOLDER_REGEX)).map((match) => match[1])
    ];
    if (unresolved.length > 0) {
        const uniqueUnresolved = [...new Set(unresolved)];
        throw new Error(`Startup contains unresolved placeholders: ${uniqueUnresolved.join(', ')}`);
    }

    return startup;
}

const STARTUP_PRESET_DEFINITIONS = [
    {
        id: 'paper_stable',
        label: 'Paper Stable',
        description: 'Paper with pinned Minecraft version and latest build.',
        imageKeywords: ['paper'],
        variables: {
            MINECRAFT_VERSION: '1.20.4',
            BUILD_NUMBER: 'latest',
            SERVER_JARFILE: 'server.jar'
        }
    },
    {
        id: 'purpur_stable',
        label: 'Purpur Stable',
        description: 'Purpur latest build for a known stable branch.',
        imageKeywords: ['purpur'],
        variables: {
            MINECRAFT_VERSION: '1.20.4',
            BUILD_NUMBER: 'latest',
            SERVER_JARFILE: 'server.jar'
        }
    },
    {
        id: 'forge_lts',
        label: 'Forge LTS',
        description: 'Forge profile for common modern LTS combinations.',
        imageKeywords: ['forge'],
        variables: {
            MC_VERSION: '1.20.1',
            FORGE_VERSION: 'latest'
        }
    },
    {
        id: 'fabric_latest',
        label: 'Fabric Latest',
        description: 'Fabric loader with a modern Minecraft baseline.',
        imageKeywords: ['fabric'],
        variables: {
            MINECRAFT_VERSION: '1.20.4',
            LOADER_VERSION: 'latest'
        }
    },
    {
        id: 'java_legacy',
        label: 'Java Legacy 1.8.x',
        description: 'Legacy Java profile for old server branches.',
        imageKeywords: ['java', 'spigot', 'bukkit'],
        variables: {
            MINECRAFT_VERSION: '1.8.8',
            BUILD_NUMBER: 'latest'
        }
    }
];

function getServerStartupPresetSettingKey(serverId) {
    return `${SERVER_STARTUP_PRESET_KEY_PREFIX}${serverId}`;
}

async function getServerStartupPresetSelection(serverId) {
    const row = await Settings.findByPk(getServerStartupPresetSettingKey(serverId));
    if (!row || !row.value) return '';
    return String(row.value).trim();
}

async function setServerStartupPresetSelection(serverId, presetId) {
    const normalized = String(presetId || '').trim();
    if (!normalized) {
        await Settings.destroy({ where: { key: getServerStartupPresetSettingKey(serverId) } });
        return '';
    }
    await Settings.upsert({
        key: getServerStartupPresetSettingKey(serverId),
        value: normalized
    });
    return normalized;
}

function getStartupPresetsForImage(image, variableDefinitions) {
    const imageDescriptor = `${String(image && image.name ? image.name : '')} ${String(image && image.description ? image.description : '')}`.toLowerCase();
    const availableKeys = new Set((variableDefinitions || []).map((entry) => String(entry.env_variable || '').trim()).filter(Boolean));

    return STARTUP_PRESET_DEFINITIONS
        .filter((preset) => {
            if (!preset || !preset.id) return false;
            if (Array.isArray(preset.imageKeywords) && preset.imageKeywords.length > 0) {
                const matchesKeyword = preset.imageKeywords.some((keyword) => imageDescriptor.includes(String(keyword || '').toLowerCase()));
                if (!matchesKeyword) return false;
            }
            return Object.keys(preset.variables || {}).some((key) => availableKeys.has(key));
        })
        .map((preset) => {
            const compatibleVariables = {};
            const incompatibleVariables = [];
            Object.entries(preset.variables || {}).forEach(([key, value]) => {
                if (availableKeys.has(key)) {
                    compatibleVariables[key] = String(value);
                } else {
                    incompatibleVariables.push(key);
                }
            });
            return {
                id: preset.id,
                label: preset.label,
                description: preset.description,
                variables: compatibleVariables,
                incompatibleVariables
            };
        });
}

function applyStartupPresetVariables(currentVariables, preset, variableDefinitions) {
    if (!preset || !preset.variables || Object.keys(preset.variables).length === 0) {
        return { variables: currentVariables, appliedKeys: [] };
    }

    const definitionMap = new Map((variableDefinitions || []).map((entry) => [String(entry.env_variable || ''), entry]));
    const nextVariables = { ...currentVariables };
    const appliedKeys = [];

    Object.entries(preset.variables).forEach(([key, value]) => {
        if (!definitionMap.has(key)) return;
        const asString = value === null || value === undefined ? '' : String(value);
        const definition = definitionMap.get(key);
        validateEnvironmentValue(key, asString, definition && definition.rules ? definition.rules : '');
        nextVariables[key] = asString;
        appliedKeys.push(key);
    });

    if (appliedKeys.length === 0) {
        throw new Error('Selected startup preset is not compatible with this image variables.');
    }
    return { variables: nextVariables, appliedKeys };
}

function looksLikeDockerImageReference(value) {
    if (typeof value !== 'string') return false;
    const trimmed = value.trim();
    if (!trimmed) return false;
    return trimmed.includes('/') || trimmed.includes(':');
}

function normalizeImportedDockerImages(rawDockerImages, fallbackDockerImage = '') {
    if (!rawDockerImages || typeof rawDockerImages !== 'object' || Array.isArray(rawDockerImages)) {
        return {};
    }

    const normalized = {};
    for (const [rawKey, rawValue] of Object.entries(rawDockerImages)) {
        if (typeof rawValue !== 'string') continue;

        const key = String(rawKey).trim();
        const value = rawValue.trim();
        if (!key || !value) continue;

        // Pterodactyl egg exports use imageRef -> label.
        if (looksLikeDockerImageReference(key) && !looksLikeDockerImageReference(value)) {
            normalized[value] = key;
            continue;
        }

        // Native CPanel format uses label -> imageRef.
        normalized[key] = value;
    }

    if (fallbackDockerImage && !Object.values(normalized).includes(fallbackDockerImage)) {
        normalized['Default'] = fallbackDockerImage;
    }

    return normalized;
}

function extractImportedEnvironment(rawPayload) {
    if (rawPayload.environment && typeof rawPayload.environment === 'object' && !Array.isArray(rawPayload.environment)) {
        const importedMeta = rawPayload.environmentMeta && typeof rawPayload.environmentMeta === 'object' && !Array.isArray(rawPayload.environmentMeta)
            ? rawPayload.environmentMeta
            : (rawPayload.environment_meta && typeof rawPayload.environment_meta === 'object' && !Array.isArray(rawPayload.environment_meta)
                ? rawPayload.environment_meta
                : {});
        return {
            environment: Object.fromEntries(
                Object.entries(rawPayload.environment).map(([key, value]) => [key, value === null || value === undefined ? '' : String(value)])
            ),
            environmentMeta: importedMeta
        };
    }

    if (Array.isArray(rawPayload.variables)) {
        const env = {};
        const meta = {};
        rawPayload.variables.forEach((item) => {
            if (!item || typeof item !== 'object') return;
            const key = item.env_variable;
            if (!key) return;
            env[key] = item.default_value === null || item.default_value === undefined ? '' : String(item.default_value);
            meta[key] = {
                name: typeof item.name === 'string' ? item.name : key,
                description: typeof item.description === 'string' ? item.description : '',
                rules: typeof item.rules === 'string' ? item.rules : '',
                userEditable: item.user_editable === undefined ? true : Boolean(item.user_editable),
                userViewable: item.user_viewable === undefined ? true : Boolean(item.user_viewable),
                fieldType: typeof item.field_type === 'string' ? item.field_type : 'text'
            };
        });
        return {
            environment: env,
            environmentMeta: meta
        };
    }

    return {
        environment: {},
        environmentMeta: {}
    };
}

function normalizeImportedStartup(startup) {
    if (typeof startup !== 'string' || !startup.trim()) {
        throw new Error('Imported JSON is missing startup command.');
    }

    return startup.trim();
}

function normalizeImportedInstallation(rawInstallation) {
    if (!rawInstallation || typeof rawInstallation !== 'object' || Array.isArray(rawInstallation)) {
        return null;
    }

    const script = typeof rawInstallation.script === 'string' ? rawInstallation.script.trim() : '';
    if (!script) {
        return null;
    }

    const container = typeof rawInstallation.container === 'string' ? rawInstallation.container.trim() : '';
    const rawEntrypoint = rawInstallation.entrypoint;
    let entrypoint = null;
    if (Array.isArray(rawEntrypoint)) {
        entrypoint = rawEntrypoint.map((value) => String(value || '').trim()).filter(Boolean);
    } else if (typeof rawEntrypoint === 'string' && rawEntrypoint.trim()) {
        entrypoint = rawEntrypoint.trim().split(/\s+/).filter(Boolean);
    }

    return {
        container: container || null,
        entrypoint: entrypoint && entrypoint.length > 0 ? entrypoint : null,
        script
    };
}

function extractImportedInstallation(rawPayload) {
    const directInstallation = normalizeImportedInstallation(rawPayload.installation);
    if (directInstallation) return directInstallation;

    if (rawPayload.scripts && typeof rawPayload.scripts === 'object') {
        const eggInstallation = normalizeImportedInstallation(rawPayload.scripts.installation);
        if (eggInstallation) return eggInstallation;
    }

    return null;
}

function normalizeImportedConfigFiles(rawConfigFiles) {
    if (rawConfigFiles === null || rawConfigFiles === undefined) {
        return null;
    }

    let payload = rawConfigFiles;
    if (typeof payload === 'string') {
        try {
            payload = JSON.parse(payload);
        } catch (error) {
            throw new Error('Image config.files definition is invalid JSON.');
        }
    }

    if (!payload || typeof payload !== 'object') {
        throw new Error('Image config.files definition is invalid.');
    }

    const normalizeFindEntries = (source) => {
        let findPayload = source;
        if (typeof findPayload === 'string') {
            try {
                findPayload = JSON.parse(findPayload);
            } catch (error) {
                return [];
            }
        }

        if (!findPayload || typeof findPayload !== 'object' || Array.isArray(findPayload)) {
            return [];
        }

        const entries = [];
        Object.entries(findPayload).forEach(([key, value]) => {
            if (typeof key !== 'string' || !key.trim()) return;
            entries.push({
                match: key.trim(),
                replace_with: value
            });
        });
        return entries;
    };

    const normalizeReplaceArray = (source) => {
        let replacePayload = source;
        if (typeof replacePayload === 'string') {
            try {
                replacePayload = JSON.parse(replacePayload);
            } catch (error) {
                return [];
            }
        }

        if (!Array.isArray(replacePayload)) {
            return [];
        }

        const entries = [];
        replacePayload.forEach((item) => {
            if (!item || typeof item !== 'object') return;
            const matchPath = typeof item.match === 'string' ? item.match.trim() : '';
            if (!matchPath) return;
            const hasReplaceWith = Object.prototype.hasOwnProperty.call(item, 'replace_with')
                || Object.prototype.hasOwnProperty.call(item, 'replaceWith');
            if (!hasReplaceWith) return;

            const normalized = {
                match: matchPath,
                replace_with: Object.prototype.hasOwnProperty.call(item, 'replace_with')
                    ? item.replace_with
                    : item.replaceWith
            };

            if (Object.prototype.hasOwnProperty.call(item, 'if_value')) {
                normalized.if_value = item.if_value;
            } else if (Object.prototype.hasOwnProperty.call(item, 'ifValue')) {
                normalized.if_value = item.ifValue;
            }

            entries.push(normalized);
        });

        return entries;
    };

    const normalizeDefinition = (source) => {
        let definition = source;
        if (typeof definition === 'string') {
            try {
                definition = JSON.parse(definition);
            } catch (error) {
                return null;
            }
        }

        if (!definition || typeof definition !== 'object' || Array.isArray(definition)) {
            return null;
        }

        return definition;
    };

    const consumeDefinition = (fileName, rawDefinition, output) => {
        if (typeof fileName !== 'string' || !fileName.trim()) return;
        const definition = normalizeDefinition(rawDefinition);
        if (!definition) return;

        const parser = String(definition.parser || definition.format || 'file').trim().toLowerCase();
        const replaceEntries = [
            ...normalizeFindEntries(definition.find ?? definition.replacements),
            ...normalizeReplaceArray(definition.replace)
        ];
        if (replaceEntries.length === 0) return;

        output[fileName.trim()] = {
            parser,
            replace: replaceEntries
        };
    };

    const normalized = {};

    if (!Array.isArray(payload)
        && typeof payload.file === 'string'
        && (Object.prototype.hasOwnProperty.call(payload, 'find')
            || Object.prototype.hasOwnProperty.call(payload, 'replace')
            || Object.prototype.hasOwnProperty.call(payload, 'replacements'))) {
        consumeDefinition(payload.file, payload, normalized);
        return Object.keys(normalized).length > 0 ? normalized : null;
    }

    if (Array.isArray(payload)) {
        payload.forEach((entry) => {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return;
            const fileName = entry.file || entry.fileName || entry.filename || entry.path;
            consumeDefinition(fileName, entry, normalized);
        });
    } else {
        Object.entries(payload).forEach(([fileName, definition]) => {
            consumeDefinition(fileName, definition, normalized);
        });
    }

    return Object.keys(normalized).length > 0 ? normalized : null;
}

function extractImportedConfigFiles(rawPayload) {
    const directConfigFiles = normalizeImportedConfigFiles(
        rawPayload.configFiles ?? rawPayload.config_files
    );
    if (directConfigFiles) return directConfigFiles;

    let configSection = rawPayload.config;
    if (typeof configSection === 'string') {
        try {
            configSection = JSON.parse(configSection);
        } catch (error) {
            configSection = null;
        }
    }

    if (configSection && typeof configSection === 'object' && !Array.isArray(configSection)) {
        const nestedConfigFiles = normalizeImportedConfigFiles(configSection.files);
        if (nestedConfigFiles) return nestedConfigFiles;
    }

    return null;
}

function shouldUseCommandStartup(image) {
    if (image.installation && typeof image.installation === 'object') {
        return true;
    }

    if (typeof image.dockerImage === 'string' && image.dockerImage.includes('ghcr.io/pterodactyl/')) {
        return true;
    }

    if (image.dockerImages && typeof image.dockerImages === 'object' && !Array.isArray(image.dockerImages)) {
        return Object.values(image.dockerImages).some((value) => typeof value === 'string' && value.includes('ghcr.io/pterodactyl/'));
    }

    return false;
}

function normalizeExternalPanelUrl(value) {
    const raw = String(value || '').trim();
    if (!raw) return null;
    try {
        const parsed = new URL(raw);
        const protocol = String(parsed.protocol || '').toLowerCase();
        if (protocol !== 'http:' && protocol !== 'https:') return null;
        const cleanPath = String(parsed.pathname || '/').replace(/\/+$/, '');
        const basePath = cleanPath && cleanPath !== '/' ? cleanPath : '';
        return `${protocol}//${parsed.host}${basePath}`;
    } catch {
        return null;
    }
}

function inferSftpHostFromPanelUrl(panelUrl) {
    const normalized = normalizeExternalPanelUrl(panelUrl);
    if (!normalized) return '';
    try {
        const parsed = new URL(normalized);
        return String(parsed.hostname || '').trim();
    } catch {
        return '';
    }
}

async function fetchPterodactylApplicationServer(panelUrl, apiKey, reference) {
    const baseUrl = normalizeExternalPanelUrl(panelUrl);
    if (!baseUrl) {
        throw new Error('Pterodactyl panel URL must be a valid HTTP/HTTPS URL.');
    }

    const token = String(apiKey || '').trim();
    if (!token) {
        throw new Error('Pterodactyl Application API key is required.');
    }

    const ref = String(reference || '').trim();
    if (!ref) {
        throw new Error('Server reference is required (ID, external ID, UUID, or identifier).');
    }

    const headers = {
        Authorization: `Bearer ${token}`,
        Accept: 'Application/vnd.pterodactyl.v1+json',
        'Content-Type': 'application/json'
    };

    const includeParam = 'allocations,databases';
    const withInclude = (url) => {
        if (!url) return url;
        return url.includes('?')
            ? `${url}&include=${encodeURIComponent(includeParam)}`
            : `${url}?include=${encodeURIComponent(includeParam)}`;
    };

    const candidates = [];
    if (/^\d+$/.test(ref)) {
        candidates.push(withInclude(`${baseUrl}/api/application/servers/${ref}`));
    }
    candidates.push(withInclude(`${baseUrl}/api/application/servers/external/${encodeURIComponent(ref)}`));
    candidates.push(withInclude(`${baseUrl}/api/application/servers/${encodeURIComponent(ref)}`));

    let lastError = null;
    const extractPteroErrorMessage = (error) => {
        if (!error || !error.response || !error.response.data) return '';
        const payload = error.response.data;
        if (payload.errors && Array.isArray(payload.errors) && payload.errors.length > 0) {
            const first = payload.errors[0];
            if (first && typeof first.detail === 'string' && first.detail.trim()) return first.detail.trim();
        }
        if (typeof payload.error === 'string' && payload.error.trim()) return payload.error.trim();
        if (typeof payload.message === 'string' && payload.message.trim()) return payload.message.trim();
        return '';
    };

    const normalizeApplicationServerPayload = (input) => {
        if (!input) return null;
        if (input.attributes && typeof input.attributes === 'object') {
            const merged = { ...input.attributes };
            if (input.relationships && typeof input.relationships === 'object') {
                merged.relationships = input.relationships;
            }
            return merged;
        }
        if (input.object === 'server' && typeof input === 'object') return input;
        return input;
    };

    const attachRelationshipList = async (payload, relation, endpoint, extraParams = {}) => {
        if (!payload || !relation || !endpoint) return;
        if (payload.relationships && payload.relationships[relation] && Array.isArray(payload.relationships[relation].data)) {
            return;
        }
        try {
            const response = await axios.get(endpoint, {
                headers,
                timeout: 10000,
                params: extraParams
            });
            const dataRows = response && response.data && Array.isArray(response.data.data)
                ? response.data.data
                : [];
            if (!payload.relationships || typeof payload.relationships !== 'object') {
                payload.relationships = {};
            }
            payload.relationships[relation] = { data: dataRows };
        } catch {
            // Best effort only.
        }
    };

    const enrichRelationships = async (payload) => {
        const serverId = Number.parseInt(payload && payload.id, 10);
        if (!Number.isInteger(serverId) || serverId <= 0) return payload;
        await attachRelationshipList(
            payload,
            'allocations',
            `${baseUrl}/api/application/servers/${serverId}/allocations`
        );
        await attachRelationshipList(
            payload,
            'databases',
            `${baseUrl}/api/application/servers/${serverId}/databases`,
            { include: 'host' }
        );
        return payload;
    };

    for (const endpoint of candidates) {
        try {
            const response = await axios.get(endpoint, {
                headers,
                timeout: 10000
            });
            if (response && response.data) {
                const payload = normalizeApplicationServerPayload(response.data);
                if (payload && typeof payload === 'object') {
                    await enrichRelationships(payload);
                    return payload;
                }
            }
        } catch (error) {
            lastError = error;
            if (error.response && error.response.status !== 404) {
                break;
            }
        }
    }

    // Fallback: scan application server list and match by id/external_id/uuid/identifier.
    // This helps when users provide UUID/identifier and direct endpoint variants fail.
    if (!lastError || !lastError.response || lastError.response.status === 404) {
        try {
            let page = 1;
            const maxPages = 20;
            while (page <= maxPages) {
                const listResponse = await axios.get(`${baseUrl}/api/application/servers`, {
                    headers,
                    timeout: 10000,
                    params: {
                        page,
                        per_page: 100
                    }
                });
                const dataRows = listResponse && listResponse.data && Array.isArray(listResponse.data.data)
                    ? listResponse.data.data
                    : [];
                for (const row of dataRows) {
                    const serverPayload = normalizeApplicationServerPayload(row);
                    if (!serverPayload || typeof serverPayload !== 'object') continue;
                    const id = String(serverPayload.id || '').trim();
                    const externalId = String(serverPayload.external_id || '').trim();
                    const uuid = String(serverPayload.uuid || '').trim();
                    const identifier = String(serverPayload.identifier || '').trim();
                    if (
                        (id && id === ref) ||
                        (externalId && externalId === ref) ||
                        (uuid && uuid === ref) ||
                        (identifier && identifier === ref)
                    ) {
                        await enrichRelationships(serverPayload);
                        return serverPayload;
                    }
                }

                const totalPages = Number.parseInt(
                    (((listResponse || {}).data || {}).meta || {}).pagination
                        ? ((listResponse.data.meta.pagination.total_pages) || 1)
                        : 1,
                    10
                ) || 1;
                if (page >= totalPages) break;
                page += 1;
            }
        } catch (scanError) {
            lastError = scanError;
        }
    }

    if (lastError && lastError.response && lastError.response.status === 401) {
        const detail = extractPteroErrorMessage(lastError);
        throw new Error(detail
            ? `Pterodactyl API rejected the key (401 Unauthorized): ${detail}`
            : 'Pterodactyl API rejected the key (401 Unauthorized).');
    }
    if (lastError && lastError.response && lastError.response.status === 403) {
        const detail = extractPteroErrorMessage(lastError);
        throw new Error(detail
            ? `Pterodactyl API key does not have application-level permissions: ${detail}`
            : 'Pterodactyl API key does not have application-level permissions.');
    }
    if (lastError && lastError.response && lastError.response.status === 404) {
        throw new Error('Server not found on the provided Pterodactyl panel.');
    }
    if (lastError) {
        throw new Error(`Failed to fetch Pterodactyl server: ${lastError.message}`);
    }
    throw new Error('Failed to fetch Pterodactyl server.');
}

function normalizePterodactylServerForMigration(rawServer) {
    if (!rawServer || typeof rawServer !== 'object') {
        throw new Error('Invalid Pterodactyl server payload.');
    }

    const limits = rawServer.limits && typeof rawServer.limits === 'object' ? rawServer.limits : {};
    const container = rawServer.container && typeof rawServer.container === 'object' ? rawServer.container : {};
    const allocation = rawServer.allocation && typeof rawServer.allocation === 'object' ? rawServer.allocation : {};
    const featureLimits = rawServer.feature_limits && typeof rawServer.feature_limits === 'object' ? rawServer.feature_limits : {};
    const relationships = rawServer.relationships && typeof rawServer.relationships === 'object'
        ? rawServer.relationships
        : {};

    const memory = Number.parseInt(limits.memory, 10);
    const disk = Number.parseInt(limits.disk, 10);
    const cpu = Number.parseInt(limits.cpu, 10);

    const extractRelationshipData = (relation) => {
        if (!relation || typeof relation !== 'object') return [];
        const rows = Array.isArray(relation.data) ? relation.data : [];
        return rows.filter(Boolean);
    };

    const normalizeAllocationRow = (row) => {
        const payload = row && row.attributes && typeof row.attributes === 'object' ? row.attributes : row;
        if (!payload || typeof payload !== 'object') return null;
        const ip = String(payload.ip || '').trim();
        const port = Number.parseInt(payload.port, 10);
        if (!ip || !Number.isInteger(port)) return null;
        return {
            id: Number.parseInt(payload.id, 10) || null,
            ip,
            port,
            alias: String(payload.alias || '').trim(),
            notes: String(payload.notes || '').trim(),
            isDefault: Boolean(payload.is_default || payload.default || payload.isDefault)
        };
    };

    const normalizeDatabaseRow = (row) => {
        const payload = row && row.attributes && typeof row.attributes === 'object' ? row.attributes : row;
        if (!payload || typeof payload !== 'object') return null;
        const name = String(payload.database || payload.name || '').trim();
        const username = String(payload.username || '').trim();
        if (!name) return null;

        let host = null;
        const hostRel = row && row.relationships && row.relationships.host
            ? row.relationships.host
            : (payload.host && typeof payload.host === 'object' ? payload.host : null);
        if (hostRel && typeof hostRel === 'object') {
            const hostPayload = hostRel.attributes || hostRel.data && hostRel.data.attributes || hostRel.data;
            if (hostPayload && typeof hostPayload === 'object') {
                host = {
                    id: Number.parseInt(hostPayload.id, 10) || null,
                    name: String(hostPayload.name || '').trim(),
                    type: String(hostPayload.type || '').trim(),
                    host: String(hostPayload.host || '').trim(),
                    port: Number.parseInt(hostPayload.port, 10) || null
                };
            }
        }

        return {
            id: Number.parseInt(payload.id, 10) || null,
            name,
            username,
            remote: Boolean(payload.remote),
            host
        };
    };

    const allocationsRaw = extractRelationshipData(relationships.allocations);
    const allocationRows = allocationsRaw.map(normalizeAllocationRow).filter(Boolean);
    const defaultAllocationId = Number.parseInt(allocation.id, 10) || null;
    const allocations = [];
    const defaultIp = String(allocation.ip || '').trim();
    const defaultPort = Number.parseInt(allocation.port, 10);

    if (defaultIp && Number.isInteger(defaultPort)) {
        allocations.push({
            id: defaultAllocationId,
            ip: defaultIp,
            port: defaultPort,
            alias: String(allocation.alias || '').trim(),
            notes: String(allocation.notes || '').trim(),
            isDefault: true
        });
    }

    allocationRows.forEach((row) => {
        const isDefault = row.isDefault
            || (defaultAllocationId && row.id === defaultAllocationId)
            || (defaultIp && defaultPort && row.ip === defaultIp && row.port === defaultPort);
        const exists = allocations.find((entry) => entry.ip === row.ip && entry.port === row.port);
        if (exists) {
            if (isDefault) exists.isDefault = true;
            if (!exists.alias && row.alias) exists.alias = row.alias;
            if (!exists.notes && row.notes) exists.notes = row.notes;
        } else {
            allocations.push({ ...row, isDefault });
        }
    });

    const databasesRaw = extractRelationshipData(relationships.databases);
    const databases = databasesRaw.map(normalizeDatabaseRow).filter(Boolean);

    return {
        id: Number.parseInt(rawServer.id, 10) || null,
        uuid: String(rawServer.uuid || '').trim(),
        identifier: String(rawServer.identifier || '').trim(),
        externalId: String(rawServer.external_id || '').trim(),
        name: String(rawServer.name || '').trim() || 'Imported Server',
        description: String(rawServer.description || '').trim(),
        suspended: Boolean(rawServer.suspended),
        status: String(rawServer.status || '').trim(),
        memory: Number.isInteger(memory) && memory > 0 ? memory : 1024,
        disk: Number.isInteger(disk) && disk > 0 ? disk : 10240,
        cpu: Number.isInteger(cpu) && cpu > 0 ? cpu : 100,
        swap: Number.parseInt(limits.swap, 10) || 0,
        io: Number.parseInt(limits.io, 10) || 500,
        startup: String(container.startup_command || '').trim(),
        dockerImage: String(container.image || '').trim(),
        environment: normalizeClientVariables(container.environment || {}),
        defaultAllocation: {
            ip: String(allocation.ip || '').trim(),
            port: Number.parseInt(allocation.port, 10) || null
        },
        allocations,
        databases,
        featureLimits: {
            databases: Number.parseInt(featureLimits.databases, 10) || 0,
            allocations: Number.parseInt(featureLimits.allocations, 10) || 0,
            backups: Number.parseInt(featureLimits.backups, 10) || 0
        },
        egg: {
            id: Number.parseInt(rawServer.egg, 10) || null,
            nestId: Number.parseInt(rawServer.nest, 10) || null
        }
    };
}

function encodeMigrationSnapshot(snapshot) {
    const serialized = JSON.stringify(snapshot || {});
    return Buffer.from(serialized, 'utf8').toString('base64');
}

function decodeMigrationSnapshot(rawToken) {
    const token = String(rawToken || '').trim();
    if (!token) throw new Error('Missing migration snapshot.');
    const raw = Buffer.from(token, 'base64').toString('utf8');
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') {
        throw new Error('Invalid migration snapshot payload.');
    }
    return parsed;
}

function parseImportedImageJson(rawPayload) {
    let payload = rawPayload;

    // Accept wrapper payloads such as API responses containing an "attributes" object.
    if (payload && typeof payload === 'object' && !Array.isArray(payload) && payload.attributes && typeof payload.attributes === 'object') {
        payload = payload.attributes;
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('Imported file must be a JSON object.');
    }

    const name = String(payload.name || '').trim();
    if (!name) {
        throw new Error('Imported JSON is missing "name".');
    }

    const description = String(payload.description || '').trim() || `${name} (imported)`;
    const directDockerImage = typeof payload.docker_image === 'string'
        ? payload.docker_image.trim()
        : (typeof payload.dockerImage === 'string' ? payload.dockerImage.trim() : '');
    const dockerImages = normalizeImportedDockerImages(payload.docker_images || payload.dockerImages, directDockerImage);
    const dockerImage = directDockerImage || Object.values(dockerImages)[0] || '';
    if (!dockerImage) {
        throw new Error('Imported JSON must include docker_image or docker_images.');
    }

    const startup = normalizeImportedStartup(payload.startup);
    const { environment, environmentMeta } = extractImportedEnvironment(payload);
    const installation = extractImportedInstallation(payload);
    const configFiles = extractImportedConfigFiles(payload);

    let ports = null;
    if (payload.ports !== null && payload.ports !== undefined) {
        ports = resolveImagePorts(payload.ports);
    } else {
        // Fallback or heuristic if ports missing
        ports = [{ container: 25565, protocol: 'tcp' }];
    }

    const rawIsPublic = payload.isPublic;
    const rawPrivate = payload.private;
    const isPublic = rawPrivate !== undefined
        ? !['1', 'true', 'yes', 'on'].includes(String(rawPrivate).trim().toLowerCase())
        : ['1', 'true', 'yes', 'on'].includes(String(rawIsPublic).trim().toLowerCase()) || rawIsPublic === undefined;

    return {
        name,
        description,
        isPublic,
        dockerImage,
        dockerImages,
        startup,
        environment,
        environmentMeta,
        configFiles,
        ports,
        installation,
        eggConfig: payload.config || payload.eggConfig || null,
        eggScripts: payload.scripts || payload.eggScripts || null,
        eggVariables: Array.isArray(payload.variables) ? payload.variables : (Array.isArray(payload.eggVariables) ? payload.eggVariables : []),
        configPath: `imported:${new Date().toISOString()}`
    };
}


async function getConnectorAllocatedUsage(connectorId) {
    const servers = await Server.findAll({
        attributes: ['memory', 'disk'],
        include: [{
            model: Allocation,
            as: 'allocation',
            attributes: [],
            where: { connectorId }
        }],
        raw: true
    });

    const memoryMb = servers.reduce((sum, srv) => sum + (Number.parseInt(srv.memory, 10) || 0), 0);
    const diskMb = servers.reduce((sum, srv) => sum + (Number.parseInt(srv.disk, 10) || 0), 0);

    return {
        memoryMb,
        diskMb,
        memoryGb: Number((memoryMb / 1024).toFixed(1)),
        diskGb: Number((diskMb / 1024).toFixed(1))
    };
}

    return {
        normalizeClientVariables,
        resolveImagePorts,
        buildDeploymentPorts,
        resolveImageDockerChoices,
        resolveImageVariableDefinitions,
        buildServerEnvironment,
        parseRuleTokens,
        validateEnvironmentValue,
        buildStartupCommand,
        STARTUP_PRESET_DEFINITIONS,
        getServerStartupPresetSettingKey,
        getServerStartupPresetSelection,
        setServerStartupPresetSelection,
        getStartupPresetsForImage,
        applyStartupPresetVariables,
        looksLikeDockerImageReference,
        normalizeImportedDockerImages,
        extractImportedEnvironment,
        normalizeImportedStartup,
        normalizeImportedInstallation,
        extractImportedInstallation,
        normalizeImportedConfigFiles,
        extractImportedConfigFiles,
        shouldUseCommandStartup,
        normalizeExternalPanelUrl,
        inferSftpHostFromPanelUrl,
        fetchPterodactylApplicationServer,
        normalizePterodactylServerForMigration,
        encodeMigrationSnapshot,
        decodeMigrationSnapshot,
        parseImportedImageJson,
        getConnectorAllocatedUsage
    };
}

module.exports = { createLegacyStartupHelpers };
