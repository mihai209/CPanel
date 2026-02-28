require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');
const fs = require('fs');
const path = require('path');

// Database Setup
let sequelize;
const dbConnection = process.env.DB_CONNECTION || 'sqlite';

if (dbConnection === 'sqlite') {
    sequelize = new Sequelize({
        dialect: 'sqlite',
        storage: path.join(__dirname, '../database.sqlite'),
        logging: false
    });
} else {
    sequelize = new Sequelize(
        process.env.DB_DATABASE,
        process.env.DB_USERNAME,
        process.env.DB_PASSWORD,
        {
            host: process.env.DB_HOST,
            dialect: dbConnection === 'postgres' ? 'postgres' : 'mysql',
            port: process.env.DB_PORT,
            logging: false
        }
    );
}

const Image = sequelize.define('Image', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT },
    dockerImage: { type: DataTypes.STRING, allowNull: false },
    dockerImages: { type: DataTypes.JSON, defaultValue: {} },
    startup: { type: DataTypes.TEXT, allowNull: false },
    environment: { type: DataTypes.JSON, defaultValue: {} },
    environmentMeta: { type: DataTypes.JSON, allowNull: true },
    configFiles: { type: DataTypes.JSON, allowNull: true },
    ports: { type: DataTypes.JSON, allowNull: true },
    installation: { type: DataTypes.JSON, allowNull: true },
    configPath: { type: DataTypes.STRING }
});

function normalizeInstallation(rawInstallation) {
    if (!rawInstallation || typeof rawInstallation !== 'object' || Array.isArray(rawInstallation)) {
        return null;
    }

    const script = typeof rawInstallation.script === 'string' ? rawInstallation.script.trim() : '';
    if (!script) return null;

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

function normalizeConfigFiles(rawImageData) {
    let configSection = rawImageData.config;
    if (typeof configSection === 'string') {
        try {
            configSection = JSON.parse(configSection);
        } catch (error) {
            configSection = null;
        }
    }

    const rawConfigFiles = rawImageData.configFiles
        ?? rawImageData.config_files
        ?? (configSection && typeof configSection === 'object' ? configSection.files : null);

    if (rawConfigFiles === null || rawConfigFiles === undefined) {
        return null;
    }

    let payload = rawConfigFiles;
    if (typeof payload === 'string') {
        try {
            payload = JSON.parse(payload);
        } catch (error) {
            return null;
        }
    }

    if (!payload || typeof payload !== 'object') {
        return null;
    }

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
            if (!key || typeof key !== 'string' || !key.trim()) return;
            entries.push({
                match: key.trim(),
                replace_with: value
            });
        });
        return entries;
    };

    const normalizeReplaceEntries = (source) => {
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

    const normalized = {};
    const consumeDefinition = (fileName, rawDefinition) => {
        if (!fileName || typeof fileName !== 'string' || !fileName.trim()) return;

        const config = normalizeDefinition(rawDefinition);
        if (!config) return;

        const replaceEntries = [
            ...normalizeFindEntries(config.find ?? config.replacements),
            ...normalizeReplaceEntries(config.replace)
        ];
        if (replaceEntries.length === 0) return;

        normalized[fileName.trim()] = {
            parser: String(config.parser || config.format || 'file').trim().toLowerCase(),
            replace: replaceEntries
        };
    };

    if (!Array.isArray(payload)
        && typeof payload.file === 'string'
        && (Object.prototype.hasOwnProperty.call(payload, 'find')
            || Object.prototype.hasOwnProperty.call(payload, 'replace')
            || Object.prototype.hasOwnProperty.call(payload, 'replacements'))) {
        consumeDefinition(payload.file, payload);
    } else if (Array.isArray(payload)) {
        payload.forEach((entry) => {
            if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return;
            consumeDefinition(entry.file || entry.fileName || entry.filename || entry.path, entry);
        });
    } else {
        Object.entries(payload).forEach(([fileName, definition]) => {
            consumeDefinition(fileName, definition);
        });
    }

    return Object.keys(normalized).length > 0 ? normalized : null;
}

function normalizeEnvironment(rawImageData) {
    if (rawImageData.environment && typeof rawImageData.environment === 'object' && !Array.isArray(rawImageData.environment)) {
        const importedMeta = rawImageData.environmentMeta && typeof rawImageData.environmentMeta === 'object' && !Array.isArray(rawImageData.environmentMeta)
            ? rawImageData.environmentMeta
            : (rawImageData.environment_meta && typeof rawImageData.environment_meta === 'object' && !Array.isArray(rawImageData.environment_meta)
                ? rawImageData.environment_meta
                : {});
        return {
            environment: rawImageData.environment,
            environmentMeta: importedMeta
        };
    }

    if (Array.isArray(rawImageData.variables)) {
        const environment = {};
        const environmentMeta = {};

        rawImageData.variables.forEach((item) => {
            if (!item || typeof item !== 'object' || !item.env_variable) return;
            const key = String(item.env_variable);
            environment[key] = item.default_value === null || item.default_value === undefined ? '' : String(item.default_value);
            environmentMeta[key] = {
                name: typeof item.name === 'string' ? item.name : key,
                description: typeof item.description === 'string' ? item.description : '',
                rules: typeof item.rules === 'string' ? item.rules : '',
                userEditable: item.user_editable === undefined ? true : Boolean(item.user_editable),
                userViewable: item.user_viewable === undefined ? true : Boolean(item.user_viewable),
                fieldType: typeof item.field_type === 'string' ? item.field_type : 'text'
            };
        });

        return { environment, environmentMeta };
    }

    return { environment: {}, environmentMeta: {} };
}

async function syncImages() {
    try {
        console.log('Starting image sync...');
        const imagesDir = path.join(__dirname, '../../images');

        if (!fs.existsSync(imagesDir)) {
            console.log('Images directory does not exist.');
            process.exit(0);
        }

        const files = fs.readdirSync(imagesDir).filter(f => f.endsWith('.json'));

        for (const file of files) {
            const filePath = path.join(imagesDir, file);
            const imageData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            const imagePorts = Array.isArray(imageData.ports) ? imageData.ports : null;
            const imageInstallation = normalizeInstallation(imageData.installation || (imageData.scripts && imageData.scripts.installation));
            const { environment, environmentMeta } = normalizeEnvironment(imageData);
            const configFiles = normalizeConfigFiles(imageData);

            const [image, created] = await Image.findOrCreate({
                where: { name: imageData.name },
                defaults: {
                    description: imageData.description,
                    dockerImage: imageData.docker_image || imageData.dockerImage,
                    dockerImages: imageData.docker_images || imageData.dockerImages || {},
                    startup: imageData.startup,
                    environment,
                    environmentMeta,
                    configFiles,
                    ports: imagePorts,
                    installation: imageInstallation,
                    configPath: file
                }
            });

            if (created) {
                console.log(`Created image: ${imageData.name}`);
            } else {
                image.description = imageData.description;
                image.dockerImage = imageData.docker_image || imageData.dockerImage;
                image.dockerImages = imageData.docker_images || imageData.dockerImages || {};
                image.startup = imageData.startup;
                image.environment = environment;
                image.environmentMeta = environmentMeta;
                image.configFiles = configFiles;
                image.ports = imagePorts;
                image.installation = imageInstallation;
                image.configPath = file;
                await image.save();
                console.log(`Updated image: ${imageData.name}`);
            }
        }

        console.log('Image sync completed successfully.');
        process.exit(0);
    } catch (error) {
        console.error('Image sync failed:', error);
        process.exit(1);
    }
}

syncImages();
