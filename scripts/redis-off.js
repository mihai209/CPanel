const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const { Sequelize, DataTypes } = require('sequelize');

const dbConnection = process.env.DB_CONNECTION || 'sqlite';
let sequelize;

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

const Settings = sequelize.define('Settings', {
    key: { type: DataTypes.STRING, primaryKey: true },
    value: { type: DataTypes.TEXT, allowNull: true }
});

async function disableRedisInSettings() {
    const updates = {
        redisEnabled: 'false',
        redisRequired: 'false'
    };

    const keys = Object.keys(updates);
    for (const key of keys) {
        await Settings.upsert({ key, value: updates[key] });
    }

    console.log('Redis disabled in database settings (redisEnabled=false, redisRequired=false).');
}

async function main() {
    try {
        await sequelize.authenticate();
        await sequelize.sync();
        await disableRedisInSettings();
    } catch (error) {
        console.error('Failed to disable Redis in database settings:', error && error.message ? error.message : error);
        process.exitCode = 1;
    } finally {
        try {
            await sequelize.close();
        } catch (_) {}
    }
}

main();