require('dotenv').config();
const { Sequelize, DataTypes } = require('sequelize');

let sequelize;
const dbConnection = process.env.DB_CONNECTION || 'sqlite';

const path = require('path');
if (dbConnection === 'sqlite') {
    sequelize = new Sequelize({
        dialect: 'sqlite',
        storage: './database.sqlite',
        logging: console.log
    });
} else {
    sequelize = new Sequelize(
        process.env.DB_DATABASE,
        process.env.DB_USERNAME,
        process.env.DB_PASSWORD,
        {
            host: process.env.DB_HOST,
            dialect: 'mysql',
            port: process.env.DB_PORT,
            logging: console.log
        }
    );
}

async function fixSchema() {
    const queryInterface = sequelize.getQueryInterface();

    try {
        console.log('Checking for missing columns...');

        // 1. Add dockerImages to Images table
        try {
            await queryInterface.addColumn('Images', 'dockerImages', {
                type: DataTypes.JSON,
                defaultValue: {}
            });
            console.log('Added dockerImages to Images table.');
        } catch (e) {
            console.log('dockerImages already exists in Images or error:', e.message);
        }

        // 2. Add dockerImage to Servers table
        try {
            await queryInterface.addColumn('Servers', 'dockerImage', {
                type: DataTypes.STRING,
                allowNull: true
            });
            console.log('Added dockerImage to Servers table.');
        } catch (e) {
            console.log('dockerImage already exists in Servers or error:', e.message);
        }

        // 3. Add ports to Images table
        try {
            await queryInterface.addColumn('Images', 'ports', {
                type: DataTypes.JSON,
                allowNull: true
            });
            console.log('Added ports to Images table.');
        } catch (e) {
            console.log('ports already exists in Images or error:', e.message);
        }

        // 4. Add installation to Images table
        try {
            await queryInterface.addColumn('Images', 'installation', {
                type: DataTypes.JSON,
                allowNull: true
            });
            console.log('Added installation to Images table.');
        } catch (e) {
            console.log('installation already exists in Images or error:', e.message);
        }

        // 5. Add environmentMeta to Images table
        try {
            await queryInterface.addColumn('Images', 'environmentMeta', {
                type: DataTypes.JSON,
                allowNull: true
            });
            console.log('Added environmentMeta to Images table.');
        } catch (e) {
            console.log('environmentMeta already exists in Images or error:', e.message);
        }

        // 6. Add configFiles to Images table
        try {
            await queryInterface.addColumn('Images', 'configFiles', {
                type: DataTypes.JSON,
                allowNull: true
            });
            console.log('Added configFiles to Images table.');
        } catch (e) {
            console.log('configFiles already exists in Images or error:', e.message);
        }

        console.log('Finished schema fix.');
        process.exit(0);
    } catch (err) {
        console.error('Schema fix failed:', err);
        process.exit(1);
    }
}

fixSchema();
