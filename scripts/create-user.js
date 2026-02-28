const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const inquirer = require('inquirer');
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');

// Database Setup (Must match server.js logic)
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

// User Model (Must match server.js)
const User = sequelize.define('User', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    username: { type: DataTypes.STRING, unique: true, allowNull: false },
    email: { type: DataTypes.STRING, unique: true, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false },
    firstName: { type: DataTypes.STRING, allowNull: false },
    lastName: { type: DataTypes.STRING, allowNull: false },
    isAdmin: { type: DataTypes.BOOLEAN, defaultValue: false },
    coins: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    lastAfkClaimAt: { type: DataTypes.DATE, allowNull: true },
    isSuspended: { type: DataTypes.BOOLEAN, defaultValue: false }, // User suspension field
    avatarUrl: { type: DataTypes.STRING, allowNull: true } // Custom Avatar URL
});

async function main() {
    try {
        await sequelize.authenticate();
        await sequelize.sync(); // Ensure table exists

        const answers = await inquirer.prompt([
            { type: 'input', name: 'username', message: 'Username:' },
            { type: 'input', name: 'email', message: 'Email:' },
            { type: 'input', name: 'firstName', message: 'First Name:' },
            { type: 'input', name: 'lastName', message: 'Last Name:' },
            { type: 'password', name: 'password', message: 'Password:' },
            { type: 'confirm', name: 'isAdmin', message: 'Is Admin?', default: false }
        ]);

        const hashedPassword = await bcrypt.hash(answers.password, 10);

        await User.create({
            username: answers.username,
            email: answers.email,
            firstName: answers.firstName,
            lastName: answers.lastName,
            password: hashedPassword,
            isAdmin: answers.isAdmin
        });

        console.log(`\nUser ${answers.username} created successfully!`);
    } catch (error) {
        console.error('Error creating user:', error.message);
    } finally {
        await sequelize.close();
    }
}

main();
