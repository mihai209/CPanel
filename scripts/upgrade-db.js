require('dotenv').config();
const { Sequelize, DataTypes, QueryTypes } = require('sequelize');
// Database Setup (copied from server.js for consistency)
let sequelize;
const dbConnection = process.env.DB_CONNECTION || 'sqlite';

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
            dialect: dbConnection === 'postgres' ? 'postgres' : 'mysql',
            port: process.env.DB_PORT,
            logging: console.log
        }
    );
}

const User = sequelize.define('User', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    username: { type: DataTypes.STRING, unique: true, allowNull: false },
    email: { type: DataTypes.STRING, unique: true, allowNull: false, validate: { isEmail: true } },
    password: { type: DataTypes.STRING, allowNull: false },
    firstName: { type: DataTypes.STRING, allowNull: false },
    lastName: { type: DataTypes.STRING, allowNull: false },
    isAdmin: { type: DataTypes.BOOLEAN, defaultValue: false },
    coins: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    lastAfkClaimAt: { type: DataTypes.DATE, allowNull: true },
    permissions: { type: DataTypes.JSON, allowNull: false, defaultValue: {} },
    isSuspended: { type: DataTypes.BOOLEAN, defaultValue: false },
    avatarUrl: { type: DataTypes.STRING, allowNull: true },
    avatarProvider: { type: DataTypes.STRING, defaultValue: 'gravatar' },
    twoFactorSecret: { type: DataTypes.STRING, allowNull: true },
    twoFactorEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
    oauthProvider: { type: DataTypes.STRING, allowNull: true, defaultValue: null },
    oauthId: { type: DataTypes.STRING, allowNull: true, defaultValue: null }
});

const LinkedAccount = sequelize.define('LinkedAccount', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    userId: { type: DataTypes.INTEGER, allowNull: false },
    provider: { type: DataTypes.STRING, allowNull: false },
    providerId: { type: DataTypes.STRING, allowNull: false },
    providerEmail: { type: DataTypes.STRING, allowNull: true },
    providerUsername: { type: DataTypes.STRING, allowNull: true }
});

const UserLoginEvent = sequelize.define('UserLoginEvent', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    userId: { type: DataTypes.INTEGER, allowNull: false },
    usernameSnapshot: { type: DataTypes.STRING(100), allowNull: false },
    loginType: { type: DataTypes.STRING(16), allowNull: false, defaultValue: 'email' },
    ipAddress: { type: DataTypes.STRING(120), allowNull: false, defaultValue: 'unknown' },
    location: { type: DataTypes.STRING(160), allowNull: true },
    operatingSystem: { type: DataTypes.STRING(120), allowNull: true },
    userAgent: { type: DataTypes.TEXT, allowNull: true }
}, {
    indexes: [
        { fields: ['userId'] },
        { fields: ['createdAt'] },
        { fields: ['userId', 'createdAt'] }
    ]
});

// Associations are declared after all models are defined.

const Settings = sequelize.define('Settings', {
    key: { type: DataTypes.STRING, primaryKey: true },
    value: { type: DataTypes.TEXT, allowNull: true }
});

const Location = sequelize.define('Location', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    shortName: { type: DataTypes.STRING, allowNull: false, unique: true },
    description: { type: DataTypes.STRING(255), allowNull: true },
    imageUrl: { type: DataTypes.TEXT, allowNull: true }
});

const DatabaseHost = sequelize.define('DatabaseHost', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING, allowNull: false },
    host: { type: DataTypes.STRING, allowNull: false },
    port: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 3306 },
    username: { type: DataTypes.STRING, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false },
    database: { type: DataTypes.STRING, allowNull: false, defaultValue: 'mysql' },
    locationId: { type: DataTypes.INTEGER, allowNull: false },
    type: { type: DataTypes.STRING, allowNull: false, defaultValue: 'mysql' }
});

const ServerDatabase = sequelize.define('ServerDatabase', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false },
    databaseHostId: { type: DataTypes.INTEGER, allowNull: false },
    name: { type: DataTypes.STRING, allowNull: false },
    username: { type: DataTypes.STRING, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false },
    remoteDatabaseId: { type: DataTypes.STRING, allowNull: true }
}, {
    indexes: [
        { fields: ['serverId'] },
        { fields: ['databaseHostId'] },
        { fields: ['serverId', 'name'], unique: true },
        { fields: ['databaseHostId', 'name'], unique: true }
    ]
});

const Connector = sequelize.define('Connector', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING, allowNull: false },
    fqdn: { type: DataTypes.STRING, allowNull: false },
    port: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 2009 },
    sftpPort: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 8312 },
    ssl: { type: DataTypes.BOOLEAN, defaultValue: false },
    locationId: { type: DataTypes.INTEGER, allowNull: false },
    fileDirectory: { type: DataTypes.STRING, allowNull: false, defaultValue: '/var/lib/cpanel/volumes' },
    totalMemory: { type: DataTypes.INTEGER, allowNull: false },
    memoryOverAllocation: { type: DataTypes.INTEGER, defaultValue: 0 },
    totalDisk: { type: DataTypes.INTEGER, allowNull: false },
    diskOverAllocation: { type: DataTypes.INTEGER, defaultValue: 0 },
    isPublic: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
    description: { type: DataTypes.STRING(50), allowNull: true },
    token: { type: DataTypes.STRING(255), allowNull: true }
});

const Allocation = sequelize.define('Allocation', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    ip: { type: DataTypes.STRING, allowNull: false },
    port: { type: DataTypes.INTEGER, allowNull: false },
    alias: { type: DataTypes.STRING, allowNull: true },
    notes: { type: DataTypes.STRING(20), allowNull: true },
    connectorId: { type: DataTypes.INTEGER, allowNull: false },
    serverId: { type: DataTypes.INTEGER, allowNull: true }
});

const Package = sequelize.define('Package', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.STRING(150), allowNull: true },
    imageUrl: { type: DataTypes.TEXT, allowNull: true }
});

const Image = sequelize.define('Image', {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    name: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT },
    isPublic: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
    dockerImage: { type: DataTypes.STRING, allowNull: false },
    dockerImages: { type: DataTypes.JSON, defaultValue: {} },
    startup: { type: DataTypes.TEXT, allowNull: false },
    environment: { type: DataTypes.JSON, defaultValue: {} },
    environmentMeta: { type: DataTypes.JSON, allowNull: true },
    configFiles: { type: DataTypes.JSON, allowNull: true },
    ports: { type: DataTypes.JSON, allowNull: true },
    installation: { type: DataTypes.JSON, allowNull: true },
    eggConfig: { type: DataTypes.JSON, allowNull: true },
    eggScripts: { type: DataTypes.JSON, allowNull: true },
    eggVariables: { type: DataTypes.JSON, defaultValue: [] },
    configPath: { type: DataTypes.STRING },
    packageId: { type: DataTypes.INTEGER, allowNull: true } // Can be null for legacy, but mandatory for new imports
});

const Server = sequelize.define('Server', {
    name: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.STRING(50), allowNull: true },
    folder: { type: DataTypes.STRING(64), allowNull: true },
    tags: { type: DataTypes.JSON, allowNull: false, defaultValue: [] },
    containerId: { type: DataTypes.STRING, unique: true },
    status: { type: DataTypes.STRING, defaultValue: 'installing' },
    isSuspended: { type: DataTypes.BOOLEAN, defaultValue: false },
    suspendReason: { type: DataTypes.TEXT, allowNull: true },
    ownerId: { type: DataTypes.INTEGER, allowNull: false },
    imageId: { type: DataTypes.UUID, allowNull: false },
    allocationId: { type: DataTypes.INTEGER, allowNull: true },
    memory: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1024 },
    disk: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 10240 },
    databaseLimit: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    cpu: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 100 },
    swapLimit: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    ioWeight: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 500 },
    pidsLimit: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 512 },
    oomKillDisable: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    oomScoreAdj: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    dockerImage: { type: DataTypes.STRING, allowNull: true },
    startup: { type: DataTypes.TEXT, allowNull: true },
    variables: { type: DataTypes.JSON, defaultValue: {} }
});

const ServerSubuser = sequelize.define('ServerSubuser', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false },
    userId: { type: DataTypes.INTEGER, allowNull: false },
    invitedByUserId: { type: DataTypes.INTEGER, allowNull: true },
    permissions: { type: DataTypes.JSON, allowNull: false, defaultValue: [] }
}, {
    indexes: [
        {
            unique: true,
            fields: ['serverId', 'userId']
        }
    ]
});

const ServerApiKey = sequelize.define('ServerApiKey', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false },
    ownerUserId: { type: DataTypes.INTEGER, allowNull: false },
    name: { type: DataTypes.STRING(120), allowNull: false },
    keyPrefix: { type: DataTypes.STRING(16), allowNull: false },
    keyHash: { type: DataTypes.STRING(128), allowNull: false },
    permissions: { type: DataTypes.JSON, allowNull: false, defaultValue: [] },
    lastUsedAt: { type: DataTypes.DATE, allowNull: true },
    lastUsedIp: { type: DataTypes.STRING(120), allowNull: true },
    expiresAt: { type: DataTypes.DATE, allowNull: true },
    revokedAt: { type: DataTypes.DATE, allowNull: true }
}, {
    indexes: [
        { fields: ['serverId'] },
        { fields: ['ownerUserId'] },
        { fields: ['keyHash'], unique: true },
        { fields: ['serverId', 'keyPrefix'] }
    ]
});

const ServerCommandMacro = sequelize.define('ServerCommandMacro', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false },
    createdByUserId: { type: DataTypes.INTEGER, allowNull: true },
    name: { type: DataTypes.STRING(80), allowNull: false },
    description: { type: DataTypes.STRING(160), allowNull: true },
    command: { type: DataTypes.STRING(1024), allowNull: false },
    position: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 }
}, {
    indexes: [
        { fields: ['serverId'] },
        { fields: ['createdByUserId'] },
        { fields: ['serverId', 'position'] }
    ]
});

const ServerResourceSample = sequelize.define('ServerResourceSample', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false },
    cpuPercent: { type: DataTypes.FLOAT, allowNull: false, defaultValue: 0 },
    memoryMb: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    diskMb: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    collectedAt: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW }
}, {
    indexes: [
        { fields: ['serverId'] },
        { fields: ['collectedAt'] },
        { fields: ['serverId', 'collectedAt'] }
    ]
});

const AdminApiKey = sequelize.define('AdminApiKey', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    creatorUserId: { type: DataTypes.INTEGER, allowNull: false },
    name: { type: DataTypes.STRING(120), allowNull: false, unique: true },
    keyPrefix: { type: DataTypes.STRING(16), allowNull: false },
    keyHash: { type: DataTypes.STRING(128), allowNull: false },
    permissions: { type: DataTypes.JSON, allowNull: false, defaultValue: [] },
    lastUsedAt: { type: DataTypes.DATE, allowNull: true },
    lastUsedIp: { type: DataTypes.STRING(120), allowNull: true },
    lastUsedGeo: { type: DataTypes.STRING(160), allowNull: true },
    allowedIps: { type: DataTypes.JSON, allowNull: false, defaultValue: [] },
    expiresAt: { type: DataTypes.DATE, allowNull: true },
    rotationIntervalDays: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    rotatedAt: { type: DataTypes.DATE, allowNull: true },
    revokedAt: { type: DataTypes.DATE, allowNull: true }
}, {
    indexes: [
        { fields: ['creatorUserId'] },
        { fields: ['name'], unique: true },
        { fields: ['keyHash'], unique: true },
        { fields: ['keyPrefix'] }
    ]
});

const AdminApiKeyAudit = sequelize.define('AdminApiKeyAudit', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    adminApiKeyId: { type: DataTypes.INTEGER, allowNull: false },
    method: { type: DataTypes.STRING(10), allowNull: true },
    path: { type: DataTypes.STRING(255), allowNull: true },
    permission: { type: DataTypes.STRING(120), allowNull: true },
    statusCode: { type: DataTypes.INTEGER, allowNull: true },
    ip: { type: DataTypes.STRING(120), allowNull: true },
    userAgent: { type: DataTypes.TEXT, allowNull: true },
    metadata: { type: DataTypes.JSON, allowNull: true }
}, {
    indexes: [
        { fields: ['adminApiKeyId'] },
        { fields: ['createdAt'] },
        { fields: ['path'] }
    ]
});

const Job = sequelize.define('Job', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    type: { type: DataTypes.STRING(100), allowNull: false },
    status: { type: DataTypes.STRING(32), allowNull: false, defaultValue: 'queued' },
    priority: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    payload: { type: DataTypes.JSON, allowNull: false, defaultValue: {} },
    result: { type: DataTypes.JSON, allowNull: true },
    attempts: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
    maxAttempts: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 3 },
    runAt: { type: DataTypes.DATE, allowNull: false, defaultValue: DataTypes.NOW },
    lockedAt: { type: DataTypes.DATE, allowNull: true },
    lockOwner: { type: DataTypes.STRING(120), allowNull: true },
    startedAt: { type: DataTypes.DATE, allowNull: true },
    finishedAt: { type: DataTypes.DATE, allowNull: true },
    lastError: { type: DataTypes.TEXT, allowNull: true },
    createdByUserId: { type: DataTypes.INTEGER, allowNull: true }
});

const AuditLog = sequelize.define('AuditLog', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    actorUserId: { type: DataTypes.INTEGER, allowNull: true },
    action: { type: DataTypes.STRING(120), allowNull: false },
    targetType: { type: DataTypes.STRING(64), allowNull: true },
    targetId: { type: DataTypes.STRING(120), allowNull: true },
    method: { type: DataTypes.STRING(10), allowNull: true },
    path: { type: DataTypes.STRING(255), allowNull: true },
    ip: { type: DataTypes.STRING(120), allowNull: true },
    userAgent: { type: DataTypes.TEXT, allowNull: true },
    metadata: { type: DataTypes.JSON, allowNull: true }
});

const SecurityEvent = sequelize.define('SecurityEvent', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    userId: { type: DataTypes.INTEGER, allowNull: true },
    severity: { type: DataTypes.STRING(16), allowNull: false, defaultValue: 'medium' },
    category: { type: DataTypes.STRING(40), allowNull: false, defaultValue: 'request' },
    eventType: { type: DataTypes.STRING(120), allowNull: false },
    message: { type: DataTypes.STRING(255), allowNull: false },
    source: { type: DataTypes.STRING(40), allowNull: false, defaultValue: 'panel' },
    method: { type: DataTypes.STRING(10), allowNull: true },
    path: { type: DataTypes.STRING(255), allowNull: true },
    ip: { type: DataTypes.STRING(120), allowNull: true },
    userAgent: { type: DataTypes.TEXT, allowNull: true },
    requestId: { type: DataTypes.STRING(64), allowNull: true },
    metadata: { type: DataTypes.JSON, allowNull: true }
}, {
    indexes: [
        { fields: ['createdAt'] },
        { fields: ['severity'] },
        { fields: ['category'] },
        { fields: ['eventType'] },
        { fields: ['ip'] },
        { fields: ['userId'] }
    ]
});

const ServerBackupPolicy = sequelize.define('ServerBackupPolicy', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false, unique: true },
    enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    intervalMinutes: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 720 },
    retentionCount: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 5 },
    destinationPath: { type: DataTypes.STRING, allowNull: false, defaultValue: './backups' },
    lastRunAt: { type: DataTypes.DATE, allowNull: true }
});

const ServerBackup = sequelize.define('ServerBackup', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false },
    status: { type: DataTypes.STRING(32), allowNull: false, defaultValue: 'completed' },
    filePath: { type: DataTypes.STRING, allowNull: false },
    sizeBytes: { type: DataTypes.BIGINT, allowNull: true },
    checksum: { type: DataTypes.STRING(128), allowNull: true },
    metadata: { type: DataTypes.JSON, allowNull: true }
});

const Mount = sequelize.define('Mount', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    name: { type: DataTypes.STRING(120), allowNull: false },
    description: { type: DataTypes.STRING(255), allowNull: true },
    sourcePath: { type: DataTypes.STRING(512), allowNull: false },
    targetPath: { type: DataTypes.STRING(512), allowNull: false },
    readOnly: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    connectorId: { type: DataTypes.INTEGER, allowNull: true }
});

const ServerMount = sequelize.define('ServerMount', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    serverId: { type: DataTypes.INTEGER, allowNull: false },
    mountId: { type: DataTypes.INTEGER, allowNull: false },
    readOnly: { type: DataTypes.BOOLEAN, allowNull: true }
}, {
    indexes: [
        { fields: ['serverId'] },
        { fields: ['mountId'] },
        { fields: ['serverId', 'mountId'], unique: true }
    ]
});

// Associations
User.hasMany(LinkedAccount, { foreignKey: 'userId', as: 'linkedAccounts' });
LinkedAccount.belongsTo(User, { foreignKey: 'userId' });
User.hasMany(UserLoginEvent, {
    foreignKey: 'userId',
    as: 'loginEvents',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
UserLoginEvent.belongsTo(User, {
    foreignKey: 'userId',
    as: 'user',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});

User.hasMany(Server, { foreignKey: 'ownerId', as: 'servers' });
Server.belongsTo(User, { foreignKey: 'ownerId', as: 'owner' });

Image.hasMany(Server, { foreignKey: 'imageId', as: 'servers' });
Server.belongsTo(Image, { foreignKey: 'imageId', as: 'image' });

Allocation.hasOne(Server, { foreignKey: 'allocationId', as: 'server' });
Server.belongsTo(Allocation, { foreignKey: 'allocationId', as: 'allocation' });

Location.hasMany(DatabaseHost, { foreignKey: 'locationId', as: 'databaseHosts' });
DatabaseHost.belongsTo(Location, { foreignKey: 'locationId', as: 'location' });
Server.hasMany(ServerDatabase, {
    foreignKey: 'serverId',
    as: 'databases',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
ServerDatabase.belongsTo(Server, {
    foreignKey: 'serverId',
    as: 'server',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});
DatabaseHost.hasMany(ServerDatabase, {
    foreignKey: 'databaseHostId',
    as: 'serverDatabases',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
ServerDatabase.belongsTo(DatabaseHost, {
    foreignKey: 'databaseHostId',
    as: 'host',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});

Location.hasMany(Connector, { foreignKey: 'locationId', as: 'connectors' });
Connector.belongsTo(Location, { foreignKey: 'locationId', as: 'location' });

Connector.hasMany(Allocation, { foreignKey: 'connectorId', as: 'allocations' });
Allocation.belongsTo(Connector, { foreignKey: 'connectorId', as: 'connector' });

Image.belongsTo(Package, { foreignKey: 'packageId', as: 'package' });
Package.hasMany(Image, { foreignKey: 'packageId', as: 'images' });

User.hasMany(AuditLog, { foreignKey: 'actorUserId', as: 'auditEntries' });
AuditLog.belongsTo(User, { foreignKey: 'actorUserId', as: 'actor' });
User.hasMany(SecurityEvent, {
    foreignKey: 'userId',
    as: 'securityEvents',
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE'
});
SecurityEvent.belongsTo(User, {
    foreignKey: 'userId',
    as: 'user',
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE'
});

Server.hasOne(ServerBackupPolicy, { foreignKey: 'serverId', as: 'backupPolicy' });
ServerBackupPolicy.belongsTo(Server, { foreignKey: 'serverId', as: 'server' });

Connector.hasMany(Mount, { foreignKey: 'connectorId', as: 'mounts' });
Mount.belongsTo(Connector, { foreignKey: 'connectorId', as: 'connector' });

Server.belongsToMany(Mount, { through: ServerMount, foreignKey: 'serverId', otherKey: 'mountId', as: 'mounts' });
Mount.belongsToMany(Server, { through: ServerMount, foreignKey: 'mountId', otherKey: 'serverId', as: 'servers' });
Server.hasMany(ServerMount, { foreignKey: 'serverId', as: 'serverMounts', onDelete: 'CASCADE', hooks: true });
ServerMount.belongsTo(Server, { foreignKey: 'serverId', as: 'server', onDelete: 'CASCADE' });
Mount.hasMany(ServerMount, { foreignKey: 'mountId', as: 'serverMounts', onDelete: 'CASCADE', hooks: true });
ServerMount.belongsTo(Mount, { foreignKey: 'mountId', as: 'mount', onDelete: 'CASCADE' });

Server.hasMany(ServerBackup, { foreignKey: 'serverId', as: 'backups' });
ServerBackup.belongsTo(Server, { foreignKey: 'serverId', as: 'server' });

Server.hasMany(ServerSubuser, { foreignKey: 'serverId', as: 'subusers' });
ServerSubuser.belongsTo(Server, { foreignKey: 'serverId', as: 'server' });
User.hasMany(ServerSubuser, { foreignKey: 'userId', as: 'serverMemberships' });
ServerSubuser.belongsTo(User, { foreignKey: 'userId', as: 'user' });
User.hasMany(ServerSubuser, { foreignKey: 'invitedByUserId', as: 'invitedSubusers' });
ServerSubuser.belongsTo(User, { foreignKey: 'invitedByUserId', as: 'invitedBy' });
Server.hasMany(ServerApiKey, {
    foreignKey: 'serverId',
    as: 'apiKeys',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
ServerApiKey.belongsTo(Server, {
    foreignKey: 'serverId',
    as: 'server',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});
User.hasMany(ServerApiKey, {
    foreignKey: 'ownerUserId',
    as: 'serverApiKeys',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
ServerApiKey.belongsTo(User, {
    foreignKey: 'ownerUserId',
    as: 'owner',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});
Server.hasMany(ServerCommandMacro, {
    foreignKey: 'serverId',
    as: 'commandMacros',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
ServerCommandMacro.belongsTo(Server, {
    foreignKey: 'serverId',
    as: 'server',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});
User.hasMany(ServerCommandMacro, {
    foreignKey: 'createdByUserId',
    as: 'createdServerMacros',
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE'
});
ServerCommandMacro.belongsTo(User, {
    foreignKey: 'createdByUserId',
    as: 'creator',
    onDelete: 'SET NULL',
    onUpdate: 'CASCADE'
});
Server.hasMany(ServerResourceSample, {
    foreignKey: 'serverId',
    as: 'resourceSamples',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
ServerResourceSample.belongsTo(Server, {
    foreignKey: 'serverId',
    as: 'server',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});
User.hasMany(AdminApiKey, {
    foreignKey: 'creatorUserId',
    as: 'adminApiKeys',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
AdminApiKey.belongsTo(User, {
    foreignKey: 'creatorUserId',
    as: 'creator',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});
AdminApiKey.hasMany(AdminApiKeyAudit, {
    foreignKey: 'adminApiKeyId',
    as: 'usageAudit',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE',
    hooks: true
});
AdminApiKeyAudit.belongsTo(AdminApiKey, {
    foreignKey: 'adminApiKeyId',
    as: 'apiKey',
    onDelete: 'CASCADE',
    onUpdate: 'CASCADE'
});

async function upgrade() {
    let sqliteForeignKeysDisabled = false;
    try {
        console.log('Starting database upgrade...');

        // Sync the Settings model
        await Settings.sync();
        console.log('Settings table synced.');

        // Sync the Location model
        await Location.sync();
        console.log('Location table synced.');

        // Sync the DatabaseHost model
        await DatabaseHost.sync();
        console.log('DatabaseHost table synced.');

        // Sync the Package model
        await Package.sync();
        console.log('Package table synced.');

        // SQLite cannot safely run ALTER-based table rebuilds when FK checks are on.
        if (dbConnection === 'sqlite') {
            await sequelize.query('PRAGMA foreign_keys = OFF');
            sqliteForeignKeysDisabled = true;
            console.log('SQLite foreign key checks temporarily disabled for ALTER sync.');

            const backupTables = await sequelize.query(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE '%\\_backup' ESCAPE '\\'",
                { type: QueryTypes.SELECT }
            );

            for (const table of backupTables) {
                await sequelize.query(`DROP TABLE IF EXISTS \`${table.name}\``);
                console.log(`Removed stale backup table: ${table.name}`);
            }
        }

        // Pre-sync repair for legacy SQLite installs where ServerDatabases has
        // an invalid UNIQUE(databaseHostId) constraint.
        const preSyncResolveTableName = (model) => {
            const table = model.getTableName();
            if (typeof table === 'string') return table;
            if (table && typeof table.tableName === 'string') return table.tableName;
            return String(table);
        };
        const preSyncTableExists = async (tableName) => {
            if (dbConnection !== 'sqlite') return false;
            const rows = await sequelize.query(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = :tableName",
                { type: QueryTypes.SELECT, replacements: { tableName } }
            );
            return Array.isArray(rows) && rows.length > 0;
        };
        const preSyncListSqliteIndexes = async (tableName) => {
            if (dbConnection !== 'sqlite') return [];
            if (!await preSyncTableExists(tableName)) return [];
            return sequelize.query(`PRAGMA index_list(\`${tableName}\`)`, { type: QueryTypes.SELECT });
        };
        const preSyncListSqliteIndexColumns = async (indexName) => {
            if (dbConnection !== 'sqlite') return [];
            return sequelize.query(`PRAGMA index_info(\`${indexName}\`)`, { type: QueryTypes.SELECT });
        };
        const preSyncHasLegacyServerDatabaseHostUniqueConstraint = async (tableName) => {
            if (dbConnection !== 'sqlite') return false;
            const indexes = await preSyncListSqliteIndexes(tableName);
            for (const index of indexes) {
                if (!Number(index && index.unique)) continue;
                const indexName = String(index && index.name ? index.name : '').trim();
                if (!indexName) continue;
                const columns = await preSyncListSqliteIndexColumns(indexName);
                const names = columns
                    .map((col) => String((col && col.name) || '').trim())
                    .filter(Boolean);
                if (names.length === 1 && names[0] === 'databaseHostId') {
                    return true;
                }
            }
            return false;
        };
        const preSyncRebuildServerDatabaseTableWithoutLegacyUnique = async (tableName) => {
            if (dbConnection !== 'sqlite') return;
            if (!await preSyncTableExists(tableName)) return;
            const queryInterface = sequelize.getQueryInterface();
            const tempTable = `${tableName}__host_fix_tmp`;
            await sequelize.query(`DROP TABLE IF EXISTS \`${tempTable}\``);
            await queryInterface.createTable(tempTable, {
                id: { type: DataTypes.INTEGER, allowNull: false, primaryKey: true, autoIncrement: true },
                serverId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    references: { model: preSyncResolveTableName(Server), key: 'id' },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE'
                },
                databaseHostId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    references: { model: preSyncResolveTableName(DatabaseHost), key: 'id' },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE'
                },
                name: { type: DataTypes.STRING, allowNull: false },
                username: { type: DataTypes.STRING, allowNull: false },
                password: { type: DataTypes.STRING, allowNull: false },
                remoteDatabaseId: { type: DataTypes.STRING, allowNull: true },
                createdAt: { type: DataTypes.DATE, allowNull: false },
                updatedAt: { type: DataTypes.DATE, allowNull: false }
            });
            await sequelize.query(
                `INSERT INTO \`${tempTable}\` (` +
                '`id`,`serverId`,`databaseHostId`,`name`,`username`,`password`,`remoteDatabaseId`,`createdAt`,`updatedAt`) ' +
                `SELECT ` +
                '`id`,`serverId`,`databaseHostId`,`name`,`username`,`password`,`remoteDatabaseId`,`createdAt`,`updatedAt` ' +
                `FROM \`${tableName}\``
            );
            await sequelize.query(`DROP TABLE \`${tableName}\``);
            await sequelize.query(`ALTER TABLE \`${tempTable}\` RENAME TO \`${tableName}\``);
        };

        const preSyncServerDatabaseTable = preSyncResolveTableName(ServerDatabase);
        if (await preSyncHasLegacyServerDatabaseHostUniqueConstraint(preSyncServerDatabaseTable)) {
            console.log('Pre-sync: detected legacy UNIQUE(databaseHostId) on ServerDatabases. Repairing before ALTER sync...');
            await preSyncRebuildServerDatabaseTableWithoutLegacyUnique(preSyncServerDatabaseTable);
            console.log('Pre-sync: ServerDatabases legacy unique constraint repaired.');
        }

        await User.sync({ alter: true });
        console.log('User table synced.');

        // Sync the LinkedAccount model
        await LinkedAccount.sync({ alter: true });
        console.log('LinkedAccount table synced.');

        // Sync the UserLoginEvent model
        await UserLoginEvent.sync({ alter: true });
        console.log('UserLoginEvent table synced.');

        // Sync the Connector model
        await Connector.sync({ alter: true });
        console.log('Connector table synced.');

        // Sync the Allocation model
        await Allocation.sync({ alter: true });
        console.log('Allocation table synced.');

        // Sync the Image model
        await Image.sync({ alter: true });
        console.log('Image table synced.');

        // Sync the Server model
        await Server.sync({ alter: true });
        console.log('Server table synced.');

        // Sync the ServerDatabase model
        // SQLite `alter` path rebuilds via *_backup and may fail on legacy unique constraints.
        // We already do a targeted pre-sync repair + defensive index repair below, so use safe sync.
        if (dbConnection === 'sqlite') {
            await ServerDatabase.sync();
        } else {
            await ServerDatabase.sync({ alter: true });
        }
        console.log('ServerDatabase table synced.');

        // Sync the ServerSubuser model
        await ServerSubuser.sync({ alter: true });
        console.log('ServerSubuser table synced.');

        // Sync the ServerApiKey model
        await ServerApiKey.sync({ alter: true });
        console.log('ServerApiKey table synced.');

        // Sync the ServerCommandMacro model
        await ServerCommandMacro.sync({ alter: true });
        console.log('ServerCommandMacro table synced.');

        // Sync the ServerResourceSample model
        await ServerResourceSample.sync({ alter: true });
        console.log('ServerResourceSample table synced.');

        // Sync the AdminApiKey model
        await AdminApiKey.sync({ alter: true });
        console.log('AdminApiKey table synced.');

        // Sync the AdminApiKeyAudit model
        await AdminApiKeyAudit.sync({ alter: true });
        console.log('AdminApiKeyAudit table synced.');

        // Sync the Job model
        await Job.sync({ alter: true });
        console.log('Job table synced.');

        // Sync the AuditLog model
        await AuditLog.sync({ alter: true });
        console.log('AuditLog table synced.');

        // Sync the SecurityEvent model
        await SecurityEvent.sync({ alter: true });
        console.log('SecurityEvent table synced.');

        // Sync the ServerBackupPolicy model
        await ServerBackupPolicy.sync({ alter: true });
        console.log('ServerBackupPolicy table synced.');

        // Sync the ServerBackup model
        await ServerBackup.sync({ alter: true });
        console.log('ServerBackup table synced.');

        // Sync the Mount model
        await Mount.sync({ alter: true });
        console.log('Mount table synced.');

        // Sync the ServerMount model
        await ServerMount.sync({ alter: true });
        console.log('ServerMount table synced.');

        // Backfill legacy/null values for JSON and required fields used by newer features.
        await User.update(
            { coins: 0 },
            { where: { coins: null } }
        );
        await User.update(
            { permissions: {} },
            { where: { permissions: null } }
        );
        await UserLoginEvent.update(
            { loginType: 'email' },
            { where: { loginType: null } }
        );
        await UserLoginEvent.update(
            { ipAddress: 'unknown' },
            { where: { ipAddress: null } }
        );
        await UserLoginEvent.update(
            { usernameSnapshot: 'unknown' },
            { where: { usernameSnapshot: null } }
        );
        await Server.update(
            { status: 'offline' },
            { where: { status: null } }
        );
        await Server.update(
            { variables: {} },
            { where: { variables: null } }
        );
        await Server.update(
            { tags: [] },
            { where: { tags: null } }
        );
        await Server.update(
            { databaseLimit: 0 },
            { where: { databaseLimit: null } }
        );
        await Connector.update(
            { isPublic: true },
            { where: { isPublic: null } }
        );
        await ServerSubuser.update(
            { permissions: [] },
            { where: { permissions: null } }
        );
        await ServerApiKey.update(
            { permissions: [] },
            { where: { permissions: null } }
        );
        await AdminApiKey.update(
            { permissions: [] },
            { where: { permissions: null } }
        );
        await AdminApiKey.update(
            { allowedIps: [] },
            { where: { allowedIps: null } }
        );
        await AdminApiKey.update(
            { rotationIntervalDays: 0 },
            { where: { rotationIntervalDays: null } }
        );
        await Image.update(
            { isPublic: true },
            { where: { isPublic: null } }
        );
        await Image.update(
            { dockerImages: {} },
            { where: { dockerImages: null } }
        );
        await Image.update(
            { environment: {} },
            { where: { environment: null } }
        );
        await Image.update(
            { eggVariables: [] },
            { where: { eggVariables: null } }
        );
        console.log('Null backfills completed for User/Server/Subuser/ApiKey/Image/AdminApiKey.');

        // Defensive index repair for older installs where alter may skip/rebuild indexes inconsistently.
        const queryInterface = sequelize.getQueryInterface();
        const resolveTableName = (model) => {
            const table = model.getTableName();
            if (typeof table === 'string') return table;
            if (table && typeof table.tableName === 'string') return table.tableName;
            return String(table);
        };
        const addIndexIfMissing = async (tableName, fields, options) => {
            try {
                await queryInterface.addIndex(tableName, fields, options);
            } catch (error) {
                const msg = String(error && error.message ? error.message : '').toLowerCase();
                const alreadyExists =
                    msg.includes('already exists') ||
                    msg.includes('duplicate key name') ||
                    msg.includes('duplicate relation') ||
                    (msg.includes('relation') && msg.includes('already exists'));
                if (alreadyExists) {
                    return;
                }
                throw error;
            }
        };
        const listSqliteIndexes = async (tableName) => {
            if (dbConnection !== 'sqlite') return [];
            return sequelize.query(`PRAGMA index_list(\`${tableName}\`)`, { type: QueryTypes.SELECT });
        };
        const listSqliteIndexColumns = async (indexName) => {
            if (dbConnection !== 'sqlite') return [];
            return sequelize.query(`PRAGMA index_info(\`${indexName}\`)`, { type: QueryTypes.SELECT });
        };
        const hasLegacyServerDatabaseHostUniqueConstraint = async (tableName) => {
            if (dbConnection !== 'sqlite') return false;
            const indexes = await listSqliteIndexes(tableName);
            for (const index of indexes) {
                if (!Number(index && index.unique)) continue;
                const indexName = String(index && index.name ? index.name : '').trim();
                if (!indexName) continue;
                const columns = await listSqliteIndexColumns(indexName);
                const names = columns
                    .map((col) => String((col && col.name) || '').trim())
                    .filter(Boolean);
                if (names.length === 1 && names[0] === 'databaseHostId') {
                    return true;
                }
            }
            return false;
        };
        const rebuildServerDatabaseTableWithoutLegacyUnique = async (tableName) => {
            if (dbConnection !== 'sqlite') return;
            const tempTable = `${tableName}__host_fix_tmp`;
            await sequelize.query(`DROP TABLE IF EXISTS \`${tempTable}\``);
            await queryInterface.createTable(tempTable, {
                id: { type: DataTypes.INTEGER, allowNull: false, primaryKey: true, autoIncrement: true },
                serverId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    references: { model: resolveTableName(Server), key: 'id' },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE'
                },
                databaseHostId: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    references: { model: resolveTableName(DatabaseHost), key: 'id' },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE'
                },
                name: { type: DataTypes.STRING, allowNull: false },
                username: { type: DataTypes.STRING, allowNull: false },
                password: { type: DataTypes.STRING, allowNull: false },
                remoteDatabaseId: { type: DataTypes.STRING, allowNull: true },
                createdAt: { type: DataTypes.DATE, allowNull: false },
                updatedAt: { type: DataTypes.DATE, allowNull: false }
            });
            await sequelize.query(
                `INSERT INTO \`${tempTable}\` (` +
                '`id`,`serverId`,`databaseHostId`,`name`,`username`,`password`,`remoteDatabaseId`,`createdAt`,`updatedAt`) ' +
                `SELECT ` +
                '`id`,`serverId`,`databaseHostId`,`name`,`username`,`password`,`remoteDatabaseId`,`createdAt`,`updatedAt` ' +
                `FROM \`${tableName}\``
            );
            await sequelize.query(`DROP TABLE \`${tableName}\``);
            await sequelize.query(`ALTER TABLE \`${tempTable}\` RENAME TO \`${tableName}\``);
        };
        const userTable = resolveTableName(User);
        const userLoginEventTable = resolveTableName(UserLoginEvent);
        const serverTable = resolveTableName(Server);
        const allocationTable = resolveTableName(Allocation);
        const serverSubuserTable = resolveTableName(ServerSubuser);
        const serverApiKeyTable = resolveTableName(ServerApiKey);
        const serverCommandMacroTable = resolveTableName(ServerCommandMacro);
        const serverResourceSampleTable = resolveTableName(ServerResourceSample);
        const adminApiKeyTable = resolveTableName(AdminApiKey);
        const adminApiKeyAuditTable = resolveTableName(AdminApiKeyAudit);
        const jobTable = resolveTableName(Job);
        const auditLogTable = resolveTableName(AuditLog);
        const securityEventTable = resolveTableName(SecurityEvent);
        const backupPolicyTable = resolveTableName(ServerBackupPolicy);
        const backupTable = resolveTableName(ServerBackup);
        const serverDatabaseTable = resolveTableName(ServerDatabase);

        if (await hasLegacyServerDatabaseHostUniqueConstraint(serverDatabaseTable)) {
            console.log('Detected legacy UNIQUE(databaseHostId) on ServerDatabases. Rebuilding table to repair schema...');
            await rebuildServerDatabaseTableWithoutLegacyUnique(serverDatabaseTable);
            console.log('ServerDatabases schema repaired.');
        }

        await addIndexIfMissing(serverApiKeyTable, ['serverId'], { name: 'server_api_keys_server_id_idx' });
        await addIndexIfMissing(serverApiKeyTable, ['ownerUserId'], { name: 'server_api_keys_owner_user_id_idx' });
        await addIndexIfMissing(serverApiKeyTable, ['serverId', 'keyPrefix'], { name: 'server_api_keys_server_prefix_idx' });
        await addIndexIfMissing(serverApiKeyTable, ['keyHash'], { name: 'server_api_keys_key_hash_uq', unique: true });
        await addIndexIfMissing(serverCommandMacroTable, ['serverId'], { name: 'server_command_macros_server_id_idx' });
        await addIndexIfMissing(serverCommandMacroTable, ['createdByUserId'], { name: 'server_command_macros_creator_user_id_idx' });
        await addIndexIfMissing(serverCommandMacroTable, ['serverId', 'position'], { name: 'server_command_macros_server_position_idx' });
        await addIndexIfMissing(serverResourceSampleTable, ['serverId'], { name: 'server_resource_samples_server_id_idx' });
        await addIndexIfMissing(serverResourceSampleTable, ['collectedAt'], { name: 'server_resource_samples_collected_at_idx' });
        await addIndexIfMissing(serverResourceSampleTable, ['serverId', 'collectedAt'], { name: 'server_resource_samples_server_collected_idx' });
        await addIndexIfMissing(adminApiKeyTable, ['creatorUserId'], { name: 'admin_api_keys_creator_user_id_idx' });
        await addIndexIfMissing(adminApiKeyTable, ['name'], { name: 'admin_api_keys_name_uq', unique: true });
        await addIndexIfMissing(adminApiKeyTable, ['keyHash'], { name: 'admin_api_keys_key_hash_uq', unique: true });
        await addIndexIfMissing(adminApiKeyTable, ['keyPrefix'], { name: 'admin_api_keys_prefix_idx' });
        await addIndexIfMissing(adminApiKeyAuditTable, ['adminApiKeyId'], { name: 'admin_api_key_audit_key_id_idx' });
        await addIndexIfMissing(adminApiKeyAuditTable, ['createdAt'], { name: 'admin_api_key_audit_created_at_idx' });
        await addIndexIfMissing(adminApiKeyAuditTable, ['path'], { name: 'admin_api_key_audit_path_idx' });

        await addIndexIfMissing(userTable, ['username'], { name: 'users_username_idx' });
        await addIndexIfMissing(userTable, ['email'], { name: 'users_email_idx' });
        await addIndexIfMissing(userLoginEventTable, ['userId'], { name: 'user_login_events_user_id_idx' });
        await addIndexIfMissing(userLoginEventTable, ['createdAt'], { name: 'user_login_events_created_at_idx' });
        await addIndexIfMissing(userLoginEventTable, ['userId', 'createdAt'], { name: 'user_login_events_user_created_idx' });

        await addIndexIfMissing(serverTable, ['ownerId'], { name: 'servers_owner_id_idx' });
        await addIndexIfMissing(serverTable, ['allocationId'], { name: 'servers_allocation_id_idx' });
        await addIndexIfMissing(serverTable, ['containerId'], { name: 'servers_container_id_idx' });

        await addIndexIfMissing(allocationTable, ['connectorId'], { name: 'allocations_connector_id_idx' });
        await addIndexIfMissing(allocationTable, ['serverId'], { name: 'allocations_server_id_idx' });

        await addIndexIfMissing(serverSubuserTable, ['serverId'], { name: 'server_subusers_server_id_idx' });
        await addIndexIfMissing(serverSubuserTable, ['userId'], { name: 'server_subusers_user_id_idx' });

        await addIndexIfMissing(jobTable, ['status', 'runAt', 'priority'], { name: 'jobs_queue_scan_idx' });
        await addIndexIfMissing(jobTable, ['lockedAt'], { name: 'jobs_locked_at_idx' });
        await addIndexIfMissing(jobTable, ['createdByUserId'], { name: 'jobs_created_by_user_id_idx' });
        await addIndexIfMissing(jobTable, ['type'], { name: 'jobs_type_idx' });

        await addIndexIfMissing(auditLogTable, ['action'], { name: 'audit_logs_action_idx' });
        await addIndexIfMissing(auditLogTable, ['actorUserId'], { name: 'audit_logs_actor_user_id_idx' });
        await addIndexIfMissing(auditLogTable, ['targetType', 'targetId'], { name: 'audit_logs_target_idx' });
        await addIndexIfMissing(auditLogTable, ['createdAt'], { name: 'audit_logs_created_at_idx' });
        await addIndexIfMissing(securityEventTable, ['createdAt'], { name: 'security_events_created_at_idx' });
        await addIndexIfMissing(securityEventTable, ['severity'], { name: 'security_events_severity_idx' });
        await addIndexIfMissing(securityEventTable, ['category'], { name: 'security_events_category_idx' });
        await addIndexIfMissing(securityEventTable, ['eventType'], { name: 'security_events_event_type_idx' });
        await addIndexIfMissing(securityEventTable, ['ip'], { name: 'security_events_ip_idx' });
        await addIndexIfMissing(securityEventTable, ['userId'], { name: 'security_events_user_id_idx' });

        await addIndexIfMissing(backupPolicyTable, ['serverId'], { name: 'server_backup_policies_server_id_idx' });
        await addIndexIfMissing(backupTable, ['serverId'], { name: 'server_backups_server_id_idx' });
        await addIndexIfMissing(backupTable, ['createdAt'], { name: 'server_backups_created_at_idx' });
        await addIndexIfMissing(serverDatabaseTable, ['serverId'], { name: 'server_databases_server_id_idx' });
        await addIndexIfMissing(serverDatabaseTable, ['databaseHostId'], { name: 'server_databases_host_id_idx' });
        await addIndexIfMissing(serverDatabaseTable, ['serverId', 'name'], { name: 'server_databases_server_name_uq', unique: true });
        await addIndexIfMissing(serverDatabaseTable, ['databaseHostId', 'name'], { name: 'server_databases_host_name_uq', unique: true });
        console.log('Defensive indexes verified.');

        if (sqliteForeignKeysDisabled) {
            await sequelize.query('PRAGMA foreign_keys = ON');
            sqliteForeignKeysDisabled = false;
            console.log('SQLite foreign key checks re-enabled.');
        }

        // Seed default values if they don't exist
        const defaults = [
            { key: 'brandName', value: 'CPanel' },
            { key: 'faviconUrl', value: '/assets/rocky.png' },
            { key: 'captchastatus', value: 'off' },
            { key: 'authStandardEnabled', value: 'true' },
            { key: 'authDiscordEnabled', value: 'false' },
            { key: 'authDiscordRegisterEnabled', value: 'true' },
            { key: 'authDiscordClientId', value: '' },
            { key: 'authDiscordClientSecret', value: '' },
            { key: 'authGoogleEnabled', value: 'false' },
            { key: 'authGoogleRegisterEnabled', value: 'true' },
            { key: 'authGoogleClientId', value: '' },
            { key: 'authGoogleClientSecret', value: '' },
            { key: 'authRedditEnabled', value: 'false' },
            { key: 'authRedditRegisterEnabled', value: 'true' },
            { key: 'authRedditClientId', value: '' },
            { key: 'authRedditClientSecret', value: '' },
            { key: 'authGithubEnabled', value: 'false' },
            { key: 'authGithubRegisterEnabled', value: 'true' },
            { key: 'authGithubClientId', value: '' },
            { key: 'authGithubClientSecret', value: '' },
            { key: 'featureCostPerServerEnabled', value: 'false' },
            { key: 'featureUserCreateEnabled', value: 'false' },
            { key: 'featureInventoryEnabled', value: 'false' },
            { key: 'featureStoreDealsEnabled', value: 'false' },
            { key: 'featureStoreRedeemCodesEnabled', value: 'false' },
            { key: 'featureBillingInvoicesEnabled', value: 'true' },
            { key: 'featureBillingStatementsEnabled', value: 'true' },
            { key: 'featureBillingInvoiceWebhookEnabled', value: 'false' },
            { key: 'featureAutoRemediationEnabled', value: 'false' },
            { key: 'featureAntiMinerEnabled', value: 'false' },
            { key: 'featureAbuseScoreEnabled', value: 'false' },
            { key: 'abuseScoreWindowHours', value: '72' },
            { key: 'abuseScoreAlertThreshold', value: '80' },
            { key: 'featureServiceHealthChecksEnabled', value: 'false' },
            { key: 'serviceHealthCheckIntervalSeconds', value: '300' },
            { key: 'featureSentrySeekerEnabled', value: 'true' },
            { key: 'sentrySeekerRetentionDays', value: '30' },
            { key: 'securityMaxBodyMb', value: '2' },
            { key: 'featurePolicyEngineEnabled', value: 'false' },
            { key: 'featurePlaybooksAutomationEnabled', value: 'false' },
            { key: 'featureStrictAuditEnabled', value: 'false' },
            { key: 'featureSftpEnabled', value: 'true' },
            { key: 'featureWebUploadEnabled', value: 'true' },
            { key: 'featureWebUploadMaxMb', value: '50' },
            { key: 'featureServerApiKeysEnabled', value: 'true' },
            { key: 'featureAfkRewardsEnabled', value: 'false' },
            { key: 'featureClaimRewardsEnabled', value: 'false' },
            { key: 'featureQuotaForecastingEnabled', value: 'true' },
            { key: 'featureScheduledScalingEnabled', value: 'false' },
            { key: 'featureAdminApiRatePlansEnabled', value: 'false' },
            { key: 'featureAdminRbacV2Enabled', value: 'false' },
            { key: 'featureAdminRbacV2StrictEnabled', value: 'false' },
            { key: 'featureRevenueModeEnabled', value: 'false' },
            { key: 'revenueDefaultTrialDays', value: '3' },
            { key: 'revenueGraceDays', value: '2' },
            { key: 'extensionAnnouncerEnabled', value: 'false' },
            { key: 'extensionAnnouncerSeverity', value: 'normal' },
            { key: 'extensionAnnouncerMessage', value: '' },
            { key: 'featureExtensionWebhooksEnabled', value: 'false' },
            { key: 'featureExtensionIncidentsEnabled', value: 'false' },
            { key: 'featureExtensionMaintenanceEnabled', value: 'false' },
            { key: 'featureExtensionSecurityCenterEnabled', value: 'false' },
            { key: 'extensionWebhooksConfig', value: '{"enabled":false,"discordWebhook":"","telegramBotToken":"","telegramChatId":"","events":{"incidentCreated":true,"incidentResolved":true,"maintenanceScheduled":true,"maintenanceCompleted":true,"securityAlertCreated":true,"securityAlertResolved":true,"serverStarted":true,"serverStopped":true,"serverCrashed":true,"serverInstallFailed":true,"connectorError":true,"commandFailed":true,"runtimeIncidentCreated":true}}' },
            { key: 'extensionIncidentsRecords', value: '[]' },
            { key: 'extensionMaintenanceRecords', value: '[]' },
            { key: 'extensionSecurityAlertsRecords', value: '[]' },
            { key: 'serviceHealthChecksHistory', value: '[]' },
            { key: 'incidentCenterRecords', value: '[]' },
            { key: 'economyUnit', value: 'Coins' },
            { key: 'costCurrency', value: 'Coins' },
            { key: 'afkTimerCoins', value: '2' },
            { key: 'afkTimerCooldownSeconds', value: '60' },
            { key: 'afkRewardActivePeriod', value: 'minute' },
            { key: 'afkRewardMinuteCoins', value: '2' },
            { key: 'afkRewardHourCoins', value: '20' },
            { key: 'afkRewardDayCoins', value: '120' },
            { key: 'afkRewardWeekCoins', value: '700' },
            { key: 'afkRewardMonthCoins', value: '3000' },
            { key: 'afkRewardYearCoins', value: '36000' },
            { key: 'claimDailyStreakBonusCoins', value: '5' },
            { key: 'claimDailyStreakMax', value: '30' },
            { key: 'costBasePerServerMonthly', value: '0' },
            { key: 'costPerGbRamMonthly', value: '1.5' },
            { key: 'costPerCpuCoreMonthly', value: '2.5' },
            { key: 'costPerGbDiskMonthly', value: '0.2' },
            { key: 'storeRamPerGbCoins', value: '10' },
            { key: 'storeCpuPerCoreCoins', value: '20' },
            { key: 'storeSwapPerGbCoins', value: '3' },
            { key: 'storeDiskPerGbCoins', value: '2' },
            { key: 'storeAllocationCoins', value: '5' },
            { key: 'storeImageCoins', value: '15' },
            { key: 'storePackageCoins', value: '25' },
            { key: 'storeDatabaseCoins', value: '5' },
            { key: 'storeRenewDays', value: '30' },
            { key: 'storeDeleteGraceDays', value: '7' },
            { key: 'storeDealsCatalog', value: '[]' },
            { key: 'storeRedeemCodesCatalog', value: '[]' },
            { key: 'revenuePlanCatalog', value: '[]' },
            { key: 'autoRemediationCooldownSeconds', value: '300' },
            { key: 'antiMinerSuspendScore', value: '10' },
            { key: 'antiMinerHighCpuPercent', value: '95' },
            { key: 'antiMinerHighCpuSamples', value: '8' },
            { key: 'antiMinerDecayMinutes', value: '20' },
            { key: 'antiMinerCooldownSeconds', value: '600' },
            { key: 'featureRemoteDownloadEnabled', value: 'true' },
            { key: 'crashDetectionEnabled', value: 'true' },
            { key: 'crashDetectCleanExitAsCrash', value: 'true' },
            { key: 'crashDetectionCooldownSeconds', value: '60' },
            { key: 'connectorConsoleThrottleEnabled', value: 'true' },
            { key: 'connectorConsoleThrottleLines', value: '2000' },
            { key: 'connectorConsoleThrottleIntervalMs', value: '100' },
            { key: 'connectorDiskCheckTtlSeconds', value: '10' },
            { key: 'connectorTransferDownloadLimit', value: '0' },
            { key: 'connectorSftpReadOnly', value: 'false' },
            { key: 'connectorApiHost', value: '0.0.0.0' },
            { key: 'connectorApiSslEnabled', value: 'false' },
            { key: 'connectorApiSslCertPath', value: '' },
            { key: 'connectorApiSslKeyPath', value: '' },
            { key: 'connectorApiTrustedProxies', value: '' },
            { key: 'connectorRootlessEnabled', value: 'false' },
            { key: 'connectorRootlessContainerUid', value: '0' },
            { key: 'connectorRootlessContainerGid', value: '0' }
        ];

        for (const item of defaults) {
            const [setting, created] = await Settings.findOrCreate({
                where: { key: item.key },
                defaults: { value: item.value }
            });
            if (created) {
                console.log(`Created default setting: ${item.key} = ${item.value}`);
            } else {
                console.log(`Setting already exists: ${item.key}`);
            }
        }

        console.log('Database upgrade completed successfully.');
        await sequelize.close();
        process.exit(0);
    } catch (error) {
        if (sqliteForeignKeysDisabled) {
            try {
                await sequelize.query('PRAGMA foreign_keys = ON');
                console.log('SQLite foreign key checks re-enabled after error.');
            } catch (pragmaError) {
                console.error('Failed to re-enable SQLite foreign key checks:', pragmaError);
            }
        }
        console.error('Database upgrade failed:', error);
        try {
            await sequelize.close();
        } catch (closeError) {
            console.error('Failed to close Sequelize connection:', closeError);
        }
        process.exit(1);
    }
}

upgrade();
