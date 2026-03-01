const { Sequelize, DataTypes } = require('sequelize');

const dbConnection = process.env.DB_CONNECTION || 'sqlite';

let sequelize;
if (dbConnection === 'sqlite') {
    sequelize = new Sequelize({
        dialect: 'sqlite',
        storage: './database.sqlite',
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
    packageId: { type: DataTypes.INTEGER, allowNull: true }
});

const Server = sequelize.define('Server', {
    name: { type: DataTypes.STRING, allowNull: false },
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
    description: { type: DataTypes.STRING(50), allowNull: true },
    token: { type: DataTypes.STRING(255), allowNull: true }
});

const Allocation = sequelize.define('Allocation', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    ip: { type: DataTypes.STRING, allowNull: false },
    port: { type: DataTypes.INTEGER, allowNull: false },
    alias: { type: DataTypes.STRING, allowNull: true },
    connectorId: { type: DataTypes.INTEGER, allowNull: false },
    serverId: { type: DataTypes.INTEGER, allowNull: true }
});

const Job = sequelize.define('Job', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    type: { type: DataTypes.STRING(100), allowNull: false },
    status: { type: DataTypes.STRING(32), allowNull: false, defaultValue: 'queued' }, // queued|running|retrying|completed|failed|cancelled
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
    status: { type: DataTypes.STRING(32), allowNull: false, defaultValue: 'completed' }, // completed|failed
    filePath: { type: DataTypes.STRING, allowNull: false },
    sizeBytes: { type: DataTypes.BIGINT, allowNull: true },
    checksum: { type: DataTypes.STRING(128), allowNull: true },
    metadata: { type: DataTypes.JSON, allowNull: true }
});

User.hasMany(LinkedAccount, { foreignKey: 'userId', as: 'linkedAccounts' });
LinkedAccount.belongsTo(User, { foreignKey: 'userId' });

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

Server.hasOne(ServerBackupPolicy, { foreignKey: 'serverId', as: 'backupPolicy' });
ServerBackupPolicy.belongsTo(Server, { foreignKey: 'serverId', as: 'server' });

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

sequelize.sync().then(() => {
    console.log(`Database synced (${dbConnection})`);
}).catch((err) => {
    console.error("Database sync failed:", err);
});

module.exports = {
    sequelize,
    dbConnection,
    User,
    LinkedAccount,
    Package,
    Image,
    Server,
    Settings,
    Location,
    DatabaseHost,
    ServerDatabase,
    Connector,
    Allocation,
    Job,
    AuditLog,
    ServerBackupPolicy,
    ServerBackup,
    ServerSubuser,
    ServerApiKey,
    AdminApiKey,
    AdminApiKeyAudit
};
