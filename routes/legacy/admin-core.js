function registerAdminCoreRoutes(ctx) {
    for (const [key, value] of Object.entries(ctx || {})) {
        try {
            globalThis[key] = value;
        } catch {
            // Ignore non-writable globals (e.g. crypto on newer Node versions).
        }
    }
// Admin Locations
app.get('/admin/locations', requireAuth, requireAdmin, async (req, res) => {
    try {
        const locations = await Location.findAll({
            include: [
                { model: DatabaseHost, as: 'databaseHosts' },
                { model: Connector, as: 'connectors' }
            ]
        });
        res.render('admin/locations', {
            user: req.session.user,
            locations,
            path: '/admin/locations',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Error fetching locations:", error);
        res.render('admin/locations', {
            user: req.session.user,
            locations: [],
            path: '/admin/locations',
            success: null,
            error: 'Failed to fetch locations.'
        });
    }
});

app.post('/admin/locations', requireAuth, requireAdmin, [
    body('shortName').trim().notEmpty().withMessage('Short Name is required'),
    body('description').trim().isLength({ max: 30 }).withMessage('Description must be 30 characters or less'),
    body('imageUrl').trim().optional({ checkFalsy: true }).isURL().withMessage('Invalid Image URL')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const locations = await Location.findAll();
        return res.render('admin/locations', {
            user: req.session.user,
            locations,
            path: '/admin/locations',
            success: null,
            error: errors.array()[0].msg
        });
    }

    const { shortName, description, imageUrl } = req.body;
    try {
        await Location.create({ shortName, description, imageUrl });
        res.redirect('/admin/locations?success=Location created successfully!');
    } catch (error) {
        console.error("Error creating location:", error);
        const locations = await Location.findAll({
            include: [
                { model: DatabaseHost, as: 'databaseHosts' },
                { model: Connector, as: 'connectors' }
            ]
        });
        res.render('admin/locations', {
            user: req.session.user,
            locations,
            path: '/admin/locations',
            success: null,
            error: error.name === 'SequelizeUniqueConstraintError' ? 'Short Name already exists' : 'Failed to create location.'
        });
    }
});

app.post('/admin/locations/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        // Check if location is used by any DatabaseHost
        const dbHostCount = await DatabaseHost.count({ where: { locationId: req.params.id } });
        if (dbHostCount > 0) {
            return res.redirect(`/admin/locations?error=Cannot delete location because it is currently used by ${dbHostCount} database host(s).`);
        }

        // Check if location is used by any Connector
        const connectorCount = await Connector.count({ where: { locationId: req.params.id } });
        if (connectorCount > 0) {
            return res.redirect(`/admin/locations?error=Cannot delete location because it is currently used by ${connectorCount} connector(s).`);
        }

        await Location.destroy({ where: { id: req.params.id } });
        res.redirect('/admin/locations?success=Location deleted successfully!');
    } catch (error) {
        console.error("Error deleting location:", error);
        res.redirect('/admin/locations?error=Failed to delete location.');
    }
});

// Admin Users
app.get('/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({
            include: [{ model: LinkedAccount, as: 'linkedAccounts' }]
        });
        res.render('admin/users', {
            user: req.session.user,
            users,
            md5, // Pass md5 for gravatar hashing in the view
            path: '/admin/users',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Error fetching users:", error);
        res.render('admin/users', {
            user: req.session.user,
            users: [],
            path: '/admin/users',
            success: null,
            error: 'Failed to fetch users.'
        });
    }
});

// Admin Force Unlink OAuth Account
app.post('/admin/users/:id/unlink/:provider', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id, provider } = req.params;
        const targetUser = await User.findByPk(id);
        if (!targetUser) return res.redirect('/admin/users?error=User not found.');

        await LinkedAccount.destroy({ where: { userId: id, provider } });

        // Clear legacy field if it matches
        if (targetUser.oauthProvider === provider) {
            await targetUser.update({ oauthProvider: null, oauthId: null });
        }

        res.redirect(`/admin/users?success=Successfully unlinked ${provider} from ${targetUser.username}.`);
    } catch (err) {
        console.error('Error in admin unlink:', err);
        res.redirect('/admin/users?error=Failed to unlink account.');
    }
});

app.post('/admin/users', requireAuth, requireAdmin, [
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('email').trim().isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const users = await User.findAll();
        return res.render('admin/users', {
            user: req.session.user,
            users,
            md5,
            path: '/admin/users',
            success: null,
            error: errors.array()[0].msg
        });
    }

    const { username, email, password, avatarUrl, avatarProvider, isAdmin } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({
            username,
            email,
            password: hashedPassword,
            firstName: username, // Default to username as requested form doesn't have these
            lastName: '',
            avatarUrl: avatarUrl || null,
            avatarProvider: avatarProvider || 'gravatar',
            isAdmin: isAdmin === 'on' || isAdmin === true,
            isSuspended: false // Default to active
        });
        res.redirect('/admin/users?success=User created successfully!');
    } catch (error) {
        console.error("Error creating user:", error);
        const users = await User.findAll();
        res.render('admin/users', {
            user: req.session.user,
            users,
            md5,
            path: '/admin/users',
            success: null,
            error: 'Failed to create user. Username or email might already exist.'
        });
    }
});

app.post('/admin/users/edit/:id', requireAuth, requireAdmin, [
    body('email').trim().isEmail().withMessage('Valid email is required'),
    body('password').optional({ checkFalsy: true }).isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
    const { id } = req.params;
    const { email, username, avatarUrl, avatarProvider, isAdmin, password } = req.body;

    try {
        const updateData = {
            email,
            username,
            avatarUrl: avatarUrl || null,
            avatarProvider: avatarProvider || 'gravatar',
            isAdmin: isAdmin === 'on' || isAdmin === true || isAdmin === 'true',
            isSuspended: req.body.isSuspended === 'on' || req.body.isSuspended === true || req.body.isSuspended === 'true'
        };

        // Prevent self-suspension
        if (parseInt(id) === req.session.user.id && updateData.isSuspended) {
            // If trying to suspend self, force it to false
            updateData.isSuspended = false;
        }

        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        await User.update(updateData, { where: { id } });
        res.redirect('/admin/users?success=User updated successfully!');
    } catch (error) {
        console.error("Error updating user:", error);
        res.redirect(`/admin/users?error=Failed to update user.`);
    }
});

app.post('/admin/users/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    const { id } = req.params;

    // Prevent self-deletion
    if (parseInt(id) === req.session.user.id) {
        return res.redirect('/admin/users?error=You cannot delete your own account!');
    }

    try {
        await LinkedAccount.destroy({ where: { userId: id } });
        await User.destroy({ where: { id } });
        res.redirect('/admin/users?success=User deleted successfully!');
    } catch (error) {
        console.error("Error deleting user:", error);
        res.redirect('/admin/users?error=Failed to delete user.');
    }
});

app.post('/admin/locations/edit/:id', requireAuth, requireAdmin, [
    body('shortName').trim().notEmpty().withMessage('Short Name is required'),
    body('description').trim().isLength({ max: 30 }).withMessage('Description must be 30 characters or less'),
    body('imageUrl').trim().optional({ checkFalsy: true }).isURL().withMessage('Invalid Image URL')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(`/admin/locations?error=${encodeURIComponent(errors.array()[0].msg)}`);
    }

    const { shortName, description, imageUrl } = req.body;
    try {
        await Location.update({ shortName, description, imageUrl }, { where: { id: req.params.id } });
        res.redirect('/admin/locations?success=Location updated successfully!');
    } catch (error) {
        console.error("Error updating location:", error);
        res.redirect('/admin/locations?error=Failed to update location.');
    }
});

// Admin Packages (List)
app.get('/admin/packages', requireAuth, requireAdmin, async (req, res) => {
    try {
        const packages = await Package.findAll({
            include: [{ model: Image, as: 'images' }],
            order: [['name', 'ASC']]
        });
        res.render('admin/packages', {
            user: req.session.user,
            packages,
            path: '/admin/packages',
            title: 'Packages',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading packages admin page:', error);
        res.redirect('/admin/overview?error=Failed to load packages.');
    }
});

// Admin Packages (Create)
app.post('/admin/packages', requireAuth, requireAdmin, async (req, res) => {
    const { name, description, imageUrl, redirect } = req.body;
    const redirectPath = redirect || '/admin/packages';
    try {
        if (!name) return res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'error=Package name is required.');
        if (description && description.length > 150) {
            return res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'error=Description must be at most 150 characters.');
        }

        await Package.create({ name, description, imageUrl });
        res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'success=Package created successfully!');
    } catch (error) {
        console.error('Error creating package:', error);
        res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'error=Failed to create package.');
    }
});

// Admin Packages (Edit)
app.post('/admin/packages/edit/:id', requireAuth, requireAdmin, async (req, res) => {
    const { name, description, imageUrl } = req.body;
    try {
        const pkg = await Package.findByPk(req.params.id);
        if (!pkg) return res.redirect('/admin/packages?error=Package not found.');

        if (!name) return res.redirect('/admin/packages?error=Package name is required.');
        if (description && description.length > 150) {
            return res.redirect('/admin/packages?error=Description must be at most 150 characters.');
        }

        await pkg.update({ name, description, imageUrl });
        res.redirect('/admin/packages?success=Package updated successfully!');
    } catch (error) {
        console.error('Error updating package:', error);
        res.redirect('/admin/packages?error=Failed to update package.');
    }
});

// Admin Packages (Delete)
app.get('/admin/packages/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const pkg = await Package.findByPk(req.params.id, {
            include: [{ model: Image, as: 'images' }]
        });
        if (!pkg) return res.redirect('/admin/packages?error=Package not found.');

        if (pkg.images && pkg.images.length > 0) {
            return res.redirect('/admin/packages?error=Cannot delete package with assigned images.');
        }

        await pkg.destroy();
        res.redirect('/admin/packages?success=Package deleted successfully!');
    } catch (error) {
        console.error('Error deleting package:', error);
        res.redirect('/admin/packages?error=Failed to delete package.');
    }
});

// API: Get Packages JSON (For modals)
app.get('/api/admin/packages', requireAuth, requireAdmin, async (req, res) => {
    try {
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.json(packages);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch packages' });
    }
});

// Admin Images
app.get('/admin/images', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { packageId } = req.query;
        const where = {};
        if (packageId) where.packageId = packageId;

        const images = await Image.findAll({
            where,
            include: [{ model: Package, as: 'package' }],
            order: [['name', 'ASC']]
        });
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.render('admin/images', {
            user: req.session.user,
            images,
            packages,
            path: '/admin/images',
            title: 'Images',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading images admin page:', error);
        res.render('admin/images', {
            user: req.session.user,
            images: [],
            packages: [],
            path: '/admin/images',
            title: 'Images',
            success: null,
            error: 'Failed to load images.'
        });
    }
});

app.post('/admin/images/import', requireAuth, requireAdmin, async (req, res) => {
    try {
        const jsonPayload = (req.body.jsonPayload || '').trim();
        const packageId = req.body.packageId;

        if (!packageId) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('You must select a package for the imported image.'));
        }

        if (!jsonPayload) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('Please upload or paste a JSON file first.'));
        }

        let parsedJson;
        try {
            parsedJson = JSON.parse(jsonPayload);
        } catch (error) {
            return res.redirect('/admin/images?error=' + encodeURIComponent('Invalid JSON format.'));
        }

        if (Array.isArray(parsedJson)) {
            if (parsedJson.length !== 1 || !parsedJson[0] || typeof parsedJson[0] !== 'object') {
                return res.redirect('/admin/images?error=' + encodeURIComponent('JSON array imports must contain exactly one image object.'));
            }
            parsedJson = parsedJson[0];
        }

        const normalized = parseImportedImageJson(parsedJson);
        normalized.packageId = packageId; // Assign the selected package

        const [image, created] = await Image.findOrCreate({
            where: { name: normalized.name },
            defaults: normalized
        });

        if (!created) {
            await image.update(normalized);
        }

        const message = created
            ? `Image "${normalized.name}" imported successfully.`
            : `Image "${normalized.name}" updated successfully from JSON import.`;
        res.redirect('/admin/images?success=' + encodeURIComponent(message));
    } catch (error) {
        console.error('Failed to import image JSON:', error);
        res.redirect('/admin/images?error=' + encodeURIComponent(error.message || 'Image import failed.'));
    }
});

// Admin Images (Edit - GET)
app.get('/admin/images/edit/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.render('admin/edit-image', {
            user: req.session.user,
            image,
            packages,
            path: '/admin/images',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading edit image page:', error);
        res.redirect('/admin/images?error=Failed to load image.');
    }
});

// Admin Images (Edit - POST)
app.post('/admin/images/edit/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { name, description, dockerImage, startup, environment, dockerImages, packageId } = req.body;

        let envParsed = {};
        try {
            envParsed = JSON.parse(environment);
        } catch (e) {
            return res.redirect(`/admin/images/edit/${req.params.id}?error=Invalid JSON for Environment Variables`);
        }

        let imagesParsed = {};
        try {
            imagesParsed = JSON.parse(dockerImages);
        } catch (e) {
            return res.redirect(`/admin/images/edit/${req.params.id}?error=Invalid JSON for Docker Images`);
        }

        await Image.update({
            name,
            description,
            dockerImage,
            startup,
            environment: envParsed,
            dockerImages: imagesParsed,
            packageId: packageId || null
        }, { where: { id: req.params.id } });

        res.redirect(`/admin/images/edit/${req.params.id}?success=Image updated successfully!`);
    } catch (error) {
        console.error('Error updating image:', error);
        res.redirect(`/admin/images/edit/${req.params.id}?error=Failed to update image.`);
    }
});

// Admin Images (Delete - POST)
app.post('/admin/images/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const usageCount = await Server.count({ where: { imageId: req.params.id } });
        if (usageCount > 0) {
            return res.redirect(`/admin/images?error=Cannot delete image because it is used by ${usageCount} server(s).`);
        }

        await Image.destroy({ where: { id: req.params.id } });
        res.redirect('/admin/images?success=Image deleted successfully!');
    } catch (error) {
        console.error('Error deleting image:', error);
        res.redirect('/admin/images?error=Failed to delete image.');
    }
});

// Admin Images (Export JSON)
app.get('/admin/images/export/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }

        const exportData = image.toJSON();
        res.setHeader('Content-disposition', `attachment; filename=${image.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`);
        res.setHeader('Content-type', 'application/json');
        res.send(JSON.stringify(exportData, null, 2));
    } catch (error) {
        console.error('Error exporting image:', error);
        res.redirect('/admin/images?error=Failed to export image.');
    }
});

// Admin Images (Edit JSON - GET)
app.get('/admin/images/edit-json/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }
        const packages = await Package.findAll({ order: [['name', 'ASC']] });
        res.render('admin/edit-image-json', {
            user: req.session.user,
            image,
            packages,
            path: '/admin/images',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error('Error loading edit image json page:', error);
        res.redirect('/admin/images?error=Failed to load image.');
    }
});

// Admin Images (Edit JSON - POST)
app.post('/admin/images/edit-json/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { jsonPayload, packageId } = req.body;
        let parsed;
        try {
            parsed = JSON.parse(jsonPayload);
        } catch (e) {
            return res.redirect(`/admin/images/edit-json/${req.params.id}?error=Invalid JSON format.`);
        }

        if (Array.isArray(parsed)) {
            if (parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== 'object') {
                return res.redirect(`/admin/images/edit-json/${req.params.id}?error=JSON array payload must contain exactly one image object.`);
            }
            parsed = parsed[0];
        }

        const image = await Image.findByPk(req.params.id);
        if (!image) {
            return res.redirect('/admin/images?error=Image not found.');
        }

        const normalized = parseImportedImageJson(parsed);
        normalized.configPath = image.configPath || normalized.configPath;
        normalized.packageId = packageId || image.packageId;
        await image.update(normalized);
        res.redirect(`/admin/images/edit-json/${req.params.id}?success=Image JSON updated successfully!`);
    } catch (error) {
        console.error('Error updating image via JSON:', error);
        res.redirect(`/admin/images/edit-json/${req.params.id}?error=${encodeURIComponent(error.message || 'Failed to update image.')}`);
    }
});

// Admin Databases
app.get('/admin/databases', requireAuth, requireAdmin, async (req, res) => {
    try {
        const hosts = await DatabaseHost.findAll({
            include: [{ model: Location, as: 'location' }]
        });
        const locations = await Location.findAll();
        res.render('admin/databases', {
            user: req.session.user,
            hosts,
            locations,
            path: '/admin/databases',
            success: req.query.success || null,
            error: req.query.error || null
        });
    } catch (error) {
        console.error("Error fetching database hosts:", error);
        res.render('admin/databases', {
            user: req.session.user,
            hosts: [],
            path: '/admin/databases',
            success: null,
            error: 'Failed to fetch database hosts.'
        });
    }
});

app.post('/admin/databases', requireAuth, requireAdmin, [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('host').trim().notEmpty().withMessage('Host is required'),
    body('port').isInt().withMessage('Port must be a number'),
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').trim().notEmpty().withMessage('Password is required'),
    body('database').trim().notEmpty().withMessage('Database name is required'),
    body('locationId').isInt().withMessage('Location is required'),
    body('type').isIn(['mysql', 'postgres', 'mariadb']).withMessage('Invalid database type')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const hosts = await DatabaseHost.findAll({ include: [{ model: Location, as: 'location' }] });
        const locations = await Location.findAll();
        return res.render('admin/databases', {
            user: req.session.user,
            hosts,
            locations,
            path: '/admin/databases',
            success: null,
            error: errors.array()[0].msg
        });
    }

    const { name, host, port, username, password, database, locationId, type } = req.body;
    try {
        await DatabaseHost.create({ name, host, port, username, password, database, locationId, type });
        res.redirect('/admin/databases?success=Database host created successfully!');
    } catch (error) {
        console.error("Error creating database host:", error);
        const hosts = await DatabaseHost.findAll({ include: [{ model: Location, as: 'location' }] });
        const locations = await Location.findAll();
        res.render('admin/databases', {
            user: req.session.user,
            hosts,
            locations,
            path: '/admin/databases',
            success: null,
            error: 'Failed to create database host.'
        });
    }
});

app.post('/admin/databases/delete/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        await DatabaseHost.destroy({ where: { id: req.params.id } });
        res.redirect('/admin/databases?success=Database host deleted successfully!');
    } catch (error) {
        console.error("Error deleting database host:", error);
        res.redirect('/admin/databases?error=Failed to delete database host.');
    }
});

app.post('/admin/databases/edit/:id', requireAuth, requireAdmin, [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('host').trim().notEmpty().withMessage('Host is required'),
    body('port').isInt().withMessage('Port must be a number'),
    body('username').trim().notEmpty().withMessage('Username is required'),
    body('password').trim().notEmpty().withMessage('Password is required'),
    body('database').trim().notEmpty().withMessage('Database name is required'),
    body('locationId').isInt().withMessage('Location is required'),
    body('type').isIn(['mysql', 'postgres', 'mariadb']).withMessage('Invalid database type')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.redirect(`/admin/databases?error=${encodeURIComponent(errors.array()[0].msg)}`);
    }

    const { name, host, port, username, password, database, locationId, type } = req.body;
    try {
        await DatabaseHost.update({ name, host, port, username, password, database, locationId, type }, { where: { id: req.params.id } });
        res.redirect('/admin/databases?success=Database host updated successfully!');
    } catch (error) {
        console.error("Error updating database host:", error);
        res.redirect('/admin/databases?error=Failed to update database host.');
    }
});

app.post('/admin/databases/ping/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const host = await DatabaseHost.findByPk(req.params.id);
        if (!host) {
            return res.status(404).json({ success: false, error: 'Database host not found' });
        }

        // Create a temporary sequelize instance to test connection
        const testSequelize = new Sequelize(
            host.database || (host.type === 'mysql' ? 'mysql' : 'postgres'),
            host.username,
            host.password,
            {
                host: host.host,
                port: host.port,
                dialect: host.type === 'postgres' ? 'postgres' : 'mysql',
                logging: false,
                dialectOptions: {
                    connectTimeout: 5000 // 5 seconds timeout
                }
            }
        );

        try {
            await testSequelize.authenticate();
            await testSequelize.close();
            return res.json({ success: true });
        } catch (err) {
            console.error("Ping failed:", err);
            return res.json({ success: false, error: err.message });
        }
    } catch (error) {
        console.error("Error in ping route:", error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

}

module.exports = { registerAdminCoreRoutes };
