function registerInternalApiRoutes(deps) {
    const {
        app,
        User,
        Server,
        bcrypt,
        jwt,
        secretKey,
        axios,
        connectorSecret,
        authenticateToken
    } = deps;

    app.post('/api/auth/login', async (req, res) => {
        const { username, password } = req.body;
        try {
            const user = await User.findOne({ where: { username } });
            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign({
                id: user.id,
                isAdmin: user.isAdmin,
                username: user.username
            }, secretKey, { expiresIn: '24h' });

            res.json({
                token,
                user: {
                    username: user.username,
                    email: user.email,
                    isAdmin: user.isAdmin,
                    firstName: user.firstName,
                    lastName: user.lastName
                }
            });
        } catch (error) {
            console.error('API login failed:', error);
            res.status(500).json({ error: 'Login failed' });
        }
    });

    app.get('/api/servers', authenticateToken, async (req, res) => {
        const servers = await Server.findAll();
        res.json(servers);
    });

    app.post('/api/servers', authenticateToken, async (req, res) => {
        if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin only' });

        const { name, image } = req.body;

        try {
            const response = await axios.post('http://localhost:3001/api/servers', {
                name: `${name}-${Date.now()}`,
                image: image || 'nginx:latest'
            }, {
                headers: { Authorization: `Bearer ${connectorSecret}` }
            });

            const { id: containerId } = response.data;

            const serverEntry = await Server.create({
                name,
                containerId,
                status: 'creating',
                dockerImage: image || 'nginx:latest'
            });

            res.json(serverEntry);
        } catch (error) {
            console.error('Failed to create server:', error.message);
            res.status(500).json({ error: 'Failed to create server on node' });
        }
    });
}

module.exports = { registerInternalApiRoutes };
