const svgCaptcha = require('svg-captcha');

function registerSystemRoutes(deps) {
    const {
        app,
        User,
        Settings,
        requireAuth,
        requireAdmin
    } = deps;

    app.post('/check', async (req, res) => {
        if (!req.session.user) {
            return res.json({ suspended: false, authenticated: false });
        }

        try {
            const user = await User.findByPk(req.session.user.id);
            if (user && user.isSuspended) {
                return res.json({ suspended: true, authenticated: true });
            }
            return res.json({ suspended: false, authenticated: true });
        } catch (error) {
            console.error('Error checking suspension:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    app.get('/suspend', async (req, res) => {
        if (!req.session.user) {
            return res.redirect('/login');
        }

        try {
            const user = await User.findByPk(req.session.user.id);
            if (!user || !user.isSuspended) {
                console.log(`[Suspend] Redirecting user ${req.session.user.id} to / (Not suspended or not found)`);
                return res.redirect('/');
            }
            res.render('suspended', { settings: res.locals.settings });
        } catch (error) {
            console.error('Error in /suspend:', error);
            res.redirect('/');
        }
    });

    app.get('/captcha', (req, res) => {
        const captcha = svgCaptcha.create({
            size: 6,
            noise: 3,
            color: true,
            background: '#1a1a20'
        });

        req.session.captcha = captcha.text.toLowerCase();
        res.type('svg');
        res.status(200).send(captcha.data);
    });

    app.get('/admin/captcha', requireAuth, requireAdmin, (req, res) => {
        res.render('admin/captcha', {
            user: req.session.user,
            path: '/admin/captcha',
            success: req.query.success || null,
            error: req.query.error || null,
            captchastatus: res.locals.settings.captchastatus === 'on'
        });
    });

    app.post('/admin/captcha', requireAuth, requireAdmin, async (req, res) => {
        const { captchastatus } = req.body;
        try {
            await Settings.upsert({ key: 'captchastatus', value: captchastatus === 'on' ? 'on' : 'off' });
            res.locals.settings.captchastatus = captchastatus === 'on' ? 'on' : 'off';
            res.redirect('/admin/captcha?success=Captcha settings updated successfully!');
        } catch (error) {
            console.error('Error updating captcha settings:', error);
            res.redirect('/admin/captcha?error=Failed to update captcha settings.');
        }
    });
}

module.exports = { registerSystemRoutes };
