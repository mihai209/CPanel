function createSessionAuthGuards({ User }) {
    function requireAuth(req, res, next) {
        if (!req.session.user) {
            return res.redirect('/login');
        }

        User.findByPk(req.session.user.id).then((user) => {
            if (user && user.isSuspended) {
                console.log(`[Auth] User ${user.id} is suspended, redirecting to /suspend`);
                return res.redirect('/suspend');
            }
            if (user) {
                req.session.user.coins = Number.isFinite(Number(user.coins)) ? Number(user.coins) : 0;
            }
            next();
        }).catch((error) => {
            console.error('Error checking suspension in requireAuth:', error);
            next();
        });
    }

    function requireAdmin(req, res, next) {
        if (!req.session.user || !req.session.user.isAdmin) {
            return res.status(403).send('Access denied - Admin only');
        }
        next();
    }

    return {
        requireAuth,
        requireAdmin
    };
}

function createTokenAuthenticator({ jwt, secretKey }) {
    return function authenticateToken(req, res, next) {
        const token = req.headers.authorization;
        if (!token) return res.status(401).send();

        const tokenValue = token.split(' ')[1];
        jwt.verify(tokenValue, secretKey, (error, user) => {
            if (error) return res.status(403).send();
            req.user = user;
            next();
        });
    };
}

module.exports = {
    createSessionAuthGuards,
    createTokenAuthenticator
};
