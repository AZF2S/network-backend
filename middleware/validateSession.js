const { nodeBB } = require('../third_party/nodebb');

/**
 * Session validation middleware
 * Ensures user session and CSRF token are present
 */
const validateSession = async (req, res, next) => {
    // Parse cookies from header
    let sessionCookieValue;
    let csrfTokenValue;
    let uidValue;

    if (req.headers.cookie) {
        const cookieString = req.headers.cookie;
        const cookies = cookieString.split(';').reduce((cookiesObj, cookie) => {
            const parts = cookie.trim().split('=');
            const name = parts[0];
            cookiesObj[name] = parts.slice(1).join('=');
            return cookiesObj;
        }, {});

        sessionCookieValue = cookies['express.sid'];
        csrfTokenValue = cookies['XSRF-TOKEN'];
        uidValue = cookies['User-Id'];
    }

    if (!sessionCookieValue) {
        return res.status(401).json({
            success: false,
            message: "No session found."
        });
    }

    if (!csrfTokenValue) {
        return res.status(401).json({
            success: false,
            message: "Could not authenticate session."
        });
    }

    if (!uidValue) {
        return res.status(401).json({
            success: false,
            message: "Could not identify session."
        })
    }

    req.nodeBBHeaders = {
        'Cookie': `express.sid=${sessionCookieValue}`,
        'X-CSRF-Token': csrfTokenValue
    };

    req.uid = uidValue;

    next();
};

/**
 * Admin session validation middleware
 * Ensures user is authenticated and has admin privileges
 */
// todo: fix this. probably need to hit get user for username
const validateAdminSession = async (req, res, next) => {
    try {
        // Validate session to get credentials for admin query
        await new Promise((resolve, reject) => {
            validateSession(req, res, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });

        // Admin query
        const response = await nodeBB.api.get('/api/admin/manage/admins-mods', {
            headers: req.nodeBBHeaders
        });

        const adminData = response.data;

        // Parse admins
        const isAdmin = adminData.admins.members.some(
            (admin) => admin.username === adminData.user.username
        );

        if (isAdmin) {
            next();
        } else {
            res.status(403).json({
                success: false,
                error: "Could not certify administrator."
            });
        }
    } catch (error) {
        console.error('Admin session validation error:', error.message);

        if (error.response) {
            return res.status(error.response.status).json({
                success: false,
                error: "Error validating admin session.",
                details: error.response.data
            });
        } else if (error.request) {
            return res.status(504).json({
                success: false,
                error: "Server timeout while validating admin session."
            });
        } else {
            return res.status(500).json({
                success: false,
                error: "Internal error while validating admin session.",
            });
        }
    }
};

module.exports = {
    validateSession,
    validateAdminSession
};