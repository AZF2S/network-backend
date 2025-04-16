const { nodeBB } = require('../third_party/nodebb');

/**
 * Session validation middleware
 * Ensures user session and CSRF token are present
 */
const validateSession = async (req, res, next) => {
    if (!req.headers['x-csrf-token']) {
        return res.status(401).json({
            success: false,
            message: "No CSRF token provided."
        });
    }

    // Don't try to parse/reconstruct the cookie - just check it exists
    if (!req.headers.cookie || !req.headers.cookie.includes('express.sid')) {
        return res.status(401).json({
            success: false,
            message: "No session found."
        });
    }

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
            headers: req.headers
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