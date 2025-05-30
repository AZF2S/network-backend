const express = require('express');
const { nodeBB} = require("../../third_party/nodebb");
const mongodb = require('../../third_party/mongodb');
const { validateSession, validateAdminSession }  = require('../../middleware/validateSession');
const validation = require('./user_validation');
require("express-session/session/cookie");
const router = express.Router();

const getUserHandler = async (req, res) => {
    try {
        // Validate user object in NodeBB, the source of truth
        const response = await nodeBB.api.get(`/api/user/uid/${req.query.uid}`,
            {
                headers: req.headers
            }
        );

        if (!response.data) {
            return res.status(404).json({ error: "NodeBB user not found" });
        }

        // Pull full user object from MongoDB, to acquire custom fields
        const mongoClient = await mongodb.getCollection(process.env.MONGO_NODEBB_COLLECTION);
        const user = await mongoClient.findOne({ _key: `user:${req.query.uid}` });

        if (!user || !user.email) {
            return res.status(500).json({ error: "MongoDB user not found" });
        }

        // Redundant precaution. It's encrypted anyhow.
        if (user.password) { user.password = null }

        res.status(200).json(user);
    } catch (error) {
        if (error.response) {
            console.error("NodeBB API error:", error.response.status, error.response.data);

            if (error.response.status === 404) {
                return res.status(404).json({ error: "User not found" });
            }
        }
        else {
            console.error("Error fetching user data:", error);
        }

        return res.status(500).json({ error: "Internal Server Error" });
    }
};

router.get("/", validateSession, getUserHandler);

router.get("/admin", validateSession, validateAdminSession, getUserHandler);

router.post('/sign-up', (async (req, res) => {
    try {
        const { isValid, errors } = validation.validateSignUp(req.body);
        if (!isValid) {
            return res.status(400).json({
                success: false,
                errors: errors
            });
        }

        const _uid = 1; // to use NodeBB master bearer token
        const { username, password, email } = req.body;

        let usernameAvailable = false, emailAvailable = false;

        const collection = await mongodb.getCollection(process.env.MONGO_NODEBB_COLLECTION);

        const existingUsername = await collection.findOne({ username: username });
        if (existingUsername === null || existingUsername === undefined) { usernameAvailable = true; }
        console.log(`Found username: ${existingUsername}`);

        const existingEmail = await collection.findOne({ email: email });
        if (existingEmail === null || existingEmail === undefined) { emailAvailable = true; }
        console.log(`Found email: ${existingEmail}`);

        if (!usernameAvailable || !emailAvailable) {
            return res.status(400).json({"status": "error", "errors": "User already exists"});
        }

        const response = await nodeBB.api.post(
        '/api/v3/users',
        { _uid, username, password, email },
            {
                headers: {Authorization: `Bearer ${process.env.NODEBB_BEARER_TOKEN}`},
        }
        );

        return res.status(response.status).json(response.data);

    } catch (error) {
        console.error("Signup error:", error);
    }
}));

router.get("/notifications", validateSession, (async (req, res) => {
    try {
        console.log(`Notifications ; ${JSON.stringify(req.headers)}`);
        const response = await nodeBB.api.get(
            `/api/notifications`,
            {
                headers: req.headers
            }
        );

        let chatNotificationCount = response.data.notifications?.filter(
            (notification) =>
                notification.type === "new-chat" && notification.read === false
        ).length;

        res.json({ chat_notifications_count: chatNotificationCount });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error retrieving notifications" });
    }
}));

router.post("/login", (async (req, res) => {
    try {
        const { username, password } = req.body;
        const nodeBBSession = await nodeBB.initializeNodeBBSession(username, password);

        if (!nodeBBSession.success) {
            return res.status(401).json({
                success: false,
                message: "Invalid username or password"
            });
        }

        // Only set the session cookie, exactly as received
        res.setHeader('Set-Cookie', nodeBBSession.sessionCookie);

        // Send CSRF token in response body instead of as a cookie
        const user = {
            uid: nodeBBSession.userData.uid,
            username: nodeBBSession.userData.username,
            validEmail: nodeBBSession.userData["email:confirmed"] === 1,
            csrfToken: nodeBBSession.csrfToken  // Frontend will store this and send as header
        };

        return res.json({
            success: true,
            user: user
        });
    } catch (error) {
        console.error("Authentication error:", error);
        res.status(500).json({ success: false, message: "Authentication failed" });
    }
}));

module.exports = router;