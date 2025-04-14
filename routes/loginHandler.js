// ===== Import imperative libraries =====
let express = require('express');
let bcrypt = require('bcryptjs');
let User = require('../models/User');
let { validationResult } = require('express-validator');
let { loginLimiter, loginValidators } = require('../middleware/loginLimiter');
let { logUserActivity, logAuthenticationActivity, logErrorActivity } = require('../utils/Logger');

// Initiate the router
let router = express.Router();

// POST route to handle user login
router.post(
    '/loginHandler',
    loginLimiter,
    loginValidators[0],
    loginValidators[1],
    async (req, res) => {
        let errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Log activity
            logErrorActivity('Login attempt body:', req.body);
            // Redirect the user
            return res.status(400).render('indexLogin.njk', {
                error: 'Invalid login credentials.'
            });
        }
        // Retrieve the request body
        let { employeeId, password } = req.body;
        // Get the user from mongo
        let user = await User.findOne({ employeeId });
        // Log the user activity
        logUserActivity("User makes a login attempt", employeeId || 'Unknown', { page: "Login page", method: "POST" });

        // Render an exception if the user details are incorrect
        if (!user) {
            // Log the activity
            logErrorActivity("Invalid login credentials.", employeeId || 'Unknown');
            // Redirect the user
            return res.status(401).render('indexLogin.njk', {
                error: 'Invalid credentials.'
            });
        }

        // Compared stored password against the inputted password
        let isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            // Log activity
            logErrorActivity("Invalid credentials.", employeeId || 'Unknown');
            // Redirect the user
            return res.status(401).render('indexLogin.njk', {
                error: 'Invalid credentials.',
                employeeId
            });
        }

        // Set the user up for their session until the user logs out or ends their session. By default, after 30 minutes, the session will die.
        req.session.user = {
            id: user._id,
            name: user.fullName,
            role: user.role,
            employeeId: user.employeeId,
            isAuthenticated: false,
        };
        // Log the authentication events
        logAuthenticationActivity("User Password is correct!", req.session.user.employeeId || 'Unknown');

        // If the user is signing in for the first time, ensure that they change their password
        if (user.mustChangePassword) {
            req.session.tempUser = user._id;
            req.session.tempMfaUser = user._id;
            // Log activities
            logAuthenticationActivity("User has to change their password after first login!", req.session.user.employeeId || 'Unknown');
            logUserActivity("First time login password Change", req.session.user.employeeId || 'Unknown', { page: "Change Password", method: "POST" });
            // Redirect the user
            return res.redirect('/change-password');
        }

        // If the user doesn't have a stored mfaSecret, then the user has not setup mfa on their device. Route them to the setup page
        if(!user.mfaSecret && !user.mfaEnabled){
            req.session.tempUser = user._id;
            req.session.tempMfaUser = user._id;
            // Log activities
            logAuthenticationActivity("User has to setup their mfa!", req.session.user.employeeId || 'Unknown');
            logUserActivity("First time MFA secret", req.session.user.employeeId || 'Unknown', { page: "VerifyMfa", method: "POST" });
            // Redirect the user
            return res.redirect('/setup-mfa');
        }

        // route the user to verify their MFA
        if(user.mfaSecret && user.mfaEnabled){
            req.session.tempUser = user._id;
            req.session.tempMfaUser = user._id;
            // Log activities
            logAuthenticationActivity("User has to verify their mfa!", req.session.user.employeeId || 'Unknown');
            logUserActivity("Verify Mfa", req.session.user.employeeId || 'Unknown', { page: "VerifyMfa", method: "POST" });
            // Redirect the user
            return res.redirect('/verify-mfa');
        }
    }
);

module.exports = router;