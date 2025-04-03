/*
* Import libraries
*/
let express = require('express');
let bcrypt = require('bcryptjs');
let User = require('../models/User');
let { check, validationResult } = require('express-validator');
let { logUserActivity, logErrorActivity, logDBActivity } = require('../utils/Logger');

// Initiate the router
let router = express.Router();

// ===== GET: Render the password change page =====
router.get('/change-password', (req, res) => {
    // Redirect if there's no temporary session (unauthorized access)
    if (!req.session.tempUser) {
        return res.redirect('/');
    }

    // Log user activity
    logUserActivity(
        "Accessed change password page",
        req.session.userId || 'Unknown',
        { page: 'Change Password', method: 'GET' }
    );
    // Render change password form
    res.render('changePassword.njk');
});

// ===== POST: Handle password update logic =====
router.post(
    '/change-password',
    [
        // Validation rules for the new password
        check('newPassword')
            .isLength({ min: 10, max: 20 })
            .matches(/[a-z]/)      // Must contain lowercase
            .matches(/[A-Z]/)      // Must contain uppercase
            .matches(/[0-9]/)      // Must contain digit
            .matches(/[^a-zA-Z0-9]/) // Must contain special character
            .withMessage('Password must contain uppercase, lowercase, number, and special character'),

        // Confirm password must match new password
        check('confirmPassword').custom((value, { req }) => {
            if (value !== req.body.newPassword) {
                throw new Error('Passwords do not match');
            }
            return true;
        })
    ],
    async (req, res) => {
        let errors = validationResult(req);
        if (!errors.isEmpty()) {
            // Log activity
            logErrorActivity(errors.toString(), req.session.user.employeeId || 'Unknown');
            return res.status(400).render('changePassword.njk', { errors: errors.array() });
        }

        // If the request is delivered safely, we make get the user from the database and initiate the password change flow
        let userId = req.session.tempUser;
        let user = await User.findById(userId);
        let { newPassword } = req.body;

        // Log activity
        logDBActivity("Retrieve user for password change", userId);

        try {
            // If the user is not available
            if (!user) {
                logErrorActivity("User not found", req.session.user.employeeId || 'Unknown');
                return res.status(404).render('changePassword.njk', { error: "User not found" });
            }

            // Check if new password was used before (compare hashes)
            let isReused = false;
            for (let oldHash of user.passwordHistory || []) {
                if (await bcrypt.compare(newPassword, oldHash)) {
                    isReused = true;
                    break;
                }
            }
            // Throw a no reusability error
            if (isReused) {
                logErrorActivity('❌ You cannot reuse your last 5 passwords.', req.session.user.employeeId || 'Unknown');
                return res.status(400).render('changePassword.njk', {
                    errors: [{ msg: '❌ You cannot reuse your last 5 passwords.' }]
                });
            }

            // Hash and update password
            let newPasswordHash = await bcrypt.hash(newPassword, 14);
            let updatedHistory = [...(user.passwordHistory || []), newPasswordHash].slice(-5);

            // Update the user's password to the new hash
            user.passwordHash = newPasswordHash;
            user.passwordHistory = updatedHistory;
            user.mustChangePassword = false;

            // Save the new password
            await user.save();

            // Log user and DB activity
            logUserActivity("Inputted new password", req.session.user.employeeId || 'Unknown', {
                page: 'Change Password', method: 'POST'
            });
            logDBActivity("Update Password", req.session.user.employeeId || 'Unknown', {
                Details: "User updated their password"
            });

            // Finalize session
            req.session.user = {
                id: user._id,
                name: user.fullName,
                role: user.role,
                employeeId: user.employeeId
            };
            delete req.session.tempUser;

            // Redirect to the user's mfa verification step
            if (!user.mfaSecret) {
                return res.redirect('/setup-mfa');
            }
            return res.redirect(`/portal/${user.role}`);
        } catch (err) {
            // Log activity
            logErrorActivity(err, req.session.user.employeeId || 'Unknown');
            // Redirect the user
            return res.status(500).render('500.njk', {
                error: "Internal Server Error. Please try again later."
            });
        }
    }
);

module.exports = router;