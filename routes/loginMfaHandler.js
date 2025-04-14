/*
Handles pages and logic related to setting up and verifying MFA.
*/
let express = require("express");
let User = require("../models/User");
let { mfaAuthLimiter, verifyToken } = require("../middleware/MfaLimiter");
let { logErrorActivity, logAuthenticationActivity, logDBActivity} = require("../utils/Logger");

// Initiate the router
let router = express.Router();

/**
 * GET: Show MFA code verification form during login (NOT setup)
 * */
router.get("/verify-mfa", (req, res) => {
    if (!req.session.tempMfaUser) {
        // Log activity
        logErrorActivity("Unauthorized access to MFA verification", req.session.user.employeeId || 'Unknown');
        return res.status(403).render('403.njk', {error: "Unauthorized access to MFA verification"});
    }
    let flashMessage = req.session.flashMessage;
    delete req.session.flashMessage;

    // Log activity
    logAuthenticationActivity("User is requesting to verify their mfa", req.session.user.employeeId || 'Unknown');
    return res.render("loginVerifyMfa.njk", {
        flashMessage: flashMessage
    });
});

/**
 * POST: Verify MFA during login
 */
router.post("/verify-mfa", mfaAuthLimiter, async (req, res) => {
    // Extract the token from the request body
    let { token } = req.body;
    // Get the mongo document id of the user (user id)
    let userId = req.session.tempMfaUser;

    // Check if the user is an  actual user
    if (!userId) {
        // Log activity
        logErrorActivity("Unauthorized access", req.session.user.employeeId || 'Unknown');
        return res.status(403).render('403.njk', {error: "Unauthorized access"});
    }

    // Extract the user from the database and ensure that they are valid users in the database
    let user = await User.findById(userId);
    logDBActivity("User successfully read from the database", user.employeeId);
    if (!user || !user.mfaSecret) {
        // Log activity
        logErrorActivity("User or MFA secret not found");
        return res.status(403).render('403.njk', {error: "User or MFA secret not found"});
    }

    // Determine the validity of the inputted token
    let verified = verifyToken(user.mfaSecret, token);
    // Log activity
    logAuthenticationActivity("User has successfully verified their mfa", req.session.user.employeeId || 'Unknown');
    console.log(`\n${req.session.user.employeeId} verified: ` + verified);

    // If the user is validated, we route them over to their respective portal
    if (verified) {
        req.session.user.isAuthenticated = true;
        delete req.session.tempMfaUser;
        return res.redirect(`/portal/${user.role}`);
    } else {
        // Log activity
        logErrorActivity("Invalid MFA token");
        return res.status(401).render("loginVerifyMfa.njk", {
            error: "❌ Invalid MFA token. Please try again."
        });
    }
});

module.exports = router;