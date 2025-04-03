/*
Handles pages and logic related to setting up and verifying MFA.
*/
let qrcode = require("qrcode");
let express = require("express");
let speakeasy = require("speakeasy");
let User = require("../models/User");
let rateLimiter = require("express-rate-limit");
let { logErrorActivity, logAuthenticationActivity, logUserActivity, logDBActivity} = require("../utils/Logger");

// Initiate the router
let router = express.Router();

/**
 * Helper function to verify a TOTP token.
 */
function verifyToken(secret, token) {
    return speakeasy.totp.verify({
        secret,
        encoding: "base32",
        token,
        // My device clock and my server's clock may be out of sync. This window attribute '1' allows the device app to check 30 seconds prior and after the code was generated.
        window: 1
    });
}

// Set a limit on how many tokens can be submitted
let mfaAuthLimiter = rateLimiter({
    windowMs: 60 * 60 * 1000,
    max: 3,
    keyGenerator: (req) => req.session.tempMfaUser || req.ip,
    standardHeaders: true,
    message: "Too many verification attempts. Please try again after an hour or contact your admin.",
    // Custom handler when limit is exceeded
    handler: (req, res) => {
        return res.status(429).render('indexLogin.njk');
    }
});

/**
 * GET: Show MFA setup page (QR Code + manual secret)
 */
router.get("/setup-mfa", async (req, res) => {
    let secret = req.session.tempMfaSecret;
    let qrCode = req.session.mfaQRCode;
    let userId = req.session.tempMfaUser;
    let user = await User.findById(userId);

    // Log activities for debugging and non-repudiation
    logAuthenticationActivity("User is set to setup their mfa", req.session.user.employeeId || 'Unknown');
    logDBActivity("Retrieving user from database", req.session.user.employeeId || 'Unknown');

    // Check if the user exists
    if (!user) {return res.status(404).render('indexLogin.njk', { error: "User not found" });}

    // Log activity
    logErrorActivity("404: User not found!", req.session.user.employeeId || 'Unknown');

    // Only generate a new secret and QR if not already in session
    if (!secret || !qrCode) {
        let generated = speakeasy.generateSecret({
            name: `${user.email}`,  // or user.email
            issuer: "Stark Medical"
        });

        let newSecret = generated.base32;
        req.session.tempMfaSecret = newSecret; // set the new secret to the user's temporary mfa session secret
        // Log activity
        logAuthenticationActivity("Mfa secret has successfully been generated for the user", req.session.user.employeeId || 'Unknown');
        // save the cookies and store the MfaEnabled status as false since the user has not been verified
        user.mfaSecret = newSecret;
        user.mfaEnabled = false;
        await user.save();

        // Log activities
        logUserActivity("mfaSecret created!", req.session.user.employeeId || 'Unknown');
        logDBActivity("User secret added to database", req.session.user.employeeId || 'Unknown');

        // Generate QRCode
        qrcode.toDataURL(generated.otpauth_url, (err, data_url) => {
            if (err) {
                // Log activity
                logErrorActivity("QR generation failed:", req.session.user.employeeId || 'Unknown');
                console.error("QR generation failed:", err);
                return res.status(500).send("Error generating QR code");
            }

            req.session.mfaQRCode = data_url;
            // Reroute the user to the setupMFA page
            return res.render("setupMfa.njk", {
                qrCode: data_url,
                secret: newSecret
            });
        });
    } else {
        // Already generated — just render using stored values
        return res.render("setupMfa.njk", {
            qrCode,
            secret: req.session.tempMfaSecret
        });
    }
});

/**
 * GET: Verify the MFA code and save MFA to the user account
 * */
router.get("/verify-mfa-token", (req, res) => {
    if (!req.session.tempMfaUser) {
        logErrorActivity("Unauthorized access to MFA verification", req.session.user.employeeId || 'Unknown');
        return res.status(403).send("Unauthorized access to MFA verification");
    }
    return res.render("setupVerifyMfa.njk");
});

/**
 * POST: Verify the MFA code and save MFA to the user account
 * */
router.post("/verify-mfa-token", mfaAuthLimiter, async (req, res) => {
    // Log activity
    logUserActivity("User inputs mfa token.", req.session.user.employeeId || 'Unknown');
    // Get the generated token from the microsoft authenticator app, het
    let { token } = req.body;
    let userId = req.session.tempMfaUser;
    let user = await User.findById(userId);

    if (!userId || !user.mfaSecret) {
        // Add a flash message for the user!!
        req.session.flashMessage = "No secret generated. Redirecting to MFA setup.";
        return res.redirect("/setup-mfa");
    }

    if (!token || token.length < 6 || isNaN(token)) {
        // Log activity
        logErrorActivity("Incorrect token inputted for mfa verification", req.session.user.employeeId || 'Unknown');
        return res.status(400).render("setupVerifyMfa.njk", {
            error: "Please enter a valid 6-digit code."
        });
    }
    // Log activity
    logAuthenticationActivity("User is set to verify their mfa", req.session.user.employeeId || 'Unknown');
    // Verify the user's secret from the Mfa setup page, with the token
    let verified = verifyToken(user.mfaSecret, token);
    // redirect the user if successfully verified
    if (verified) {
        console.log("user verified", user.fullName);
        user.mfaEnabled = true;
        await user.save();
        // Log activity
        logAuthenticationActivity("User is verified and their mfa is successfully enabled!", req.session.user.employeeId || 'Unknown');
        delete req.session.tempMfaSecret;
        delete req.session.mfaQRCode;
        // Redirect the user to their appropriate portal
        console.log("issue with portal redirect");
        return res.redirect(`/portal/${user.role}`);
    } else {
        // Log activity
        logErrorActivity("Invalid MFA token inputted", req.session.user.employeeId || 'Unknown');
        return res.status(401).render("setupVerifyMfa.njk", {
            error: "❌ Invalid MFA token. Please try again.",
            qrCode: req.session.mfaQRCode,
            secret: user.mfaSecret
        });
    }
});

/**
 * GET: Show MFA code verification form during login (NOT setup)
 */
router.get("/verify-mfa", (req, res) => {
    if (!req.session.tempMfaUser) {
        // Log activity
        logErrorActivity("Unauthorized access to MFA verification", req.session.user.employeeId || 'Unknown');
        return res.status(403).render('indexLogin.njk', {error: "Unauthorized access to MFA verification"});
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
        return res.status(403).render('indexLogin.njk', {error: "Unauthorized access"});
    }

    // Extract the user from the database and ensure that they are valid users in the database
    let user = await User.findById(userId);
    logDBActivity("User successfully read from the database", user.employeeId);
    if (!user || !user.mfaSecret) {
        // Log activity
        logErrorActivity("User or MFA secret not found");
        return res.status(404).render('indexLogin.njk', {error: "User or MFA secret not found"});
    }

    // Determine the validity of the inputted token
    let verified = verifyToken(user.mfaSecret, token);
    // Log activity
    logAuthenticationActivity("User has successfully verified their mfa", req.session.user.employeeId || 'Unknown');
    console.log(`\n${req.session.user.employeeId} verified: ` + verified);

    // If the user is validated, we route them over to their respective portal
    if (verified) {
        req.session.user = {
            id: user._id,
            name: user.fullName,
            role: user.role,
            employeeId: user.employeeId
        };
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