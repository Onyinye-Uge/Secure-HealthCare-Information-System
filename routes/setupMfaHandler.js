let qrcode = require("qrcode");
let express = require("express");
let speakeasy = require("speakeasy");
let User = require("../models/User");
let { mfaAuthLimiter, verifyToken } = require("../middleware/MfaLimiter");
let { logErrorActivity, logAuthenticationActivity, logUserActivity, logDBActivity} = require("../utils/Logger");

// Initiate the router
let router = express.Router();

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
        // Update the user's authentication status
        req.session.user.isAuthenticated = true;
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

module.exports = router;