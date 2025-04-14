/*
This file will hold the implementation of limiting the amount of mfa verification attempts.
*/

// import necessary libraries
let speakeasy = require("speakeasy");
let rateLimiter = require('express-rate-limit');

/**
 * Helper function to verify a TOTP token.
 * */
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

module.exports = {
    mfaAuthLimiter: mfaAuthLimiter,
    verifyToken: verifyToken,
}