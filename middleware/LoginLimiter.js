/*
This file will hold the implementation of limiting the amount of logins.

Criteria:

     1. The user will have a total of 5 tries.
     2. If the user fails to log-in after the first attempt, we prompt the user to update their password.
     3. First, we send the user a confirmation email prompting them to reset their password.
     4. Once the user clicks on the link, we redirect them to our reset password page, and there the update occurs.
     2. If the user fails all 3 tries, we advise them to reach out to their administrator to be granted access again.
*/

// import necessary libraries
let {check} = require("express-validator");
let rateLimiter = require('express-rate-limit');
const {int} = require("nunjucks/src/filters");

let loginLimiter = rateLimiter(
    {
        windowMs: 60 * 60 * 1000,
        max: 3,
        keyGenerator: (req) => req.session.tempMfaUser || req.ip,
        standardHeaders: true,
        legacyHeaders: false,
        message: "Too many verification attempts. Please try again after an hour or contact your admin.",
        // Custom handler when limit is exceeded
        handler: (req, res) => {
            return res.status(429).render('indexLogin.njk');
        }
    });

// These validators ensure that our security criteria are met when a login attempt is made.
let loginValidators = [
    check('employeeId').isLength({ min: 6, max: 6 }).isNumeric(),
    check('password').isLength({ min: 10 })
]

//export the configuration
module.exports = {
    loginLimiter: loginLimiter,
    loginValidators: loginValidators,
};