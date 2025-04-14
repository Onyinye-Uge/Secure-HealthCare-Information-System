/*
* This file handles portal routing.
*/
let express = require('express');
let {logErrorActivity, logUserActivity} = require("../utils/Logger");

// Initiate the router
let router = express.Router();

// Middleware to ensure user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.session && req.session.user || !req.session.isAuthenticated) {
        return next();
    }
    logUserActivity("User is authenticated and accessing their respective portal!");
    return res.redirect('/loginHandler');
}

// This function will destroy the cache after the user logs out
function noCache(req, res, next) {
    res.set("Cache-Control", "no-store");
    next();
}

// Portal route - accessible only after MFA verification and login
router.get('/portal/:role', ensureAuthenticated, noCache, (req, res) => {
    let user = req.session.user;

    if (!user || user.role !== req.params.role) {
        logErrorActivity(`User not authorised to access portal`);
        return res.status(403).render('403.njk', { error: "Unauthorized access." });
    }
    logUserActivity("Routing user to their authorised portal!");
    return res.render('portal.njk', { user });
});

module.exports = router;