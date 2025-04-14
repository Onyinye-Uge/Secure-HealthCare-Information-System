// ====== Import libraries =====
let express = require('express');
let { logUserActivity } = require('../utils/Logger');

// Initiate the router
let router = express.Router();

// Route the user to the login page after logging out
router.post('/logout', (req, res, err) => {
    res.set("Cache-Control", "no-store");
    logUserActivity("User's current session is resetting and the user is logging out", req.session.user.employeeId);
    req.session.destroy(); // Destroy the previous session once the user logs out.
    res.redirect('/'); // redirect the user to the login page
});

module.exports = router;