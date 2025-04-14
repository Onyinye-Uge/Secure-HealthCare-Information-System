// ===== IMPORTS =====
let fs = require('fs');
let cors = require('cors');
let path = require('path');
let https = require('https');
let helmet = require('helmet');
let express = require('express');
let mongoose = require('mongoose');
let nunjucks = require('nunjucks');
let { format } = require('date-fns');
let bodyParser = require('body-parser');
let session = require('express-session');
let mongoSanitize = require('express-mongo-sanitize');

// ===== CONFIG AND ROUTES =====
let config = require('./config/config');
let loginHandler = require('./routes/loginHandler');
let portalHandler = require('./routes/portalHandler');
let logoutHandler = require('./routes/logoutHandler');
let setMfaRoutes = require('./routes/setupMfaHandler');
let loginMfaRoutes = require('./routes/loginMfaHandler');
let changePasswordRoute = require('./routes/changePasswordHandler');

// ===== INITIATE APP =====
console.log('Booting the Stark Medical Server...');
let app = express();

// HTTPS Certificate Options
let options = {
    key: fs.readFileSync(path.join(__dirname, '/config/key.pem')),
    cert: fs.readFileSync(path.join(__dirname, '/config/cert.pem')),
};

let server = https.createServer(options, app);

// ===== NUNJUCKS CONFIGURATION =====
nunjucks.configure('public/views', {
    autoescape: true,
    express: app,
    watch: true,
    noCache: false,
}).addFilter('date', (value, formatStr) => {
    try {
        return format(new Date(value), formatStr || 'MMMM dd, yyyy');
    } catch (err) {
        console.error("\nError formatting date: ", err);
        return value;
    }
}).addFilter('capitalize', function (str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
});

// ===== MIDDLEWARE =====
app.use(helmet()); // Sets security headers
app.use(express.static(path.join(__dirname, 'public')));
app.use(mongoSanitize()); // Prevents NoSQL injection

// ===== SESSION =====
app.use(session({
    secret: config.secretKey,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        sameSite: 'strict',
        httpOnly: true,
        maxAge: 30 * 60 * 1000 // 30 minutes in milliseconds
    },
    rolling: true // Ensures that the session expiry timer is reset every time a session restarts.
}));

// ===== PARSERS =====
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// ===== CORS SETUP =====
app.use(cors({
    origin: 'https://stark-medical.com',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

// ===== CONNECT TO DATABASE THEN BOOT =====
mongoose.connect(config.mongoURI).then(() => {
    console.log("\n✅ MongoDB connected.");

    // ===== ROUTES =====
    app.use(loginHandler);             // Handles login
    app.use(changePasswordRoute);      // Handles password change
    app.use(setMfaRoutes);                // Handles MFA setup and verification
    app.use(loginMfaRoutes);                // Handles MFA setup and verification
    app.use(portalHandler);             // Handles portal routes
    app.use(logoutHandler);             // Handles login out

    // Home Page
    app.get('/', (req, res) => res.render('indexLogin.njk'));

    // ===== ERROR HANDLING =====
    app.use((req, res) => {
        res.status(404).render('404.njk');
    });

    app.use((err, req, res) => {
        console.error(err.stack);
        res.status(500).render('500.njk');
    });

    // ===== START SERVER =====
    server.listen(config.port, () => {
        console.log(`\n🚀 Server running at https://localhost:${config.port}`);
    });

}).catch(err => {
    console.error("\n❌ MongoDB connection failed:", err);
});