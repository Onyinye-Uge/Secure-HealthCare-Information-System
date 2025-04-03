let fs = require('fs');
let path = require('path');

// Define the logging file paths
let dbLogFilePath = path.join(__dirname, '/logs/databaseActivity.log');
let authLogFilePath = path.join(__dirname, '/logs/authenticationActivity.log');
let userLogFilePath = path.join(__dirname, '/logs/userActivity.log');
let errorLogFilePath = path.join(__dirname, '/logs/errorActivity.log');

// Ensure the logs directory exists
if (!fs.existsSync(path.dirname(dbLogFilePath))) {
    fs.mkdirSync(path.dirname(dbLogFilePath), { recursive: true });
}
else if (!fs.existsSync(path.dirname(authLogFilePath))) {
    fs.mkdirSync(path.dirname(authLogFilePath), { recursive: true });
}
else if (!fs.existsSync(path.dirname(userLogFilePath))) {
    fs.mkdirSync(path.dirname(userLogFilePath), { recursive: true });
}

// Log general database activity (e.g., create, update, delete)
function logDBActivity(action, userId = 'System', data = {}) {
    let timeStamp = new Date().toISOString();
    let logEntry = `\n📝 [${timeStamp}] DATABASE ACTION: ${action} by ${userId} | Details: ${JSON.stringify(data)}\n`;
    fs.appendFileSync(dbLogFilePath, logEntry, 'utf-8');
}

// Log user-related activities (e.g., profile update, role changes)
function logUserActivity(action, userId = '', activity = {}) {
    let timeStamp = new Date().toISOString();
    let logEntry = `\n📝 [${timeStamp}]: [${userId} performed '${action}' | Details: ${JSON.stringify(activity)}\n`;
    try {
        fs.appendFileSync(userLogFilePath, logEntry, 'utf-8');
    } catch (err) {
        fs.appendFileSync(errorLogFilePath, `\n📝 Error logging user activity by ${userId}: Failed to perform ${action}`, 'utf-8');
    }
}

// Log authentication attempts and their status (e.g., success, failure)
function logAuthenticationActivity(status, userID=" ") {
    let timeStamp = new Date().toISOString();
    let logEntry = `\n📝 [${timeStamp}] AUTH ATTEMPT: ${status.toUpperCase()} by (${userID})\n`;
    fs.appendFileSync(authLogFilePath, logEntry, 'utf-8');
}

function logErrorActivity(error, userID = '', ) {
    let timeStamp = new Date().toISOString();
    let logEntry = `\n📝 [${timeStamp}] ERROR: [${userID}] inferred ${error}\n`;
    fs.appendFileSync(errorLogFilePath, logEntry, 'utf-8');
}

module.exports = {
    logDBActivity,
    logUserActivity,
    logErrorActivity,
    logAuthenticationActivity
};