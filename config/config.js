let dotenv = require('dotenv');

//Configure the environment
dotenv.config();

module.exports = {
    port: process.env.PORT,
    mongoURI: process.env.MONGO_URI,
    secretKey: process.env.SECRET_SECTION_KEY,
    encryptionKey: process.env.ENCRYPTION_KEY,
    signingKey: process.env.SIGNING_KEY,
    basePassword: process.env.BASE_PASSWORD,
}