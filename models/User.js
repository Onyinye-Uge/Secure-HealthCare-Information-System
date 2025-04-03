let mongoose = require('mongoose');
let config = require('../config/config');
let encrypt = require('mongoose-encryption');

// Define the user schema and set field validation parameters
let userSchema = new mongoose.Schema({
    employeeId: { type: String, unique: true, length: 6, minLength: 6, maxLength: 6 },
    fullName: {type: String, required: true},
    email: { type: String,
        required: true,
        unique: true,
        match: [/^\S+@\S+\.\S+$/, `Please, use a valid email address!`]
    },
    address: {
        street: String,
        city: String,
        province: String,
        postalCode: {
            type: String,
            validate: {
                validator: function(v){
                    return /^[A-Za-z]\d[A-Za-z] \d[A-Za-z]\d$/.test(v);
                },
                message: props => `${props.value} is not a valid Canadian postal code (format A1A 1A1)`
            }
        },
    },
    phoneNumber: { type: String, required: true },
    passwordHash: { type: String, required: false },
    passWordHistory: {
        type: [String],
        default: []
    },
    role: {
        type: String,
        enum: ['receptionist', 'doctor', 'assistant', 'pharmacist'],
        required: true
    },
    mustChangePassword: { type: Boolean, default: true },
    mfaEnabled: { type: Boolean, default: true },
    mfaSecret: { type: String, default: null }, // for MFA setup
    createdByAdmin: { type: Boolean, default: false },

    // Doctor-specific
    specialization: { type: String },
    licenseNumber: { type: String },
    department: { type: String },
    availability: [{ type: String }],

    // Pharmacist-specific
    certificationId: { type: String },
    licenseExpiry: { type: Date },

    // Assistant/Receptionist-specific
    assignedDoctor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    shift: { type: String },
    canBookAppointments: { type: Boolean, default: false }
}, { timestamps: true });

// ============= Data at rest encryption initiation ==================
/*
    Encryption Key:
        The encryption key provides our key for encryption and decryption: A symmetric approach.

    Signing Key:
        The signing key facilitates the verification of data integrity:
            If our data is compromised, mongo will not decrypt the data, and would provide an exception.
*/
let encKey = config.encryptionKey;
let signingKey = config.signingKey;

// Assign the encryption algorithm and the keys that will be used to protect the data at rest
userSchema.plugin(encrypt, {
    encryptionKey: encKey, // pass a 32-bit encryption key that will be utilised for the AES-256-CBC algorithm
    signingKey: signingKey, // pass a 64 bit signature key for our encryption of the data
    encryptedFields: ['phoneNumber', 'address', 'specialization', 'licenseNumber', 'certificationId',
    'passwordHash', 'role', 'passWordHistory']
})

module.exports = mongoose.model('User', userSchema);