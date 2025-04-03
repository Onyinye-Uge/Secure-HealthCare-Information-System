// This script adds a new user to the Stark Medical collection

let bcrypt = require('bcrypt');
let mongoose = require('mongoose');
let User = require('../../models/User');
let config = require('../../config/config');
let { logErrorActivity, logDBActivity } = require('../../utils/Logger');

// Generate a unique 6-digit Employee ID
function generateEmployeeID() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Create a user with proper field destructuring
let createUser = async (userData) => {
    try {
        let {
            fullName, email, role,
            phoneNumber, address,
            specialization, licenseNumber,
            department, availability
        } = userData;

        await mongoose.connect(config.mongoURI);
        logDBActivity("Establishing db connection", {
            date: new Date().toISOString()
        })

        // Hash password
        let basePassword = config.basePassword;
        let passwordHash = await bcrypt.hash(basePassword, 14);

        // Ensure unique employee ID
        let employeeId;
        let existing;
        do {
            employeeId = generateEmployeeID();
            existing = await User.findOne({ employeeId });
        } while (existing);

        // Initiate new user creation
        let newUser = new User({
            employeeId,
            fullName,
            email,
            phoneNumber,
            passwordHash,
            role,
            address,
            isEmailConfirmed: true,
            mustChangePassword: true,
            createdByAdmin: true,
            specialization,
            licenseNumber,
            department,
            availability
        });
        // Log activity
        logDBActivity(`\n✅ New User created successfully: ${newUser.fullName} [${employeeId}]`);
        console.log(`\n✅ New User created successfully: ${newUser.fullName} [${employeeId}]`);

        // Save the newly created user
        await newUser.save();

        // Log activity
        logDBActivity("Adding new user to the database", {
            date: new Date().toISOString(),
            fullName,
            role,
            employeeId
        })
    } catch (error) {
        // Log activity
        logErrorActivity("❌ Error creating user: ", "Unknown");
    } finally {
        await mongoose.disconnect();
    }
};

// Run user creation
(async () => {
    await createUser({
        fullName: "Daniel Stewart",
        email: "daniel.stewart@starkmedical.com",
        phoneNumber: "594.946.6011",
        role: "doctor",
        address: {
            street: "50176 Baird Corners Apt. 462",
            city: "Guzmanmouth",
            province: "Arkansas",
            postalCode: "T4M 0L0"
        },
        specialization: "Cardiology",
        licenseNumber: "MD-8293",
        department: "Heart Unit",
        availability: ["Monday", "Wednesday", "Friday"]
    });

    await createUser({
        fullName: "Sarah Beck",
        email: "sarah.beck@starkmedical.com",
        phoneNumber: "596-872-6930",
        role: "assistant",
        address: {
            street: "384 Martinez Fork",
            city: "Port Grace",
            province: "Kansas",
            postalCode: "F7H 0Z0"
        }
    });

    await createUser({
        fullName: "Bridget Griffin",
        email: "bridget.griffin@starkmedical.com",
        phoneNumber: "491-964-9639",
        role: "receptionist",
        address: {
            street: "933 Shawn Dam",
            city: "East Dianemouth",
            province: "Nebraska",
            postalCode: "W8V 9A8"
        }
    });
})();