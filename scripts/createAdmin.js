require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Admin = require('../models/admin');

const createFirstAdmin = async () => {
    try {
        console.log('Connecting to MongoDB...');
        await mongoose.connect('mongodb://localhost:27017/numkhor_druk');
        console.log('✅ Connected to MongoDB');

        // First, let's see if we can find any existing admins
        const allAdmins = await Admin.find({});
        console.log('\nExisting admins:', allAdmins.length);
        if (allAdmins.length > 0) {
            console.log('Current admin accounts:');
            allAdmins.forEach(admin => {
                console.log(`- Email: ${admin.email}`);
            });
        }

        // Create or update admin
        const adminData = {
            username: 'admin',
            password: 'admin123',
            email: 'admin@gmail.com'  // Using the email from your login attempt
        };

        console.log('\nAttempting to create/update admin with:', adminData);

        // Delete any existing admin first
        await Admin.deleteMany({});
        console.log('✅ Cleared existing admin accounts');

        // Create new admin
        const admin = new Admin(adminData);
        await admin.save();
        
        // Verify the admin was created
        const verifyAdmin = await Admin.findOne({ email: adminData.email });
        if (verifyAdmin) {
            console.log('\n✅ Admin account created successfully!');
            console.log('\nAdmin Login Credentials:');
            console.log('------------------------');
            console.log(`Email: ${adminData.email}`);
            console.log(`Password: ${adminData.password}`);
            console.log('\n⚠️ Please change these credentials after first login!');
            
            // Test password comparison
            const testPassword = await verifyAdmin.comparePassword(adminData.password);
            console.log('\nPassword verification test:', testPassword ? '✅ Success' : '❌ Failed');
        } else {
            console.log('❌ Failed to create admin account!');
        }

    } catch (error) {
        console.error('❌ Error:', error);
    } finally {
        await mongoose.disconnect();
        console.log('\nDisconnected from MongoDB');
    }
};

createFirstAdmin(); 