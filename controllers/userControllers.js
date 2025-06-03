// --- controllers/userControllers.js ---
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const nodemailer = require('nodemailer');
require('dotenv').config();

// Create email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Handle contact form submission
const sendContactMessage = async (req, res) => {
  try {
    const { name, email, message } = req.body;

    // Store message in database
    await db.none(
      'INSERT INTO messages (name, email, message) VALUES ($1, $2, $3)',
      [name, email, message]
    );

    // Redirect back with success message
    res.redirect('/contact?success=true');
  } catch (error) {
    console.error('Contact form error:', error);
    res.redirect('/contact?error=true');
  }
};

// Placeholder for future functions (e.g., viewing user profiles)
const getUserProfile = async (req, res) => {
  // Logic to retrieve user profile from DB using req.user.id (after auth middleware)
};

const listAllUsers = async (req, res) => {
  // Logic to fetch and render all users, for admin use
};

module.exports = {
  sendContactMessage,
  getUserProfile,    // reserved for future
  listAllUsers       // reserved for future
};
