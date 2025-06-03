const express = require('express');
const router = express.Router();
const authControllers = require('../controllers/authControllers');
const db = require('../config/db');

// Logout Route
router.get('/logout', (req, res) => {
    // Clear session
    req.session.destroy(err => {
        if (err) {
            console.error('❌ Error destroying session:', err);
        }
    });

    // Clear all auth cookies
    res.clearCookie('connect.sid');
    res.cookie('userToken', '', {
        httpOnly: true,
        expires: new Date(0)
    });
    res.cookie('adminToken', '', {
        httpOnly: true,
        expires: new Date(0)
    });

    console.log('✅ Successfully logged out');
    res.redirect('/landing');
});

// root route
router.get('/', (req, res) => {
    res.render('landing');
});

// Signup
router.get('/signup', authControllers.getSignup);
router.post('/signup', authControllers.postSignup);

// Email verification
router.get('/verify-email', authControllers.verifyEmail);

// Login
router.get('/login', authControllers.getLogin);
router.post('/login', authControllers.postLogin);

// Forgot and reset password routes
router.get('/forgot-password', authControllers.getForgotPassword);
router.post('/forgot-password', authControllers.forgotPassword);
router.get('/reset-password', authControllers.getResetPassword);
router.post('/reset-password', authControllers.resetPassword);

// Add /about route
router.get('/about', (req, res) => {
    res.render('about');
});

// Create a Route for /contact
router.get('/contact', (req, res) => {
    res.render('contact');
});

// Route for Home page
router.get('/home', async (req, res) => {
    try {
        // Fetch cars from database
        const cars = await db.any('SELECT * FROM cars ORDER BY created_at DESC');
        res.render('home', { cars });
    } catch (error) {
        console.error('Error fetching cars:', error);
        res.render('home', { cars: [], error: 'Failed to load cars' });
    }
});

// landing page route
router.get('/landing', (req, res) => {
    res.render('landing');
});

module.exports = router;






module.exports = router;