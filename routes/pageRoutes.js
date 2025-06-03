const express = require('express');
const router = express.Router();
const userController = require('../controllers/userControllers');
const db = require('../config/db');

// Static pages
router.get('/', (req, res) => {
    res.render('landing');
});

router.get('/landing', (req, res) => {
    res.render('landing');
});

router.get('/about', (req, res) => {
    res.render('about');
});

router.get('/contact', (req, res) => {
    res.render('contact', { 
        success: req.query.success === 'true', 
        error: req.query.error === 'true',
        message: null 
    });
});

// Contact form
router.post('/contact/send', userController.sendContactMessage);

// Home/Dashboard pages
router.get('/home', async (req, res) => {
    try {
        const cars = await db.any('SELECT * FROM cars ORDER BY created_at DESC');
        res.render('home', { cars, error: null });
    } catch (error) {
        console.error('Error fetching cars:', error);
        res.render('home', { cars: [], error: 'Failed to load cars' });
    }
});

module.exports = router; 