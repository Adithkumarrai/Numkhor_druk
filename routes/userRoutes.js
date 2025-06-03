// --- routes/userRoutes.js ---
const express = require('express');
const router = express.Router();
const userController = require('../controllers/userControllers');
const { isAuthenticated } = require('../middleware/authMiddleware');
const db = require('../config/db');

// Protected routes - require authentication
router.use(isAuthenticated);

// Route to /user/dashboard renders views/home.ejs
router.get('/dashboard', async (req, res) => {
  try {
    const cars = await db.any('SELECT * FROM cars ORDER BY created_at DESC');
    res.render('home', { cars });
  } catch (error) {
    console.error('Error fetching cars:', error);
    res.render('home', { cars: [], message: 'Failed to load cars' });
  }
});

// Contact form
router.post('/contact/send', userController.sendContactMessage);

module.exports = router;
