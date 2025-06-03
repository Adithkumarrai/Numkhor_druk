const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const { isAdmin } = require('../middleware/authMiddleware');

// Apply admin authentication middleware to all admin routes
router.use(isAdmin);

// Admin dashboard
router.get('/dashboard', adminController.getDashboard);  // Main dashboard route

// Car management routes
router.get('/cars/add', adminController.getAddCarForm);
router.post('/cars/add', adminController.addCar);
router.get('/cars/edit/:id', adminController.getEditCarForm);
router.post('/cars/edit/:id', adminController.updateCar);
router.post('/cars/delete/:id', adminController.deleteCar);

// Message management routes
router.get('/messages', adminController.getMessages);
router.post('/messages/mark-read/:id', adminController.markMessageAsRead);

// Logout route
router.get('/logout', (req, res) => {
    res.clearCookie('jwt');
    res.redirect('/login');
});

module.exports = router;

