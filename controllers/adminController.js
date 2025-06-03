const User = require('../models/userModels');
const db = require('../config/db');
const Message = require('../models/messageModel');

// @desc    Get admin dashboard
// @route   GET /admin/dashboard
exports.getDashboard = async (req, res) => {
    try {
        // Get user statistics
        const totalUsers = await User.countUsers();
        const newUsers = await User.countNewUsersToday();
        const recentUsers = await User.getRecentUsers(5);

        // Get car listings
        const cars = await db.any('SELECT * FROM cars ORDER BY created_at DESC');

        // Get unread message count
        const unreadMessages = await Message.getUnreadCount();

        // Get admin data from the request (set by middleware)
        const adminData = {
            username: req.admin?.username || 'Admin',
            email: req.admin?.email || process.env.ADMIN_EMAIL
        };

        res.render('adminDashboard', {
            admin: adminData,
            stats: {
                totalUsers: totalUsers || 0,
                newUsers: newUsers || 0,
                activeUsers: totalUsers || 0,
                unreadMessages: unreadMessages || 0
            },
            recentUsers: recentUsers || [],
            cars: cars || []
        });
    } catch (error) {
        console.error('❌ Dashboard error:', error);
        // Render the dashboard with error message instead of redirecting
        res.render('adminDashboard', {
            admin: { username: 'Admin', email: process.env.ADMIN_EMAIL },
            stats: { totalUsers: 0, newUsers: 0, activeUsers: 0, unreadMessages: 0 },
            recentUsers: [],
            cars: [],
            error: 'Error loading dashboard data'
        });
    }
};

// @desc    Show add car form
// @route   GET /admin/cars/add
exports.getAddCarForm = async (req, res) => {
    try {
        res.render('addCar', { error: null });
    } catch (error) {
        console.error('Error loading add car form:', error);
        res.status(500).send('Error loading add car form');
    }
};

// @desc    Add new car
// @route   POST /admin/cars/add
exports.addCar = async (req, res) => {
    try {
        const { title, brand, model, year, price, location, seller, image } = req.body;

        const newCar = await db.one(
            `INSERT INTO cars (title, brand, model, year, price, location, seller, image)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING *`,
            [title, brand, model, year, price, location, seller, image]
        );

        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error adding car:', error);
        res.render('addCar', {
            error: 'Error adding car',
            car: req.body
        });
    }
};

// @desc    Show car edit form
// @route   GET /admin/cars/edit/:id
exports.getEditCarForm = async (req, res) => {
    try {
        const carId = req.params.id;
        const car = await db.oneOrNone('SELECT * FROM cars WHERE id = $1', [carId]);
        
        if (!car) {
            return res.status(404).send('Car not found');
        }
        
        res.render('editCar', { car, error: null });
    } catch (error) {
        console.error('Error fetching car:', error);
        res.status(500).send('Error fetching car details');
    }
};

// @desc    Update car details
// @route   POST /admin/cars/edit/:id
exports.updateCar = async (req, res) => {
    try {
        const carId = req.params.id;
        const { title, brand, model, year, price, location, seller, image } = req.body;

        const updatedCar = await db.oneOrNone(
            `UPDATE cars 
             SET title = $1, brand = $2, model = $3, year = $4, 
                 price = $5, location = $6, seller = $7, image = $8,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $9
             RETURNING *`,
            [title, brand, model, year, price, location, seller, image, carId]
        );

        if (!updatedCar) {
            return res.render('editCar', {
                car: { ...req.body, id: carId },
                error: 'Car not found or could not be updated'
            });
        }

        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error updating car:', error);
        res.render('editCar', {
            car: { ...req.body, id: req.params.id },
            error: 'Error updating car details'
        });
    }
};

// @desc    Delete car
// @route   POST /admin/cars/delete/:id
exports.deleteCar = async (req, res) => {
    try {
        const carId = req.params.id;
        const result = await db.result('DELETE FROM cars WHERE id = $1', [carId]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Car not found' });
        }

        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error deleting car:', error);
        res.status(500).json({ error: 'Failed to delete car' });
    }
};

// @desc    Get contact messages
// @route   GET /admin/messages
exports.getMessages = async (req, res) => {
    try {
        const messages = await Message.getAllMessages();
        const unreadCount = await Message.getUnreadCount();
        
        res.render('contactMessage', {
            messages,
            unreadCount
        });
    } catch (error) {
        console.error('❌ Error fetching messages:', error);
        res.status(500).send('Error loading messages');
    }
};

// @desc    Mark message as read
// @route   POST /admin/messages/mark-read/:id
exports.markMessageAsRead = async (req, res) => {
    try {
        const messageId = req.params.id;
        await Message.markAsRead(messageId);
        res.redirect('/admin/messages');
    } catch (error) {
        console.error('❌ Error marking message as read:', error);
        res.status(500).send('Error updating message');
    }
};
