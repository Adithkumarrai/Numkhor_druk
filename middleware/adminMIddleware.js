const jwt = require('jsonwebtoken');

const adminAuth = (req, res, next) => {
    const token = req.cookies.adminToken;

    if (!token) {
        return res.redirect('/admin/login');
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');

        // You can expand this with a DB check if needed
        req.admin = {
            username: 'Admin',
            email: process.env.ADMIN_EMAIL
        };

        next();
    } catch (err) {
        console.error('❌ Admin auth error:', err);
        res.redirect('/admin/login');
    }
};

module.exports = adminAuth;
