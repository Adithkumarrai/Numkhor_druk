const jwt = require('jsonwebtoken');

const adminAuth = (req, res, next) => {
    try {
        const token = req.cookies.jwt;
        
        if (!token) {
            return res.redirect('/login');
        }

        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Check if the user is an admin
        if (decoded.role !== 'admin') {
            return res.redirect('/user/dashboard');
        }

        // Add admin data to request
        req.admin = {
            email: decoded.email,
            username: decoded.email.split('@')[0]
        };

        next();
    } catch (error) {
        console.error('❌ Admin authentication error:', error);
        res.clearCookie('jwt');
        res.redirect('/login');
    }
};

module.exports = adminAuth;

