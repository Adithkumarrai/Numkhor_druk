const jwt = require('jsonwebtoken');


// Protects routes for users with 'admin' role
exports.isAdmin = (req, res, next) => {
  const token = req.cookies.jwt;
  if (!token) return res.redirect('/login');


  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect('/login');
    if (decoded.role !== 'admin') return res.redirect('/user/dashboard');
    req.user = decoded;
    next();
  });
};


// Protects routes for users (admin or user)
exports.isAuthenticated = (req, res, next) => {
  const token = req.cookies.jwt;
  if (!token) return res.redirect('/login');


  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      res.clearCookie('jwt');
      return res.redirect('/login');
    }
    req.user = decoded;
    next();
  });
};

// Protect admin routes
exports.protect = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.redirect('/login');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.redirect('/user/dashboard');
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.clearCookie('jwt');
    return res.redirect('/login');
  }
};



