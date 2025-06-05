const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');
require('dotenv').config();
const { createUserTable } = require('./models/userModels');
const { createCarsTable } = require('./models/carModel');
const { createMessageTable } = require('./models/messageModel');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy - needed for secure cookies and proper IP handling
app.set('trust proxy', 1);

// Set app-wide locals
app.use((req, res, next) => {
  // Set base URL for the application
  app.locals.baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
  next();
});

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static('public/CSS'));

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'secretkey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  }
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.use('/', authRoutes);
app.use('/user', userRoutes);
app.use('/admin', adminRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render('error', { 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : null
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render('error', { 
    error: 'Page not found',
    message: 'The page you are looking for does not exist.'
  });
});

// Initialize database tables
const initializeTables = async () => {
  try {
    await createUserTable();
    await createCarsTable();
    await createMessageTable();
    console.log('✅ All database tables initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database tables:', error);
    process.exit(1);
  }
};

// Initialize tables and start server
initializeTables().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running at http://localhost:${PORT}`);
  });
});
