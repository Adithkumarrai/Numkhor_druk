const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');
require('dotenv').config();
const { createUserTable } = require('./models/userModels');
const { createCarsTable } = require('./models/carModel');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
const PORT = process.env.PORT || 3000;


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
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.use('/', authRoutes);
app.use('/user', userRoutes);
app.use('/admin', adminRoutes);

// Initialize database tables
const initializeTables = async () => {
  try {
    await createUserTable();
    await createCarsTable();
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
