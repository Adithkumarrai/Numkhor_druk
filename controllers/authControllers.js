const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const nodemailer = require('nodemailer');
require('dotenv').config();

const saltRounds = 10;

// ✅ Email transporter using App Password (Not your Gmail login password)
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,           // SSL port
  secure: true,        // Use SSL
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

                                                                                                                                                                                                                                                                                    

// ✅ Check if transporter is working
transporter.verify(function (error, success) {
  if (error) {
    console.error('❌ Email transporter error:', error);
  } else {
    console.log('✅ Email transporter is ready');
  }
});

// GET: Render login page
exports.postLogin = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Check if it's admin credentials (from .env)
    if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
      const token = jwt.sign(
        { email, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.cookie('jwt', token, { httpOnly: true });
      return res.redirect('/admin/dashboard');
    }

    // 2. If not admin, check regular users from the database
    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (!user) return res.render('login', { message: 'Invalid credentials!' });

    if (!user.is_verified) {
      return res.render('login', { message: 'Please verify your email first.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render('login', { message: 'Invalid credentials!' });

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.cookie('jwt', token, { httpOnly: true });

    return res.redirect('/user/dashboard');

  } catch (error) {
    console.error(error);
    res.render('login', { message: 'Error during login.' });
  }
};
// GET: Render login form
exports.getLogin = (req, res) => {
  res.render('login', { message: null });
};

// GET: Render signup form
exports.getSignup = (req, res) => {
  res.render('signup', { message: null });
};

// POST: Handle signup
exports.postSignup = async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  try {
    // Basic validation
    if (!name || !email || !password) {
      return res.render('signup', { 
        message: 'All fields are required',
        oldInput: { name, email }
      });
    }

    if (password !== confirmPassword) {
      return res.render('signup', {
        message: 'Passwords do not match',
        oldInput: { name, email }
      });
    }

    // Check if user already exists
    const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser) {
      return res.render('signup', { 
        message: 'Email already registered!',
        oldInput: { name }
      });
    }

    // Hash password and create verification token
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Create new user
    await db.none(
      'INSERT INTO users (name, email, password, role, verification_token) VALUES ($1, $2, $3, $4, $5)',
      [name, email, hashedPassword, 'user', verificationToken]
    );

    // Generate verification link
    const verificationLink = `${process.env.BASE_URL || `http://localhost:${process.env.PORT}`}/verify-email?token=${verificationToken}`;

    // Send verification email
    await transporter.sendMail({
      from: `"Sherubtse Auth" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Verify your email',
      html: `
        <h3>Hello ${name},</h3>
        <p>Thank you for signing up! Please verify your email by clicking the link below:</p>
        <a href="${verificationLink}" style="
          display: inline-block;
          padding: 10px 20px;
          background-color: #4a148c;
          color: white;
          text-decoration: none;
          border-radius: 5px;
          margin: 20px 0;
        ">Verify Email</a>
        <p>If you didn't create an account, please ignore this email.</p>
      `,
    });

    // Redirect to login with success message
    res.redirect('/login?signup=success');
  } catch (error) {
    console.error('Signup error:', error);
    res.render('signup', { 
      message: 'Error during signup. Please try again.',
      oldInput: { name, email }
    });
  }
};

// GET: Verify email
exports.verifyEmail = async (req, res) => {
  const { token } = req.query;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    await db.none('UPDATE users SET is_verified = true, verification_token = NULL WHERE email = $1', [email]);

    res.send('✅ Email verified successfully. You can now log in.');
  } catch (error) {
    console.error(error);
    res.send('❌ Invalid or expired verification link.');
  }
};

// GET: Forgot password form
exports.getForgotPassword = (req, res) => {
  res.render('forgot-password', { message: null });
};

// POST: Forgot password logic
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (!user) return res.render('forgot-password', { message: 'Email not found' });

    const resetToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    await db.none('UPDATE users SET reset_token = $1 WHERE email = $2', [resetToken, email]);

    const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: `"Sherubtse Auth" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Password Reset Request',
      html: `<p>Click the link below to reset your password:</p><a href="${resetLink}">${resetLink}</a>`,
    });

    res.render('forgot-password', { message: 'Password reset link has been sent to your email.' });
  } catch (error) {
    console.error(error);
    res.render('forgot-password', { message: 'Something went wrong. Please try again.' });
  }
};

// GET: Reset password form
exports.getResetPassword = (req, res) => {
  const { token } = req.query;
  res.render('reset-password', { token, message: null });
};

// POST: Reset password logic
exports.resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const email = decoded.email;

    const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
    if (!user) return res.render('reset-password', { message: 'Invalid or expired token' });

    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    await db.none('UPDATE users SET password = $1, reset_token = NULL WHERE email = $2', [hashedPassword, email]);

    res.render('reset-password', { message: 'Password has been reset successfully.' });
  } catch (error) {
    console.error(error);
    res.render('reset-password', { message: 'Invalid or expired token' });
  }
};
