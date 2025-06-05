const db = require('../config/db');

// Create users table if it doesn't exist
async function createUserTable() {
  const query = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user', -- ✅ Added role
      is_admin BOOLEAN DEFAULT FALSE,
      is_verified BOOLEAN DEFAULT FALSE,
      verification_token TEXT,
      reset_token TEXT,
      reset_token_expiry TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;

  try {
    await db.none(query);
    console.log('✅ Users table created or already exists');
  } catch (error) {
    console.error('❌ Error creating users table:', error);
    throw error;
  }
}

// Insert new user (with role and verification token)
async function insertUser(user) {
  const { name, email, password, role = 'user', verification_token } = user;
  return db.one(
    `INSERT INTO users (name, email, password, role, verification_token) 
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [name, email, password, role, verification_token]
  );
}

// Find user by email
async function findUserByEmail(email) {
  return db.oneOrNone(`SELECT * FROM users WHERE email = $1`, [email]);
}

// Find user by verification token
async function findUserByVerificationToken(token) {
  return db.oneOrNone(
    `SELECT * FROM users WHERE verification_token = $1`,
    [token]
  );
}

// Mark user as verified
async function verifyUser(userId) {
  return db.none(
    `UPDATE users 
     SET is_verified = TRUE, verification_token = NULL 
     WHERE id = $1`,
    [userId]
  );
}

// Set/reset token for forgot-password
async function updateResetToken(email, token, expiry) {
  return db.none(
    `UPDATE users 
     SET reset_token = $1, reset_token_expiry = $2 
     WHERE email = $3`,
    [token, expiry, email]
  );
}

// Find user by reset token (only if valid)
async function findUserByResetToken(token) {
  return db.oneOrNone(
    `SELECT * FROM users 
     WHERE reset_token = $1 AND reset_token_expiry > NOW()`,
    [token]
  );
}

// Reset password using token
async function resetPassword(userId, hashedPassword) {
  return db.none(
    `UPDATE users 
     SET password = $1, reset_token = NULL, reset_token_expiry = NULL 
     WHERE id = $2`,
    [hashedPassword, userId]
  );
}

// Update password (with email, legacy support)
async function updatePassword(email, newPassword) {
  return db.none(
    `UPDATE users 
     SET password = $1, reset_token = NULL, reset_token_expiry = NULL 
     WHERE email = $2`,
    [newPassword, email]
  );
}

// Analytics: Total user count
async function countUsers() {
  const result = await db.one(`SELECT COUNT(*) as count FROM users`);
  return parseInt(result.count);
}

// Analytics: New users today
async function countNewUsersToday() {
  const result = await db.one(`
    SELECT COUNT(*) as count 
    FROM users 
    WHERE DATE(created_at) = CURRENT_DATE
  `);
  return parseInt(result.count);
}

// Get latest registered users (limit)
async function getRecentUsers(limit = 5) {
  return db.any(
    `SELECT id, name, email, role, created_at 
     FROM users 
     ORDER BY created_at DESC 
     LIMIT $1`,
    [limit]
  );
}

module.exports = {
  createUserTable,
  insertUser,
  findUserByEmail,
  findUserByVerificationToken,
  verifyUser,
  updateResetToken,
  findUserByResetToken,
  resetPassword,
  updatePassword,
  countUsers,
  countNewUsersToday,
  getRecentUsers,
};
