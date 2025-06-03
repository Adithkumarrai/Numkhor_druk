const db = require('../config/db');

// Create messages table
async function createMessageTable() {
    const query = `
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_read BOOLEAN DEFAULT FALSE
        );
    `;
    try {
        await db.none(query);
        console.log('✅ Messages table created or already exists');
    } catch (error) {
        console.error('❌ Error creating messages table:', error);
        throw error;
    }
}

// Save new message
async function saveMessage({ name, email, message }) {
    try {
        const result = await db.one(
            `INSERT INTO messages (name, email, message)
             VALUES ($1, $2, $3)
             RETURNING *`,
            [name, email, message]
        );
        return result;
    } catch (error) {
        console.error('❌ Error saving message:', error);
        throw error;
    }
}

// Get all messages
async function getAllMessages() {
    try {
        const messages = await db.any(
            `SELECT * FROM messages 
             ORDER BY created_at DESC`
        );
        return messages;
    } catch (error) {
        console.error('❌ Error fetching messages:', error);
        return [];
    }
}

// Mark message as read
async function markAsRead(messageId) {
    try {
        await db.none(
            `UPDATE messages 
             SET is_read = true 
             WHERE id = $1`,
            [messageId]
        );
        return true;
    } catch (error) {
        console.error('❌ Error marking message as read:', error);
        return false;
    }
}

// Get unread messages count
async function getUnreadCount() {
    try {
        const result = await db.one(
            `SELECT COUNT(*) as count 
             FROM messages 
             WHERE is_read = false`
        );
        return parseInt(result.count);
    } catch (error) {
        console.error('❌ Error counting unread messages:', error);
        return 0;
    }
}

module.exports = {
    createMessageTable,
    saveMessage,
    getAllMessages,
    markAsRead,
    getUnreadCount
}; 