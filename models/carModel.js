const db = require('../config/db');

// Create cars table if it doesn't exist
const createCarsTable = async () => {
    try {
        await db.none(`
            CREATE TABLE IF NOT EXISTS cars (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                brand VARCHAR(100) NOT NULL,
                model VARCHAR(100) NOT NULL,
                year INTEGER NOT NULL,
                price DECIMAL(12,2) NOT NULL,
                location VARCHAR(100) NOT NULL,
                seller VARCHAR(100) NOT NULL,
                image TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('✅ Cars table created or already exists');
    } catch (error) {
        console.error('❌ Error creating cars table:', error);
        throw error;
    }
};

const CarModel = {
    // Create a new car
    async create(carData) {
        const { title, brand, model, year, price, location, seller, image } = carData;
        return db.one(
            `INSERT INTO cars (title, brand, model, year, price, location, seller, image, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
             RETURNING *`,
            [title, brand, model, year, price, location, seller, image]
        );
    },

    // Get all cars
    async findAll() {
        return db.manyOrNone('SELECT * FROM cars ORDER BY created_at DESC');
    },

    // Get a single car by ID
    async findById(id) {
        return db.oneOrNone('SELECT * FROM cars WHERE id = $1', [id]);
    },

    // Update a car
    async update(id, carData) {
        const { title, brand, model, year, price, location, seller, image } = carData;
        return db.oneOrNone(
            `UPDATE cars 
             SET title = $1, brand = $2, model = $3, year = $4, 
                 price = $5, location = $6, seller = $7, image = $8,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = $9
             RETURNING *`,
            [title, brand, model, year, price, location, seller, image, id]
        );
    },

    // Delete a car
    async delete(id) {
        return db.oneOrNone('DELETE FROM cars WHERE id = $1 RETURNING *', [id]);
    }
};

module.exports = { CarModel, createCarsTable }; 