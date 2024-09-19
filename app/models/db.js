// db.js
require('dotenv/config')
const sql = require('mysql2')

// Create a connection to the database
const connection = sql.createConnection({
    host: process.env.DB_HOST,      
    user: process.env.DB_USER,  
    password: process.env.DB_PASS, 
    database: process.env.DB_NAME
});

// Connect to the database
connection.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err.stack);
        return;
    }
    console.log('Connected to the database as id ' + connection.threadId);
});

module.exports = connection;