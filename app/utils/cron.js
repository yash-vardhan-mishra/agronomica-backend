// cron.js
const cron = require('node-cron')
const connection = require('../models/db.js');

// Schedule a job to run every minute
cron.schedule('* * * * *', () => {

    const now = new Date();
    const removeExpiredOtpsSqlEmployees = 'UPDATE Employees SET otp = NULL, otpExpiration = NULL WHERE otpExpiration < ?';
    const removeExpiredOtpsSqlFarmers = 'UPDATE Farmers SET otp = NULL, otpExpiration = NULL WHERE otpExpiration < ?';

    // Execute the query for Employees
    connection.query(removeExpiredOtpsSqlEmployees, [now], (err, results) => {
        if (err) {
            console.error('Error updating expired OTPs in Employees table:', err);
        } else {
            console.log('Expired OTPs updated in Employees table:', results.affectedRows);
        }
    });

    // Execute the query for Farmers
    connection.query(removeExpiredOtpsSqlFarmers, [now], (err, results) => {
        if (err) {
            console.error('Error updating expired OTPs in Farmers table:', err);
        } else {
            console.log('Expired OTPs updated in Farmers table:', results.affectedRows);
        }
    });
});