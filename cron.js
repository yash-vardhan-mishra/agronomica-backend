// cron.js
import cron from 'node-cron';
import connection from './db.js';

// Schedule a job to run every minute
cron.schedule('* * * * *', () => {
    console.log('Running a task every minute to remove expired OTPs');

    const now = new Date();
    const removeExpiredOtpsSql = 'UPDATE Users SET otp = NULL, otpExpiration = NULL WHERE otpExpiration < ?';

    connection.query(removeExpiredOtpsSql, [now], (err, results) => {
        if (err) {
            console.error('Error removing expired OTPs:', err);
        } else {
            console.log(`Removed ${results.affectedRows} expired OTPs`);
        }
    });
});