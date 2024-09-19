// employees.controller.js
require('dotenv/config')
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mailer = require('../utils/mailer');
const utils = require('../../utils');
const connection = require('../models/db');

const { generateOTP, passwordRegex } = utils
const { sendOtpEmail } = mailer

const jwtSecret = process.env.EMPLOYEE_JWT_SECRET
const jwtConfig = { expiresIn: '7h' };

exports.login = (req, res) => {
    const { employeeId, password } = req.body;

    if (!employeeId || !password) {
        return res.status(400).json({ success: false, error: 'employeeId and password are required' });
    }

    // Check if the employee exists
    const getEmployeeSql = 'SELECT * FROM Employees WHERE employeeId = ?';
    connection.query(getEmployeeSql, [employeeId], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ success: false, error: 'Invalid employeeId or password' });
        }

        const employee = results[0];

        // Check the password
        const passwordMatch = await bcrypt.compare(password, employee.passwordHash);
        if (!passwordMatch) {
            return res.status(400).json({ success: false, error: 'Invalid employeeId or password' });
        }

        // Generate OTP and send it to the employee's email
        const otp = generateOTP();
        const otpHash = bcrypt.hashSync(otp, 10);
        const otpExpiration = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes expiration

        // Update OTP in database
        const updateOtpSql = 'UPDATE Employees SET otp = ?, otpExpiration = ? WHERE employeeId = ?';
        connection.query(updateOtpSql, [otpHash, otpExpiration, employeeId], (err) => {
            if (err) {
                console.error('Error updating OTP in database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            // Send OTP email
            sendOtpEmail(employee.email, otp)
                .then(() => {
                    res.status(200).json({
                        success: true,
                        screen: employee.isPasswordChanged ? 'verify-otp' : 'change-password',
                        message: 'OTP has been sent to your email. Please verify to continue.'
                    });
                })
                .catch(err => {
                    console.error('Error sending OTP email:', err);
                    res.status(500).json({ success: false, error: 'Error sending OTP email' });
                });
        });
    });
}

exports.changePassword = async (req, res) => {
    const { employeeId, tempPassword, newPassword, otp } = req.body;

    if (!employeeId || !tempPassword || !newPassword || !otp) {
        return res.status(400).json({ success: false, error: 'All fields are required' });
    }

    // Validate new password format
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({ success: false, error: 'New password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character' });
    }

    // Check if the employee exists and the OTP is valid
    const getEmployeeSql = 'SELECT * FROM Employees WHERE employeeId = ?';
    connection.query(getEmployeeSql, [employeeId], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ success: false, error: 'Invalid employeeId' });
        }

        const employee = results[0];

        // Verify OTP
        const otpMatch = await bcrypt.compare(otp, employee.otp);
        if (!otpMatch || new Date() > new Date(employee.otpExpiration)) {
            return res.status(400).json({ success: false, error: 'Invalid or expired OTP' });
        }

        // Hash the new password
        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

        // Generate a new auth token
        const authToken = jwt.sign({ employeeId: employee.employeeId }, jwtSecret, jwtConfig);

        // Update the employee with the new password, clear OTP, and set passwordChanged flag
        const updatePasswordSql = 'UPDATE Employees SET passwordHash = ?, otp = NULL, otpExpiration = NULL, isPasswordChanged = TRUE WHERE employeeId = ?';
        connection.query(updatePasswordSql, [hashedNewPassword, employeeId], (err) => {
            if (err) {
                console.error('Error updating password in database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            // Update EmployeeInfo with authToken
            const updateEmployeeInfoSql = 'UPDATE EmployeeInfo SET authToken = ? WHERE employeeId = ?';
            connection.query(updateEmployeeInfoSql, [authToken, employeeId], (err) => {
                if (err) {
                    console.error('Error updating authToken in database:', err);
                    return res.status(500).json({ success: false, error: 'Database error' });
                }

                res.status(200).json({
                    success: true,
                    message: 'Password changed successfully',
                    authToken
                });
            });
        });
    });
}

exports.verifyOtp = async (req, res) => {
    const { employeeId, otp } = req.body;

    if (!employeeId || !otp) {
        return res.status(400).json({ success: false, error: 'Employee ID and OTP are required' });
    }

    // Fetch the stored OTP and expiration time from the database
    const fetchOtpSql = 'SELECT otp, otpExpiration FROM Employees WHERE employeeId = ?';
    connection.query(fetchOtpSql, [employeeId], async (err, results) => {
        if (err) {
            console.error('Error querying OTP in database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Employee not found' });
        }

        const { otp: storedOtp, otpExpiration } = results[0];

        // Check if the OTP is expired
        if (new Date() > new Date(otpExpiration)) {
            return res.status(400).json({ success: false, error: 'OTP has expired' });
        }

        // Verify the OTP
        const isOtpValid = await bcrypt.compare(otp, storedOtp);
        if (!isOtpValid) {
            return res.status(400).json({ success: false, error: 'Invalid OTP' });
        }

        // Generate auth token
        const authToken = jwt.sign({ employeeId: employeeId }, jwtSecret, jwtConfig);

        // Update employee record to remove OTP and set other flags if necessary
        const updateEmployeeSql = 'UPDATE Employees SET otp = NULL, otpExpiration = NULL WHERE employeeId = ?';
        connection.query(updateEmployeeSql, [employeeId], (err) => {
            if (err) {
                console.error('Error updating OTP status in database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            res.status(200).json({ success: true, message: 'OTP verified successfully', authToken, employeeId });
        });
    });
};
