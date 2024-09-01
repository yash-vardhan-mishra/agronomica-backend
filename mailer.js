// mailer.js
import 'dotenv/config'
import nodemailer from 'nodemailer'

// Create a Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: process.env.MAILER_SERVICE, // Use your email service
    auth: {
        user: process.env.MAILER_USER, // Replace with your email
        pass: process.env.MAILER_PASS  // Replace with your email password or app-specific password
    }
});

/**
 * Sends an OTP email to a specified address.
 *
 * This function sends an email containing an OTP (One-Time Password) to the given recipient's email address.
 * It uses a configured mail transporter to send the email and returns a promise that resolves when the email is sent
 * successfully or rejects if there is an error.
 *
 * @param {string} email - The recipient's email address to which the OTP should be sent.
 * @param {string} otp - The OTP code to include in the email.
 * @returns {Promise} - A promise that resolves with the result of the email sending operation or rejects with an error.
 *
 * @example
 * sendOtpEmail('user@example.com', '123456')
 *   .then(info => {
 *     console.log('OTP email sent:', info);
 *   })
 *   .catch(err => {
 *     console.error('Error sending OTP email:', err);
 *   });
 */
export const sendOtpEmail = (email, otp) => {
    const mailOptions = {
        from: `"Agronomica 🌾🐄🚜" <${process.env.MAILER_USER}>`, // Replace with your email
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`
    };

    return new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return reject(err);
            }
            resolve(info);
        });
    });
};


/**
 * Function to send OTP email to farmer for employee onboarding
 * @param {string} farmerEmail - The email of the farmer
 * @param {string} otp - The OTP code
 * @param {string} employeeEmail - The email of the employee to be onboarded
 * @returns {Promise} - A promise that resolves when the email is sent
 */
export const sendOtpEmailToFarmer = (farmerEmail, otp, employeeEmail) => {
    console.log('sendOtpEmailToFarmer params',farmerEmail, otp, employeeEmail);
    
    const mailOptions = {
        from: `"Agronomica 🌾🐄🚜" <${process.env.MAILER_USER}>`, // Replace with your email
        to: farmerEmail,
        subject: 'Confirm Employee Onboarding',
        text: `Are you sure you want to onboard the employee with email ID ${employeeEmail}? 
        Your OTP code for confirmation is ${otp}.`
    };

    return new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return reject(err);
            }
            resolve(info);
        });
    });
};


/**
 * Sends the employee's temporary login credentials via email.
 *
 * This function sends an email to the new employee with their temporary password and employee ID.
 *
 * @param {string} email - The employee's email address.
 * @param {string} employeeId - The employee's ID.
 * @param {string} tempPassword - The temporary password to include in the email.
 * @returns {Promise} - A promise that resolves with the result of the email sending operation or rejects with an error.
 *
 * @example
 * sendEmployeeCredentials('employee@example.com', 'E123', 'TempP@ss123')
 *   .then(info => {
 *     console.log('Employee credentials sent:', info);
 *   })
 *   .catch(err => {
 *     console.error('Error sending employee credentials:', err);
 *   });
 */
export const sendEmployeeCredentials = (email, employeeId, tempPassword) => {
    const mailOptions = {
        from: `"Agronomica 🌾🐄🚜" <${process.env.MAILER_USER}>`,
        to: email,
        subject: 'Your Temporary Login Credentials',
        text: `Your employee ID is ${employeeId} and your temporary password is ${tempPassword}. Please log in and change your password immediately.`
    };

    return new Promise((resolve, reject) => {
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return reject(err);
            }
            resolve(info);
        });
    });
};