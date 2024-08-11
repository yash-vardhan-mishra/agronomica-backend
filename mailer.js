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

// Function to send OTP email
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
