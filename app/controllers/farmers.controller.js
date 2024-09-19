// farmers.controllers.js
require('dotenv/config')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const connection = require('../models/db')
const mailer = require('../utils/mailer')
const utils = require('../../utils')

const { emailRegex, generateOTP, generateTempPassword, getOtpExpirationTime, passwordRegex } = utils;
const { sendEmployeeCredentials, sendOtpEmail, sendOtpEmailToFarmer } = mailer
const jwtSecret = process.env.FARMER_JWT_SECRET
const jwtConfig = { expiresIn: '7h' };

exports.register = async (req, res) => {
    const { password, email } = req.body;

    // Validate input
    if (!password || !email) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate email format
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate password strength
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            error: 'Password must be at least 8 characters long, include one special character, one number, one uppercase character, and one lowercase character'
        });
    }

    try {
        // Check if the email already exists
        const emailCheckSql = 'SELECT * FROM Farmers WHERE email = ?';
        connection.query(emailCheckSql, [email], async (err, results) => {
            if (err) {
                console.error('Error checking email in database:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            if (results.length > 0) {
                return res.status(409).json({ error: 'Email already exists' });
            }

            // Hash the password
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Generate OTP and set expiration time
            const otp = generateOTP();
            const otpHash = bcrypt.hashSync(otp, 10);
            const otpExpiration = getOtpExpirationTime();
            const createdAt = new Date();

            // Insert the new farmer into the database
            const insertFarmerSql = 'INSERT INTO Farmers (passwordHash, email, otp, otpExpiration, createdAt) VALUES (?, ?, ?, ?, ?)';
            connection.query(insertFarmerSql, [hashedPassword, email, otpHash, otpExpiration, createdAt], (err, result) => {
                if (err) {
                    console.error('Error inserting farmer into database:', err);
                    return res.status(500).json({ error: 'Database error' });
                }

                // Send OTP email
                sendOtpEmail(email, otp)
                    .then(info => {
                        res.status(201).json({ message: 'Farmer registered successfully', farmerId: result.insertId });
                    })
                    .catch(err => {
                        console.error('Error sending email:', err);
                        res.status(500).json({ error: 'Error sending email' });
                    });
            });
        });
    } catch (error) {
        console.error('Error registering farmer:', error);
        res.status(500).json({ error: 'Server error' });
    }
}

exports.resetPassword = (req, res) => {
    const { email } = req.body;

    const otp = generateOTP();
    const otpHash = bcrypt.hashSync(otp, 10);

    const sql = 'UPDATE Farmers SET otp = ? WHERE email = ?';
    connection.query(sql, [otpHash, email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (result.affectedRows === 0) {
            return res.status(400).json({ error: 'Invalid email' });
        }

        sendOtpEmail(email, otp)
            .then(() => {
                res.status(200).json({ message: 'OTP sent successfully' });
            })
            .catch((error) => {
                res.status(500).json({ error: 'Email sending failed' });
            });
    });
}

exports.resetPasswordVerifyOtp = (req, res) => {
    const { email, otp, newPassword } = req.body;

    // Validate password strength
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            error: 'Password must be at least 8 characters long, include one special character, one number, one uppercase character, and one lowercase character'
        });
    }

    const sql = 'SELECT otp FROM Farmers WHERE email = ?';
    connection.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (result.length === 0) {
            return res.status(400).json({ error: 'Invalid email' });
        }

        const otpHash = result[0].otp;

        if (!bcrypt.compareSync(otp, otpHash)) {
            return res.status(400).json({ error: 'Invalid OTP or expired' });
        }

        const newPasswordHash = bcrypt.hashSync(newPassword, 10);
        const updateSql = 'UPDATE Farmers SET passwordHash = ?, otp = NULL WHERE email = ?';
        connection.query(updateSql, [newPasswordHash, email], (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            res.status(200).json({ message: 'Password reset successfully' });
        });
    });
}

exports.verifyOtp = (req, res) => {
    const { email, otp } = req.body;

    // Validate input
    if (!email || !otp) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate email format
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Find the farmer by email
    const findFarmerSql = 'SELECT * FROM Farmers WHERE email = ?';
    connection.query(findFarmerSql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid email or OTP' });
        }

        const farmer = results[0];

        // Check if OTP is expired
        if (new Date() > new Date(farmer.otpExpiration)) {
            return res.status(400).json({ error: 'OTP expired' });
        }

        // Compare OTP
        const otpMatch = await bcrypt.compare(otp, farmer.otp);
        if (!otpMatch) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // Generate JWT token
        const token = jwt.sign({ farmerId: farmer.farmerId }, jwtSecret, jwtConfig);

        // Check if farmer details exist in FarmerInfo
        const findFarmerInfoSql = 'SELECT * FROM FarmerInfo WHERE farmerId = ?';
        connection.query(findFarmerInfoSql, [farmer.farmerId], (err, farmerInfoResults) => {
            if (err) {
                console.error('Error querying the FarmerInfo table:', err);
                return res.status(500).json({ error: 'Server error' });
            }

            let screen = 'profile-creation';
            if (farmerInfoResults.length > 0) {
                const farmerInfo = farmerInfoResults[0];
                if (farmerInfo.firstName && farmerInfo.lastName && farmerInfo.contactNumber) {
                    screen = 'home';
                }
            }

            // Insert or update authToken in FarmerInfo table
            const upsertFarmerTokenSql = `
            INSERT INTO FarmerInfo (farmerId, authToken)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE authToken = VALUES(authToken)
        `;
            connection.query(upsertFarmerTokenSql, [farmer.farmerId, token], (err) => {
                if (err) {
                    console.error('Error updating authToken in FarmerInfo table:', err);
                    return res.status(500).json({ error: 'Server error' });
                }

                // Clear OTP and expiration time from Farmers table
                const removeExpiredOtpsSql = 'UPDATE Farmers SET otp = NULL, otpExpiration = NULL WHERE farmerId = ?';
                connection.query(removeExpiredOtpsSql, [farmer.farmerId], (err) => {
                    if (err) {
                        console.error('Error removing expired OTPs:', err);
                    } else {
                        console.log('Removed expired OTPs');
                    }
                });

                res.status(200).json({ message: 'OTP verified successfully', token, screen, farmerId: farmer.farmerId });
            });
        });
    });
}

exports.login = (req, res) => {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Find the farmer by email
    const findFarmerSql = 'SELECT * FROM Farmers WHERE email = ?';
    connection.query(findFarmerSql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const farmer = results[0];

        // Compare password
        const passwordMatch = await bcrypt.compare(password, farmer.passwordHash);
        if (!passwordMatch) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Generate OTP and set expiration time
        const otp = generateOTP();
        const otpHash = bcrypt.hashSync(otp, 10);
        const otpExpiration = getOtpExpirationTime();

        // Update farmer with OTP and expiration
        const updateFarmerOtpSql = 'UPDATE Farmers SET otp = ?, otpExpiration = ? WHERE farmerId = ?';
        connection.query(updateFarmerOtpSql, [otpHash, otpExpiration, farmer.farmerId], async (err) => {
            if (err) {
                console.error('Error updating OTP in database:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Send OTP email
            try {
                await sendOtpEmail(email, otp);
                res.status(200).json({ message: 'Farmer logged in successfully, OTP sent' });
            } catch (err) {
                console.error('Error sending email:', err);
                res.status(500).json({ error: 'Error sending email' });
            }
        });
    });
}

exports.updateInfo = (req, res) => {
    const { farmerId, firstName, lastName, contactNumber } = req.body;

    // Validate input
    if (!farmerId || !firstName || !lastName || !contactNumber) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate contact number format (NZ and Australia)
    const contactNumberRegex = /^(\+?64|0)[2-9]\d{7,9}$|^(\+?61|0)[2-9]\d{8,9}$/;
    if (!contactNumberRegex.test(contactNumber)) {
        return res.status(400).json({ error: 'Invalid contact number format' });
    }

    // Check if the contact number already exists
    const checkContactNumberSql = 'SELECT * FROM FarmerInfo WHERE contactNumber = ? AND farmerId != ?';
    connection.query(checkContactNumberSql, [contactNumber, farmerId], (err, results) => {
        if (err) {
            console.error('Error checking contact number in database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(409).json({ error: 'Contact number already exists' });
        }

        // Update farmer information
        const updateFarmerInfoSql = `
            UPDATE FarmerInfo
            SET firstName = ?, lastName = ?, contactNumber = ?
            WHERE farmerId = ?
        `;
        connection.query(updateFarmerInfoSql, [firstName, lastName, contactNumber, farmerId], (err, results) => {
            if (err) {
                console.error('Error updating farmer information:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            if (results.affectedRows === 0) {
                return res.status(404).json({ error: 'Farmer not found' });
            }

            res.status(200).json({ message: 'Farmer information updated successfully' });
        });
    });
}

exports.getInfo = (req, res) => {
    const { farmerId } = req.query;

    if (!farmerId) {
        return res.status(400).json({ error: 'farmerId is required' });
    }

    const getFarmerInfoSql = 'SELECT firstName, lastName, contactNumber FROM FarmerInfo WHERE farmerId = ?';
    connection.query(getFarmerInfoSql, [farmerId], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Farmer not found' });
        }

        const farmerInfo = results[0];
        res.status(200).json(farmerInfo);
    });
}

exports.addField = (req, res) => {
    const { farmerId, fieldName, fieldAddress, size, cropType } = req.body;

    // Validate input
    if (!farmerId || !fieldName || !fieldAddress || !size) {
        return res.status(400).json({ error: 'Invalid input' });
    }
    console.log('this happened');


    // Check if field name already exists for the farmer
    const checkFieldNameSql = 'SELECT * FROM Fields WHERE farmerId = ? AND fieldName = ?';
    connection.query(checkFieldNameSql, [farmerId, fieldName], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(400).json({ error: 'Field name already exists for this farmer' });
        }

        // Insert new field if name is unique for the farmer
        const addFieldSql = 'INSERT INTO Fields (farmerId, fieldName, fieldAddress, size, cropType) VALUES (?, ?, ?, ?, ?)';
        const fieldValues = [farmerId, fieldName, fieldAddress, size, cropType || null];

        connection.query(addFieldSql, fieldValues, (err, results) => {
            if (err) {
                console.error('Error inserting into the database:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            res.status(201).json({ message: 'Field added successfully' });
        });
    });
}

exports.onboardEmployee = (req, res) => {
    const { employeeEmail, employeeRole } = req.body;
    const farmerId = req.user.farmerId;

    // Validate email format
    if (!emailRegex.test(employeeEmail)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    if (!employeeEmail || !employeeRole || !['supervisor', 'worker'].includes(employeeRole)) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    // Generate OTP and its hash
    const otp = generateOTP();
    const otpHash = bcrypt.hashSync(otp, 10);
    const otpExpiration = getOtpExpirationTime();

    // Retrieve the farmer's email using the farmerId
    const getFarmerEmailSql = 'SELECT email FROM Farmers WHERE farmerId = ?';
    connection.query(getFarmerEmailSql, [farmerId], async (err, results) => {
        if (err) {
            console.error('Error retrieving farmer email:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Farmer not found' });
        }

        const farmerEmail = results[0].email;

        // Store OTP and expiration time for the farmer
        const updateFarmerOtpSql = 'UPDATE Farmers SET otp = ?, otpExpiration = ? WHERE farmerId = ?';
        connection.query(updateFarmerOtpSql, [otpHash, otpExpiration, farmerId], async (err) => {
            if (err) {
                console.error('Error updating OTP in database:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Send OTP email to the farmer
            try {
                await sendOtpEmailToFarmer(farmerEmail, otp, employeeEmail);
                res.status(200).json({ message: 'OTP sent to farmer\'s email for confirmation' });
            } catch (err) {
                console.error('Error sending OTP email:', err);
                res.status(500).json({ error: 'Error sending OTP email' });
            }
        });
    });
}

exports.onboardEmployeeVerifyOtp =  async (req, res) => {
    const { otp, employeeEmail, employeeRole } = req.body;
    const farmerId = req.user.farmerId;

    if (!otp || !employeeEmail || !employeeRole || !['supervisor', 'worker'].includes(employeeRole)) {
        return res.status(400).json({ error: 'Invalid input' });
    }

    // Retrieve farmer's OTP and expiration
    const getFarmerOtpSql = 'SELECT otp, otpExpiration FROM Farmers WHERE farmerId = ?';
    connection.query(getFarmerOtpSql, [farmerId], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0 || !bcrypt.compareSync(otp, results[0].otp) || new Date() > new Date(results[0].otpExpiration)) {
            return res.status(404).json({ error: 'OTP not found or expired' });
        }

        // Generate temporary credentials for the employee
        const employeePassword = generateTempPassword();
        const hashedPassword = await bcrypt.hash(employeePassword, 10);

        // Insert new employee into the database
        const insertEmployeeSql = 'INSERT INTO Employees (farmerId, employeeRole, email, passwordHash) VALUES (?, ?, ?, ?)';
        connection.query(insertEmployeeSql, [farmerId, employeeRole, employeeEmail, hashedPassword], async (err, result) => {
            if (err) {
                console.error('Error inserting employee into database:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            const employeeId = result.insertId;

            // Send credentials to the employee
            try {
                await sendEmployeeCredentials(employeeEmail, employeeId, employeePassword);
                res.status(200).json({ message: 'Employee onboarded successfully' });
            } catch (err) {
                console.error('Error sending employee email:', err);
                res.status(500).json({ error: 'Error sending employee email' });
            }
        });
    });
}