// farmers.controllers.js
require('dotenv/config')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const connection = require('../models/db')
const mailer = require('../utils/mailer')
const utils = require('../../utils')
const uuid = require('uuid')

const { emailRegex, generateOTP, generateTempPassword, getOtpExpirationTime, passwordRegex } = utils;
const { sendEmployeeCredentials, sendOtpEmail, sendOtpEmailToFarmer } = mailer
const jwtSecret = process.env.FARMER_JWT_SECRET
const jwtConfig = { expiresIn: '7d' };

exports.register = async (req, res) => {
    const { password, email } = req.body;

    // Validate input
    if (!password || !email) {
        return res.status(400).json({ success: false, error: 'All fields are required' });
    }

    // Validate email format
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, error: 'Invalid email format' });
    }

    // Validate password strength
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            success: false,
            error: 'Password must be at least 8 characters long, include one special character, one number, one uppercase character, and one lowercase character'
        });
    }

    try {
        // Check if the email already exists
        const emailCheckSql = 'SELECT * FROM Farmers WHERE email = ?';
        connection.query(emailCheckSql, [email], async (err, results) => {
            if (err) {
                console.error('Error checking email in database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }
            if (results.length > 0) {
                return res.status(409).json({ success: false, error: 'Email already exists' });
            }

            // Hash the password
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Generate OTP and set expiration time
            const otp = generateOTP();
            const otpHash = bcrypt.hashSync(otp, 10);
            const otpExpiration = getOtpExpirationTime();
            const createdAt = new Date();

            // Generate farmerId
            const farmerId = uuid.v4();

            // Insert the new farmer into the database
            const insertFarmerSql = 'INSERT INTO Farmers (farmerId, passwordHash, email, otp, otpExpiration, createdAt) VALUES (?, ?, ?, ?, ?, ?)';
            connection.query(insertFarmerSql, [farmerId, hashedPassword, email, otpHash, otpExpiration, createdAt], (err, result) => {
                if (err) {
                    console.error('Error inserting farmer into database:', err);
                    return res.status(500).json({ success: false, error: 'Database error' });
                }

                // Send OTP email
                sendOtpEmail(email, otp)
                    .then(info => {
                        res.status(201).json({ success: true, message: 'Farmer registered successfully' });
                    })
                    .catch(err => {
                        console.error('Error sending email:', err);
                        res.status(500).json({ success: false, error: 'Error sending email' });
                    });
            });
        });
    } catch (error) {
        console.error('Error registering farmer:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
}

exports.resetPassword = (req, res) => {
    const { email } = req.body;

    const otp = generateOTP();
    const otpHash = bcrypt.hashSync(otp, 10);

    const sql = 'UPDATE Farmers SET otp = ? WHERE email = ?';
    connection.query(sql, [otpHash, email], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (result.affectedRows === 0) {
            return res.status(400).json({ success: false, error: 'Invalid email' });
        }

        sendOtpEmail(email, otp)
            .then(() => {
                res.status(200).json({ success: true, message: 'OTP sent successfully' });
            })
            .catch((error) => {
                res.status(500).json({ success: false, error: 'Email sending failed' });
            });
    });
}

exports.resetPasswordVerifyOtp = (req, res) => {
    const { email, otp, newPassword } = req.body;

    // Validate password strength
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({
            success: false,
            error: 'Password must be at least 8 characters long, include one special character, one number, one uppercase character, and one lowercase character'
        });
    }

    const sql = 'SELECT otp FROM Farmers WHERE email = ?';
    connection.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (result.length === 0) {
            return res.status(400).json({ success: false, error: 'Invalid email' });
        }

        const otpHash = result[0].otp;

        if (!bcrypt.compareSync(otp, otpHash)) {
            return res.status(400).json({ success: false, error: 'Invalid OTP or expired' });
        }

        const newPasswordHash = bcrypt.hashSync(newPassword, 10);
        const updateSql = 'UPDATE Farmers SET passwordHash = ?, otp = NULL WHERE email = ?';
        connection.query(updateSql, [newPasswordHash, email], (err, result) => {
            if (err) {
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            res.status(200).json({ success: true, message: 'Password reset successfully' });
        });
    });
}

exports.verifyOtp = (req, res) => {
    const { email, otp } = req.body;

    // Validate input
    if (!email || !otp) {
        return res.status(400).json({ success: false, error: 'All fields are required' });
    }

    // Validate email format
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, error: 'Invalid email format' });
    }

    // Find the farmer by email
    const findFarmerSql = 'SELECT * FROM Farmers WHERE email = ?';
    connection.query(findFarmerSql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ success: false, error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ success: false, error: 'Invalid email or OTP' });
        }

        const farmer = results[0];

        // Check if OTP is expired
        if (new Date() > new Date(farmer.otpExpiration)) {
            return res.status(400).json({ success: false, error: 'OTP expired' });
        }

        // Compare OTP
        const otpMatch = await bcrypt.compare(otp, farmer.otp);
        if (!otpMatch) {
            return res.status(400).json({ success: false, error: 'Invalid OTP' });
        }

        // Generate JWT token
        const token = jwt.sign({ farmerId: farmer.farmerId }, jwtSecret, jwtConfig);

        // Check if farmer details exist in FarmerInfo
        const findFarmerInfoSql = 'SELECT * FROM FarmerInfo WHERE farmerId = ?';
        connection.query(findFarmerInfoSql, [farmer.farmerId], (err, farmerInfoResults) => {
            if (err) {
                console.error('Error querying the FarmerInfo table:', err);
                return res.status(500).json({ success: false, error: 'Server error' });
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
                    return res.status(500).json({ success: false, error: 'Server error' });
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

                res.status(200).json({ success: true, message: 'OTP verified successfully', token, screen });
            });
        });
    });
}

exports.login = (req, res) => {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'All fields are required' });
    }

    // Find the farmer by email
    const findFarmerSql = 'SELECT * FROM Farmers WHERE email = ?';
    connection.query(findFarmerSql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ success: false, error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ success: false, error: 'Invalid email or password' });
        }

        const farmer = results[0];

        // Compare password
        const passwordMatch = await bcrypt.compare(password, farmer.passwordHash);
        if (!passwordMatch) {
            return res.status(400).json({ success: false, error: 'Invalid email or password' });
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
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            // Send OTP email
            try {
                await sendOtpEmail(email, otp);
                res.status(200).json({ success: true, message: 'Farmer logged in successfully, OTP sent' });
            } catch (err) {
                console.error('Error sending email:', err);
                res.status(500).json({ success: false, error: 'Error sending email' });
            }
        });
    });
}

exports.updateInfo = (req, res) => {
    // Get the authorization header and extract the token
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    // Validate that the authToken exists
    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';
    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error fetching farmerId from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Invalid authToken or farmer not found' });
        }

        // Get the farmerId from the results
        const farmerId = results[0].farmerId;

        // Get the other details from the request body
        const { firstName, lastName, contactNumber } = req.body;

        // Validate input
        if (!firstName || !lastName || !contactNumber) {
            return res.status(400).json({ success: false, error: 'All fields are required' });
        }

        // Validate contact number format (NZ and Australia)
        const contactNumberRegex = /^(\+?64|0)[2-9]\d{7,9}$|^(\+?61|0)[2-9]\d{8,9}$/;
        if (!contactNumberRegex.test(contactNumber)) {
            return res.status(400).json({ success: false, error: 'Invalid contact number format' });
        }

        // Check if the contact number already exists
        const checkContactNumberSql = 'SELECT * FROM FarmerInfo WHERE contactNumber = ? AND farmerId != ?';
        connection.query(checkContactNumberSql, [contactNumber, farmerId], (err, results) => {
            if (err) {
                console.error('Error checking contact number in database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            if (results.length > 0) {
                return res.status(409).json({ success: false, error: 'Contact number already exists' });
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
                    return res.status(500).json({ success: false, error: 'Database error' });
                }

                if (results.affectedRows === 0) {
                    return res.status(404).json({ success: false, error: 'Farmer not found' });
                }

                res.status(200).json({ success: true, message: 'Farmer information updated successfully' });
            });
        });
    });
};


exports.getInfo = (req, res) => {
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';

    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Farmer not found' });
        }

        const { farmerId } = results[0];

        // Query to get farmer information based on the retrieved farmerId
        const getFarmerInfoSql = 'SELECT firstName, lastName, contactNumber FROM FarmerInfo WHERE farmerId = ?';
        connection.query(getFarmerInfoSql, [farmerId], (err, results) => {
            if (err) {
                console.error('Error querying the database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            if (results.length === 0) {
                return res.status(404).json({ success: false, error: 'Farmer not found' });
            }

            const farmerInfo = results[0];
            res.status(200).json({ ...farmerInfo, success: true });
        });
    });
};

exports.addField = (req, res) => {
    // Get the authorization header and extract the token
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    // Validate that the authToken exists
    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';
    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error fetching farmerId from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Invalid authToken or farmer not found' });
        }

        // Get the farmerId from the results
        const farmerId = results[0].farmerId;

        // Get the field details from the request body
        const { fieldName, fieldAddress, size, fieldType, fieldLat, fieldLong } = req.body;

        // Validate input
        if (!fieldName || !fieldAddress || !size || !fieldType || !fieldLat || !fieldLong) {
            return res.status(400).json({
                success: false,
                error: 'Invalid input. All fields (fieldName, fieldAddress, size, fieldType, fieldLat, and fieldLong) are required.'
            });
        }

        // Validate field size
        if (isNaN(size) || size <= 0) {
            return res.status(400).json({ success: false, error: 'Invalid size value' });
        }

        // Validate latitude and longitude with more precise regex (up to 14 decimal places)
        const latLongRegex = /^-?\d{1,3}\.\d{1,14}$/;  // Allows up to 14 decimal places
        if (!latLongRegex.test(fieldLat) || !latLongRegex.test(fieldLong)) {
            return res.status(400).json({ success: false, error: 'Invalid latitude or longitude format' });
        }

        // Check if field name already exists for the farmer
        const checkFieldNameSql = 'SELECT * FROM Fields WHERE farmerId = ? AND fieldName = ?';
        connection.query(checkFieldNameSql, [farmerId, fieldName], (err, results) => {
            if (err) {
                console.error('Error querying the database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            if (results.length > 0) {
                return res.status(400).json({ success: false, error: 'Field name already exists for this farmer' });
            }

            // Generate a UUID for fieldId
            const fieldId = uuid.v4();

            // Insert new field if name is unique for the farmer
            const addFieldSql = `
                INSERT INTO Fields (fieldId, farmerId, fieldName, fieldAddress, size, fieldType, fieldLat, fieldLong)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `;
            const fieldValues = [
                fieldId,
                farmerId,
                fieldName,
                fieldAddress,
                size,
                fieldType,
                fieldLat,
                fieldLong
            ];

            connection.query(addFieldSql, fieldValues, (err, results) => {
                if (err) {
                    console.error('Error inserting into the database:', err);
                    return res.status(500).json({ success: false, error: 'Database error' });
                }

                res.status(201).json({ success: true, message: 'Field added successfully' });
            });
        });
    });
};

exports.onboardEmployee = (req, res) => {
    // Get the authorization header and extract the token
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    // Validate that the authToken exists
    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';
    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error fetching farmerId from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Invalid authToken or farmer not found' });
        }

        // Get the farmerId from the results
        const farmerId = results[0].farmerId;

        const { employeeEmail, employeeRole, firstName, lastName, contactNumber, fieldId } = req.body;

        const contactNumberRegex = /^(\+?64|0)[2-9]\d{7,9}$|^(\+?61|0)[2-9]\d{8,9}$/;
        if (!contactNumberRegex.test(contactNumber)) {
            return res.status(400).json({ success: false, error: 'Invalid contact number format' });
        }

        // Validate email format
        if (!emailRegex.test(employeeEmail)) {
            return res.status(400).json({ success: false, error: 'Invalid email format' });
        }

        if (!employeeEmail || !employeeRole || !firstName || !lastName || !contactNumber || !fieldId ||
            !['supervisor', 'worker'].includes(employeeRole)) {
            return res.status(400).json({ success: false, error: 'Invalid input' });
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
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            if (results.length === 0) {
                return res.status(404).json({ success: false, error: 'Farmer not found' });
            }

            const farmerEmail = results[0].email;

            // Store OTP and expiration time for the farmer
            const updateFarmerOtpSql = 'UPDATE Farmers SET otp = ?, otpExpiration = ? WHERE farmerId = ?';
            connection.query(updateFarmerOtpSql, [otpHash, otpExpiration, farmerId], async (err) => {
                if (err) {
                    console.error('Error updating OTP in database:', err);
                    return res.status(500).json({ success: false, error: 'Database error' });
                }

                // Send OTP email to the farmer
                try {
                    await sendOtpEmailToFarmer(farmerEmail, otp, employeeEmail);
                    res.status(200).json({ success: true, message: 'OTP sent to farmer\'s email for confirmation' });
                } catch (err) {
                    console.error('Error sending OTP email:', err);
                    res.status(500).json({ success: false, error: 'Error sending OTP email' });
                }
            });
        });
    });
};

exports.onboardEmployeeVerifyOtp = async (req, res) => {
    const { otp, employeeEmail, employeeRole, firstName, lastName, contactNumber, fieldId } = req.body;

    // Get the authorization header and extract the token
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    // Validate that the authToken exists
    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';
    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error fetching farmerId from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Invalid authToken or farmer not found' });
        }

        const farmerId = results[0].farmerId;

        // Validate input
        if (!otp || !employeeEmail || !employeeRole || !['supervisor', 'worker'].includes(employeeRole) ||
            !firstName || !lastName || !contactNumber || !fieldId) {
            return res.status(400).json({ success: false, error: 'Invalid input' });
        }

        // Retrieve farmer's OTP and expiration
        const getFarmerOtpSql = 'SELECT otp, otpExpiration FROM Farmers WHERE farmerId = ?';
        connection.query(getFarmerOtpSql, [farmerId], async (err, results) => {
            if (err) {
                console.error('Error querying the database:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            if (results.length === 0 || !bcrypt.compareSync(otp, results[0].otp) || new Date() > new Date(results[0].otpExpiration)) {
                return res.status(404).json({ success: false, error: 'OTP not found or expired' });
            }

            // Generate temporary credentials for the employee
            const employeePassword = generateTempPassword();
            const hashedPassword = await bcrypt.hash(employeePassword, 10);

            // Generate employeeId
            const employeeId = uuid.v4();

            // Insert new employee into the database, including fieldId
            const insertEmployeeSql = `
                INSERT INTO Employees (employeeId, farmerId, fieldId, employeeRole, email, passwordHash, firstName, lastName, contactNumber) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `;
            connection.query(insertEmployeeSql, [employeeId, farmerId, fieldId, employeeRole, employeeEmail, hashedPassword, firstName, lastName, contactNumber], async (err, result) => {
                if (err) {
                    console.error('Error inserting employee into database:', err);
                    return res.status(500).json({ success: false, error: 'Database error' });
                }

                // Send credentials to the employee
                try {
                    await sendEmployeeCredentials(employeeEmail, employeePassword);
                    res.status(200).json({ success: true, message: 'Employee onboarded successfully' });
                } catch (err) {
                    console.error('Error sending employee email:', err);
                    res.status(500).json({ success: false, error: 'Error sending employee email' });
                }
            });
        });
    });
};

exports.getFieldTypes = (req, res) => {
    // Query to get all field types from the FieldTypes table
    const getFieldTypesSql = 'SELECT typeId, fieldType FROM FieldTypes';

    // Execute the query
    connection.query(getFieldTypesSql, (err, results) => {
        if (err) {
            console.error('Error fetching field types from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        // Return the field types as JSON response
        res.status(200).json({ success: true, fieldTypes: results });
    });
};

exports.getFields = (req, res) => {
    // Get the authorization header and extract the token
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    // Validate that the authToken exists
    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';
    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error fetching farmerId from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Invalid authToken or farmer not found' });
        }

        const farmerId = results[0].farmerId;

        // SQL query to get the fields associated with this farmer
        const sqlQuery = `
            SELECT 
                f.fieldId, 
                f.fieldName, 
                f.fieldAddress, 
                f.size, 
                f.fieldType,  -- Changed from ft.fieldType to f.fieldType
                f.fieldLat, 
                f.fieldLong
            FROM 
                Fields f
            WHERE 
                f.farmerId = ?;
        `;

        // Execute the query
        connection.query(sqlQuery, [farmerId], (err, results) => {
            if (err) {
                console.error('Error fetching fields:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            // Return the results
            res.status(200).json({
                success: true,
                data: results
            });
        });
    });
};


exports.getEmployees = (req, res) => {
    // Get the authorization header and extract the token
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    // Validate that the authToken exists
    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';
    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error fetching farmerId from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Invalid authToken or farmer not found' });
        }

        const farmerId = results[0].farmerId;

        // SQL query to get the employees along with fieldType
        const sqlQuery = `
            SELECT 
                e.employeeId,
                e.fieldId,
                f.fieldType,
                e.employeeRole,
                e.email,
                e.firstName,
                e.lastName,
                e.contactNumber,
                e.createdAt,
                e.isPasswordChanged
            FROM 
                Employees e
            JOIN
                Fields f ON e.fieldId = f.fieldId  -- Join Fields table to get fieldType
            WHERE 
                e.farmerId = ?;
        `;

        // Execute the query
        connection.query(sqlQuery, [farmerId], (err, results) => {
            if (err) {
                console.error('Error fetching employees:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            // Return the results
            res.status(200).json({
                success: true,
                data: results
            });
        });
    });
};

exports.getEmployeeById = (req, res) => {
    const { employeeId } = req.params;

    // Get the authorization header and extract the token
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(' ')[1];

    // Validate that the authToken exists
    if (!authToken) {
        return res.status(400).json({ success: false, error: 'authToken is required' });
    }

    // Query to get farmerId from the authToken
    const getFarmerIdSql = 'SELECT farmerId FROM FarmerInfo WHERE authToken = ?';
    connection.query(getFarmerIdSql, [authToken], (err, results) => {
        if (err) {
            console.error('Error fetching farmerId from database:', err);
            return res.status(500).json({ success: false, error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ success: false, error: 'Invalid authToken or farmer not found' });
        }

        const farmerId = results[0].farmerId;

        // SQL query to get the employee details by employeeId and farmerId along with fieldType
        const sqlQuery = `
            SELECT 
                e.employeeId,
                e.fieldId,
                f.fieldType,
                e.employeeRole,
                e.email,
                e.firstName,
                e.lastName,
                e.contactNumber,
                e.createdAt,
                e.isPasswordChanged
            FROM 
                Employees e
            JOIN
                Fields f ON e.fieldId = f.fieldId
            WHERE 
                e.employeeId = ? AND e.farmerId = ?;
        `;

        // Execute the query
        connection.query(sqlQuery, [employeeId, farmerId], (err, results) => {
            if (err) {
                console.error('Error fetching employee details:', err);
                return res.status(500).json({ success: false, error: 'Database error' });
            }

            if (results.length === 0) {
                return res.status(404).json({ success: false, error: 'Employee not found or does not belong to this farmer' });
            }

            // Return the employee details
            res.status(200).json({
                success: true,
                data: results[0]
            });
        });
    });
};

