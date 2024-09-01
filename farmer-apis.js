// farmer-apis.js
import 'dotenv/config'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import connection from './db.js';
import { sendEmployeeCredentials, sendOtpEmail, sendOtpEmailToFarmer } from './mailer.js';
import { emailRegex, generateOTP, generateTempPassword, getOtpExpirationTime, passwordRegex } from './utils.js';
import router from './router.js';
import { authenticateFarmerToken } from './authMiddleware.js';

const jwtSecret = process.env.FARMER_JWT_SECRET
const jwtConfig = { expiresIn: '7h' };


/**
 * @swagger
 * components:
 *   schemas:
 *     Farmer:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: The farmer's email
 *         password:
 *           type: string
 *           description: The farmer's password
 *     Login:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: The user's email
 *         password:
 *           type: string
 *           description: The user's password
 *     FarmerInfo:
 *       type: object
 *       properties:
 *         farmerId:
 *           type: integer
 *           description: The farmer's ID
 *         firstName:
 *           type: string
 *           description: The farmer's first name
 *         lastName:
 *           type: string
 *           description: The farmer's last name
 *         contactNumber:
 *           type: string
 *           description: The farmer's contact number
 *     Field:
 *       type: object
 *       properties:
 *         fieldId:
 *           type: integer
 *           description: The field's ID
 *         farmerId:
 *           type: integer
 *           description: The farmer's ID
 *         fieldName:
 *           type: string
 *           description: The field's name
 *         fieldAddress:
 *           type: string
 *           description: The field's address
 *         size:
 *           type: number
 *           format: float
 *           description: The field's size
 *         cropType:
 *           type: string
 *           description: The field's crop type
 */

/**
 * @swagger
 * /farmer/register:
 *   post:
 *     summary: Register a new farmer
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Farmer'
 *     responses:
 *       201:
 *         description: Farmer registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Farmer registered successfully
 *                 farmerId:
 *                   type: integer
 *                   example: 1
 *       400:
 *         description: All fields are required
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: All fields are required
 *       409:
 *         description: Email already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Email already exists
 *       500:
 *         description: Database error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Database error
 */
router.post('/farmer/register', async (req, res) => {
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
});


/**
 * @swagger
 * /farmer/reset-password:
 *   post:
 *     summary: Send OTP to reset password
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: "farmer@example.com"
 *             required:
 *               - email
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "OTP sent successfully"
 *       400:
 *         description: Invalid email
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid email"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Server error"
 */
router.post('/farmer/reset-password', (req, res) => {
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
});

/**
 * @swagger
 * /farmer/reset-password-verify-otp:
 *   post:
 *     summary: Verify OTP and reset password
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: "farmer@example.com"
 *               otp:
 *                 type: string
 *                 example: "1234"
 *               newPassword:
 *                 type: string
 *                 example: "newPassword123"
 *             required:
 *               - email
 *               - otp
 *               - newPassword
 *     responses:
 *       200:
 *         description: Password reset successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Password reset successfully"
 *       400:
 *         description: Invalid OTP or expired
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid OTP or expired"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Server error"
 */
router.post('/farmer/reset-password-verify-otp', (req, res) => {
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
});

/**
 * @swagger
 * /farmer/verify-otp:
 *   post:
 *     summary: Verify OTP for farmer
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 example: "farmer@example.com"
 *               otp:
 *                 type: string
 *                 example: "1234"
 *             required:
 *               - email
 *               - otp
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "OTP verified successfully"
 *                 token:
 *                   type: string
 *                   example: "jwt-token-string"
 *                 screen:
 *                   type: string
 *                   example: "home or profile-creation"
 *                 farmerId:
 *                   type: string
 *                   example: "123"
 *       400:
 *         description: Invalid or expired OTP
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid or expired OTP"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Database error"
 */
router.post('/farmer/verify-otp', (req, res) => {
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
});

/**
 * @swagger
 * /farmer/login:
 *   post:
 *     summary: Login a farmer user
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Login'
 *     responses:
 *       200:
 *         description: Farmer logged in successfully, OTP sent
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Farmer logged in successfully, OTP sent
 *                 token:
 *                   type: string
 *                   example: jwt_token
 *       400:
 *         description: Invalid email or password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid email or password
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Server error
 */
router.post('/farmer/login', (req, res) => {
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
});


/**
 * @swagger
 * /farmer/update-info:
 *   post:
 *     summary: Update farmer information
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               farmerId:
 *                 type: integer
 *                 example: 1
 *               firstName:
 *                 type: string
 *                 example: "John"
 *               lastName:
 *                 type: string
 *                 example: "Doe"
 *               contactNumber:
 *                 type: string
 *                 example: "1234567890"
 *             required:
 *               - farmerId
 *               - firstName
 *               - lastName
 *               - contactNumber
 *     responses:
 *       200:
 *         description: Farmer information updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Farmer information updated successfully"
 *       400:
 *         description: Invalid input
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid input"
 *       409:
 *         description: Conflict - contact number already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Contact number already exists"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Database error"
 */
router.post('/farmer/update-info', authenticateFarmerToken, (req, res) => {
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
});


/**
 * @swagger
 * /farmer/get-info:
 *   get:
 *     summary: Get farmer information
 *     tags: [Farmer]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: farmerId
 *         required: true
 *         schema:
 *           type: integer
 *         description: The farmer ID of the farmer
 *     responses:
 *       200:
 *         description: Farmer information retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 firstName:
 *                   type: string
 *                   example: "John"
 *                 lastName:
 *                   type: string
 *                   example: "Doe"
 *                 contactNumber:
 *                   type: string
 *                   example: "+64212345678"
 *       404:
 *         description: Farmer not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Farmer not found"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Database error"
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */
router.get('/farmer/get-info', authenticateFarmerToken, (req, res) => {
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
});

/**
 * @swagger
 * /farmer/add-field:
 *   post:
 *     summary: Add a new field for a farmer
 *     tags: [Farmer]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               farmerId:
 *                 type: integer
 *                 example: 1
 *               fieldName:
 *                 type: string
 *                 example: "North Field"
 *               fieldAddress:
 *                 type: string
 *                 example: "123 Farm Lane, Ruralville"
 *               size:
 *                 type: number
 *                 format: float
 *                 example: 15.5
 *               cropType:
 *                 type: string
 *                 example: "Corn"
 *     responses:
 *       201:
 *         description: Field added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Field added successfully"
 *       400:
 *         description: Missing or invalid input or field name already exists
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid input or field name already exists"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Database error"
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */
router.post('/farmer/add-field', authenticateFarmerToken, (req, res) => {
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
});

/**
 * @swagger
 * /farmer/onboard-employee:
 *   post:
 *     summary: Initiate onboarding of an employee
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               employeeEmail:
 *                 type: string
 *                 example: "newemployee@example.com"
 *               employeeRole:
 *                 type: string
 *                 enum: [supervisor, worker]
 *                 example: "worker"
 *     responses:
 *       200:
 *         description: OTP sent to farmer's email for confirmation
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "OTP sent to farmer's email for confirmation"
 *       400:
 *         description: Invalid input
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid input"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Database error"
 */
router.post('/farmer/onboard-employee', authenticateFarmerToken, (req, res) => {
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
});


/**
 * @swagger
 * /farmer/onboard-employee-verify-otp:
 *   post:
 *     summary: Verify OTP and onboard the employee
 *     tags: [Farmer]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               otp:
 *                 type: string
 *                 example: "123456"
 *               employeeEmail:
 *                 type: string
 *                 example: "newemployee@example.com"
 *               employeeRole:
 *                 type: string
 *                 enum: [supervisor, worker]
 *                 example: "worker"
 *     responses:
 *       200:
 *         description: Employee onboarded successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Employee onboarded successfully"
 *       400:
 *         description: Invalid OTP or input
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid OTP or input"
 *       404:
 *         description: OTP not found or expired
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "OTP not found or expired"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Database error"
 */
router.post('/farmer/onboard-employee-verify-otp', authenticateFarmerToken, async (req, res) => {
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
});



export default router;
