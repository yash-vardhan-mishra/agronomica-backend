// farmer-apis.js
import 'dotenv/config'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import connection from './db.js';
import { sendOtpEmail } from './mailer.js';
import { emailRegex, generateOTP, getOtpExpirationTime } from './utils.js';
import router from './router.js';
import { authenticateToken } from './authMiddleware.js';

const jwtSecret = process.env.JWT_SECRET
const jwtConfig = { expiresIn: '7h' };

/**
 * @swagger
 * /verify-farmer:
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
 *                 example: "user@example.com"
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
router.post('/verify-farmer', (req, res) => {
    const { email, otp } = req.body;

    // Validate input
    if (!email || !otp) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate email format
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    const findUserSql = 'SELECT * FROM Users WHERE email = ? AND role = "farmer"';
    connection.query(findUserSql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid email or OTP' });
        }

        const user = results[0];

        // Check if OTP is expired
        if (new Date() > new Date(user.otpExpiration)) {
            return res.status(400).json({ error: 'OTP expired' });
        }

        // Compare OTP
        const otpMatch = await bcrypt.compare(otp, user.otp);
        if (!otpMatch) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.userId, role: user.role }, jwtSecret, jwtConfig);

        // Check if farmer details exist
        const findFarmerSql = 'SELECT * FROM Farmers WHERE userId = ?';
        connection.query(findFarmerSql, [user.userId], (err, farmerResults) => {
            if (err) {
                console.error('Error querying the Farmers table:', err);
                return res.status(500).json({ error: 'Server error' });
            }

            let screen = 'profile-creation';
            if (farmerResults.length > 0) {
                const farmer = farmerResults[0];
                if (farmer.firstName && farmer.lastName && farmer.contactNumber) {
                    screen = 'home';
                }
            }

            // Insert or update auth_token in Farmers table
            const upsertFarmerTokenSql = `
                INSERT INTO Farmers (userId, authToken)
                VALUES (?, ?)
                ON DUPLICATE KEY UPDATE authToken = VALUES(authToken)
            `;
            connection.query(upsertFarmerTokenSql, [user.userId, token], (err) => {
                if (err) {
                    console.error('Error updating authToken in Farmers table:', err);
                    return res.status(500).json({ error: 'Server error' });
                }

                // Clear OTP and expiration time
                const removeExpiredOtpsSql = 'UPDATE Users SET otp = NULL, otpExpiration = NULL WHERE userId = ?';
                connection.query(removeExpiredOtpsSql, [user.userId], (err) => {
                    if (err) {
                        console.error('Error removing expired OTPs:', err);
                    } else {
                        console.log('Removed expired OTPs');
                    }
                });

                res.status(200).json({ message: 'OTP verified successfully', token, screen, userId: user.userId });
            });
        });
    });
});

/**
 * @swagger
 * components:
 *   schemas:
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
 */

/**
 * @swagger
 * /login-farmer:
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

router.post('/login-farmer', (req, res) => {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const findUserSql = 'SELECT * FROM Users WHERE email = ? AND role = "farmer"';
    connection.query(findUserSql, [email], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Server error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const user = results[0];

        // Compare password
        const passwordMatch = await bcrypt.compare(password, user.passwordHash);
        if (!passwordMatch) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Generate OTP and set expiration time
        const otp = generateOTP();
        const otpHash = bcrypt.hashSync(otp, 10);
        const otpExpiration = getOtpExpirationTime()

        // Update user with OTP and expiration
        const updateUserOtpSql = 'UPDATE Users SET otp = ?, otpExpiration = ? WHERE userId = ?';
        connection.query(updateUserOtpSql, [otpHash, otpExpiration, user.userId], async (err) => {
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
 * /update-farmer-info:
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
 *               userId:
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
 *               - userId
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
router.post('/update-farmer-info', authenticateToken, (req, res) => {
    const { firstName, lastName, contactNumber } = req.body;
    const userId = req.user.userId; // Extract userId from the authenticated user

    // Validate input
    if (!firstName || !lastName || !contactNumber) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate contact number format (NZ and Australia)
    const contactNumberRegex = /^(\+?64|0)[2-9]\d{7,9}$|^(\+?61|0)[2-9]\d{8,9}$/;
    if (!contactNumberRegex.test(contactNumber)) {
        return res.status(400).json({ error: 'Invalid contact number format' });
    }

    // Check if the contact number already exists
    const checkContactNumberSql = 'SELECT * FROM Farmers WHERE contactNumber = ? AND userId != ?';
    connection.query(checkContactNumberSql, [contactNumber, userId], (err, results) => {
        if (err) {
            console.error('Error checking contact number in database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length > 0) {
            return res.status(409).json({ error: 'Contact number already exists' });
        }

        // Update farmer information
        const updateFarmerInfoSql = `
            UPDATE Farmers
            SET firstName = ?, lastName = ?, contactNumber = ?
            WHERE userId = ?
        `;
        connection.query(updateFarmerInfoSql, [firstName, lastName, contactNumber, userId], (err, results) => {
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
 * /get-farmer-info:
 *   get:
 *     summary: Get farmer information
 *     tags: [Farmer]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: userId
 *         required: true
 *         schema:
 *           type: integer
 *         description: The user ID of the farmer
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

router.get('/get-farmer-info', authenticateToken, (req, res) => {
    const { userId } = req.query;

    if (!userId) {
        return res.status(400).json({ error: 'userId is required' });
    }

    const getFarmerInfoSql = 'SELECT firstName, lastName, contactNumber, farmerId FROM Farmers WHERE userId = ?';
    connection.query(getFarmerInfoSql, [userId], (err, results) => {
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
 * /add-field:
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

router.post('/add-field', authenticateToken, (req, res) => {
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

export default router;
