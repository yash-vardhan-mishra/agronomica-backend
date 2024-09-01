// common-apis.js
import bcrypt from 'bcrypt';
import connection from './db.js';
import { sendOtpEmail } from './mailer.js';
import { emailRegex, generateOTP, getOtpExpirationTime } from './utils.js';
import router from './router.js';

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - email
 *         - password
 *         - role
 *       properties:
 *         email:
 *           type: string
 *           description: The user's email
 *         password:
 *           type: string
 *           description: The user's password
 *         role:
 *           type: string
 *           description: The user's role
 */

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     tags: [Common]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/User'
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User registered successfully
 *                 userId:
 *                   type: integer
 *                   example: 1
 *                 role:
 *                   type: string
 *                   example: farmer
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

router.post('/register', async (req, res) => {
    const { password, email, role } = req.body;

    // Validate input
    if (!password || !email || !role) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate email format
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Validate role
    const validRoles = ['farmer', 'employee'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }

    try {
        // Check if the email already exists
        const emailCheckSql = 'SELECT * FROM Users WHERE email = ?';
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
            const otpExpiration = getOtpExpirationTime()
            const createdAt = new Date()

            // Insert the new user into the database
            const insertUserSql = 'INSERT INTO Users (passwordHash, email, role, otp, otpExpiration, createdAt) VALUES (?, ?, ?, ?, ?, ?)';
            connection.query(insertUserSql, [hashedPassword, email, role, otpHash, otpExpiration, createdAt], (err, result) => {
                if (err) {
                    console.error('Error inserting user into database:', err);
                    return res.status(500).json({ error: 'Database error' });
                }

                // Send OTP email
                sendOtpEmail(email, otp)
                    .then(info => {
                        res.status(201).json({ message: 'User registered successfully', userId: result.insertId, role });
                    })
                    .catch(err => {
                        console.error('Error sending email:', err);
                        res.status(500).json({ error: 'Error sending email' });
                    });
            });
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

/**
 * @swagger
 * /reset-password:
 *   post:
 *     summary: Send OTP to reset password
 *     tags: [Common]
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
router.post('/reset-password', (req, res) => {
    const { email } = req.body;

    const otp = generateOTP();
    const otpHash = bcrypt.hashSync(otp, 10);

    const sql = 'UPDATE users SET otp = ? WHERE email = ?';
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
 * /verify-reset-otp:
 *   post:
 *     summary: Verify OTP and reset password
 *     tags: [Common]
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
router.post('/verify-reset-otp', (req, res) => {
    const { email, otp, newPassword } = req.body;

    const sql = 'SELECT otp FROM users WHERE email = ?';
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
        const updateSql = 'UPDATE users SET passwordHash = ?, otp = NULL WHERE email = ?';
        connection.query(updateSql, [newPasswordHash, email], (err, result) => {            
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            res.status(200).json({ message: 'Password reset successfully' });
        });
    });
});

export default router;