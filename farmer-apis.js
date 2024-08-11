// farmer-apis.js
import 'dotenv/config'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import connection from './db.js';
import { sendOtpEmail } from './mailer.js';
import { emailRegex, generateOTP, getOtpExpirationTime } from './utils.js';
import router from './router.js';

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
            return res.status(400).json({ error: 'OTP expired' });
        }

        const user = results[0];

        // Check if OTP is expired
        if (new Date() > new Date(user.otp_expiration)) {
            return res.status(400).json({ error: 'OTP expired' });
        }

        // Compare OTP
        const otpMatch = await bcrypt.compare(otp, user.otp);
        if (!otpMatch) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user.user_id, role: user.role }, jwtSecret, jwtConfig);

        res.status(200).json({ message: 'OTP verified successfully', token });

        const removeExpiredOtpsSql = 'UPDATE Users SET otp = NULL, otp_expiration = NULL WHERE user_id = ?';
        connection.query(removeExpiredOtpsSql, [user.user_id], (err, results) => {
            if (err) {
                console.error('Error removing expired OTPs:', err);
            } else {
                console.log(`Removed ${results.affectedRows} expired OTPs`);
            }
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
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Generate OTP and set expiration time
        const otp = generateOTP();
        const otpHash = bcrypt.hashSync(otp, 10);
        const otpExpiration = getOtpExpirationTime()

        // Update user with OTP and expiration
        const updateUserOtpSql = 'UPDATE Users SET otp = ?, otp_expiration = ? WHERE user_id = ?';
        connection.query(updateUserOtpSql, [otpHash, otpExpiration, user.user_id], async (err) => {
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


export default router;
