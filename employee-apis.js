// employee-apis.js
import 'dotenv/config'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import connection from './db.js';
import { sendOtpEmail } from './mailer.js';
import { generateOTP, passwordRegex } from './utils.js';
import router from './router.js';

const jwtSecret = process.env.EMPLOYEE_JWT_SECRET
const jwtConfig = { expiresIn: '7h' };

/**
 * @swagger
 * /employee/login:
 *   post:
 *     summary: Employee login
 *     tags: [Employee]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               employeeId:
 *                 type: string
 *                 example: "E123"
 *               password:
 *                 type: string
 *                 example: "TempP@ss123"
 *     responses:
 *       200:
 *         description: Login successful or require password change
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 screen:
 *                   type: string
 *                   example: "change-password"
 *                 message:
 *                   type: string
 *                   example: "Please change your temporary password"
 *       400:
 *         description: Invalid employeeId or password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid employeeId or password"
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
router.post('/employee/login', (req, res) => {
    const { employeeId, password } = req.body;

    if (!employeeId || !password) {
        return res.status(400).json({ error: 'employeeId and password are required' });
    }

    // Check if the employee exists
    const getEmployeeSql = 'SELECT * FROM Employees WHERE employeeId = ?';
    connection.query(getEmployeeSql, [employeeId], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid employeeId or password' });
        }

        const employee = results[0];

        // Check the password
        const passwordMatch = await bcrypt.compare(password, employee.passwordHash);
        if (!passwordMatch) {
            return res.status(400).json({ error: 'Invalid employeeId or password' });
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
                return res.status(500).json({ error: 'Database error' });
            }

            // Send OTP email
            sendOtpEmail(employee.email, otp)
                .then(() => {
                    res.status(200).json({
                        screen: employee.isPasswordChanged ? 'verify-otp' : 'change-password',
                        message: 'OTP has been sent to your email. Please verify to continue.'
                    });
                })
                .catch(err => {
                    console.error('Error sending OTP email:', err);
                    res.status(500).json({ error: 'Error sending OTP email' });
                });
        });
    });
});

/**
 * @swagger
 * /employee/change-password:
 *   post:
 *     summary: Change employee password
 *     tags: [Employee]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               employeeId:
 *                 type: string
 *                 example: "E123"
 *               tempPassword:
 *                 type: string
 *                 example: "TempP@ss123"
 *               newPassword:
 *                 type: string
 *                 example: "NewP@ss456"
 *               otp:
 *                 type: string
 *                 example: "123456"
 *     responses:
 *       200:
 *         description: Password changed successfully and authToken provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Password changed successfully"
 *                 authToken:
 *                   type: string
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
 *       400:
 *         description: Invalid data or OTP
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid OTP or password"
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
router.post('/employee/change-password', async (req, res) => {
    const { employeeId, tempPassword, newPassword, otp } = req.body;

    if (!employeeId || !tempPassword || !newPassword || !otp) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate new password format
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({ error: 'New password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character' });
    }

    // Check if the employee exists and the OTP is valid
    const getEmployeeSql = 'SELECT * FROM Employees WHERE employeeId = ?';
    connection.query(getEmployeeSql, [employeeId], async (err, results) => {
        if (err) {
            console.error('Error querying the database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(400).json({ error: 'Invalid employeeId' });
        }

        const employee = results[0];

        // Verify OTP
        const otpMatch = await bcrypt.compare(otp, employee.otp);
        if (!otpMatch || new Date() > new Date(employee.otpExpiration)) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
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
                return res.status(500).json({ error: 'Database error' });
            }

            // Update EmployeeInfo with authToken
            const updateEmployeeInfoSql = 'UPDATE EmployeeInfo SET authToken = ? WHERE employeeId = ?';
            connection.query(updateEmployeeInfoSql, [authToken, employeeId], (err) => {
                if (err) {
                    console.error('Error updating authToken in database:', err);
                    return res.status(500).json({ error: 'Database error' });
                }

                res.status(200).json({
                    message: 'Password changed successfully',
                    authToken
                });
            });
        });
    });
});

/**
 * @swagger
 * /employee/verify-otp:
 *   post:
 *     summary: Verify OTP for employee login
 *     tags: [Employee]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               employeeId:
 *                 type: string
 *                 example: "E123"
 *               otp:
 *                 type: string
 *                 example: "123456"
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
 *       400:
 *         description: Invalid OTP
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
router.post('/employee/verify-otp', async (req, res) => {
    const { employeeId, otp } = req.body;

    if (!employeeId || !otp) {
        return res.status(400).json({ error: 'Employee ID and OTP are required' });
    }

    // Fetch the stored OTP and expiration time from the database
    const fetchOtpSql = 'SELECT otp, otpExpiration FROM Employees WHERE employeeId = ?';
    connection.query(fetchOtpSql, [employeeId], async (err, results) => {
        if (err) {
            console.error('Error querying OTP in database:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (results.length === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        const { otp: storedOtp, otpExpiration } = results[0];

        // Check if the OTP is expired
        if (new Date() > new Date(otpExpiration)) {
            return res.status(400).json({ error: 'OTP has expired' });
        }

        // Verify the OTP
        const isOtpValid = await bcrypt.compare(otp, storedOtp);
        if (!isOtpValid) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // Generate auth token
        const authToken = jwt.sign({ employeeId: employeeId }, jwtSecret, jwtConfig);

        // Update employee record to remove OTP and set other flags if necessary
        const updateEmployeeSql = 'UPDATE Employees SET otp = NULL, otpExpiration = NULL WHERE employeeId = ?';
        connection.query(updateEmployeeSql, [employeeId], (err) => {
            if (err) {
                console.error('Error updating OTP status in database:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            res.status(200).json({ message: 'OTP verified successfully', authToken });
        });
    });
});

export default router;
