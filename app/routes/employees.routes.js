// employees.routes.js
module.exports = app => {
    const employees = require('../controllers/employees.controller.js')
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
    app.post('/employee/login', employees.login);

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
    app.post('/employee/change-password', employees.changePassword);

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
    app.post('/employee/verify-otp',);
}
