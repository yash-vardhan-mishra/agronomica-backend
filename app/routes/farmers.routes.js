// farmers.routes.js
const authMiddleware = require('../middlewares/authMiddleware.js');
const { authenticateFarmerToken } = authMiddleware

module.exports = app => {
   const farmers = require('../controllers/farmers.controller.js');
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
   app.post('/farmer/register', farmers.register);


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
   app.post('/farmer/reset-password', farmers.resetPassword);

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
   app.post('/farmer/reset-password-verify-otp', farmers.resetPasswordVerifyOtp);

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
   app.post('/farmer/verify-otp', farmers.verifyOtp);

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
   app.post('/farmer/login', farmers.login);


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
   app.post('/farmer/update-info', authenticateFarmerToken, farmers.updateInfo);

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
   app.get('/farmer/get-info', authenticateFarmerToken, farmers.getInfo);

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
   app.post('/farmer/add-field', authenticateFarmerToken, farmers.addField);

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
   app.post('/farmer/onboard-employee', authenticateFarmerToken, farmers.onboardEmployee);

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
   app.post('/farmer/onboard-employee-verify-otp', authenticateFarmerToken, farmers.onboardEmployeeVerifyOtp);
}
