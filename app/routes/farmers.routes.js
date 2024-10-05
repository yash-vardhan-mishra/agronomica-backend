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
    *     parameters:
    *       - in: header
    *         name: farmerId
    *         schema:
    *           type: integer
    *         required: true
    *         description: ID of the farmer (sent in the headers)
    *     requestBody:
    *       required: true
    *       content:
    *         application/json:
    *           schema:
    *             type: object
    *             properties:
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
    *               fieldName:
    *                 type: string
    *                 example: "North Field"
    *                 description: "Name of the field"
    *               fieldAddress:
    *                 type: string
    *                 example: "123 Farm Lane, Ruralville"
    *                 description: "Address of the field"
    *               size:
    *                 type: number
    *                 format: float
    *                 example: 15.5
    *                 description: "Size of the field in acres"
    *               fieldTypeId:
    *                 type: integer
    *                 example: 1
    *                 description: "Type of the field (e.g., Pasture, Orchard, Farm). Select from predefined types."
    *               fieldLat:
    *                 type: number
    *                 format: float
    *                 example: -37.123456
    *                 description: "Latitude of the field location"
    *               fieldLong:
    *                 type: number
    *                 format: float
    *                 example: 174.123456
    *                 description: "Longitude of the field location"
    *     responses:
    *       201:
    *         description: Field added successfully
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: true
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
    *                 success:
    *                   type: boolean
    *                   example: false
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
    *                 success:
    *                   type: boolean
    *                   example: false
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
    *               firstName:
    *                 type: string
    *                 example: "John"
    *               lastName:
    *                 type: string
    *                 example: "Doe"
    *               contactNumber:
    *                 type: string
    *                 example: "+1234567890"
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
 *               firstName:
 *                 type: string
 *                 example: "John"
 *               lastName:
 *                 type: string
 *                 example: "Doe"
 *               contactNumber:
 *                 type: string
 *                 example: "1234567890"
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

   /**
 * @swagger
 * /farmer/get-field-types:
 *   get:
 *     summary: Get all available field types
 *     tags: [Farmer]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of field types
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   typeId:
 *                     type: integer
 *                     example: 1
 *                     description: "The unique ID of the field type"
 *                   fieldType:
 *                     type: string
 *                     example: "Pasture"
 *                     description: "The name of the field type"
 *       401:
 *         description: Unauthorized access
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 error:
 *                   type: string
 *                   example: "Unauthorized"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
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
   app.get('/farmer/get-field-types', authenticateFarmerToken, farmers.getFieldTypes);

   /**
    * @swagger
    * /farmer/fields:
    *   get:
    *     summary: Retrieve all fields associated with the authenticated farmer
    *     tags: [Farmer]
    *     security:
    *       - bearerAuth: []
    *     responses:
    *       200:
    *         description: List of fields fetched successfully
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: true
    *                 data:
    *                   type: array
    *                   items:
    *                     type: object
    *                     properties:
    *                       fieldId:
    *                         type: string
    *                         example: "123e4567-e89b-12d3-a456-426614174000"
    *                         description: "Unique ID of the field"
    *                       fieldName:
    *                         type: string
    *                         example: "North Field"
    *                         description: "Name of the field"
    *                       fieldAddress:
    *                         type: string
    *                         example: "123 Farm Lane, Ruralville"
    *                         description: "Address of the field"
    *                       size:
    *                         type: number
    *                         example: 15.5
    *                         description: "Size of the field in acres"
    *                       fieldType:
    *                         type: string
    *                         example: "Orchard"
    *                         description: "Type of the field"
    *                       fieldLat:
    *                         type: number
    *                         example: -37.123456
    *                         description: "Latitude of the field location"
    *                       fieldLong:
    *                         type: number
    *                         example: 174.123456
    *                         description: "Longitude of the field location"
    *       401:
    *         description: Unauthorized. Missing or invalid token.
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: false
    *                 error:
    *                   type: string
    *                   example: "Unauthorized access. No token provided."
    *       500:
    *         description: Internal server error
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: false
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
   app.get('/farmer/get-fields', authenticateFarmerToken, farmers.getFields);

   /**
    * @swagger
    * /farmer/get-employees:
    *   get:
    *     summary: Get all employees for a specific farmer, including field type
    *     tags: [Farmer]
    *     security:
    *       - bearerAuth: []
    *     responses:
    *       200:
    *         description: Employees fetched successfully
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: true
    *                 data:
    *                   type: array
    *                   items:
    *                     type: object
    *                     properties:
    *                       employeeId:
    *                         type: string
    *                         example: "123e4567-e89b-12d3-a456-426614174000"
    *                       fieldId:
    *                         type: string
    *                         example: "456e7890-e89b-12d3-a456-426614174111"
    *                       fieldType:
    *                         type: string
    *                         example: "orchard"
    *                       employeeRole:
    *                         type: string
    *                         example: "supervisor"
    *                       email:
    *                         type: string
    *                         example: "employee@example.com"
    *                       firstName:
    *                         type: string
    *                         example: "John"
    *                       lastName:
    *                         type: string
    *                         example: "Doe"
    *                       contactNumber:
    *                         type: string
    *                         example: "+1234567890"
    *                       createdAt:
    *                         type: string
    *                         format: date-time
    *                         example: "2024-10-05T14:48:00.000Z"
    *                       isPasswordChanged:
    *                         type: boolean
    *                         example: false
    *       500:
    *         description: Internal server error
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: false
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
   app.get('/farmer/get-employees', authenticateFarmerToken, farmers.getEmployees);

   /**
    * @swagger
    * /farmer/get-employee/{employeeId}:
    *   get:
    *     summary: Get details of a specific employee by employeeId, including field type
    *     tags: [Farmer]
    *     security:
    *       - bearerAuth: []
    *     parameters:
    *       - in: path
    *         name: employeeId
    *         schema:
    *           type: string
    *         required: true
    *         description: The unique employeeId of the employee
    *     responses:
    *       200:
    *         description: Employee details fetched successfully
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: true
    *                 data:
    *                   type: object
    *                   properties:
    *                     employeeId:
    *                       type: string
    *                       example: "123e4567-e89b-12d3-a456-426614174000"
    *                     fieldId:
    *                       type: string
    *                       example: "456e7890-e89b-12d3-a456-426614174111"
    *                     fieldType:
    *                       type: string
    *                       example: "orchard"
    *                     employeeRole:
    *                       type: string
    *                       example: "supervisor"
    *                     email:
    *                       type: string
    *                       example: "employee@example.com"
    *                     firstName:
    *                       type: string
    *                       example: "John"
    *                     lastName:
    *                       type: string
    *                       example: "Doe"
    *                     contactNumber:
    *                       type: string
    *                       example: "+1234567890"
    *                     createdAt:
    *                       type: string
    *                       format: date-time
    *                       example: "2024-10-05T14:48:00.000Z"
    *                     isPasswordChanged:
    *                       type: boolean
    *                       example: false
    *       500:
    *         description: Internal server error
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 success:
    *                   type: boolean
    *                   example: false
    *                 error:
    *                   type: string
    *                   example: "Database error"
    */
   app.get('/farmer/get-employee/:employeeId', authenticateFarmerToken, farmers.getEmployeeById);

   /**
    * @swagger
    * /farmer/update-employee:
    *   post:
    *     summary: Update employee information
    *     tags: [Employee]
    *     parameters:
    *       - in: header
    *         name: authToken
    *         schema:
    *           type: string
    *         required: true
    *         description: Auth token of the farmer (sent in the headers)
    *     requestBody:
    *       required: true
    *       content:
    *         application/json:
    *           schema:
    *             type: object
    *             properties:
    *               employeeId:
    *                 type: string
    *                 example: "b6a38c4f-48b4-42f8-a69a-b58f99f4d8a4"
    *               fieldId:
    *                 type: string
    *                 example: "e5b8d1c8-8b3f-4a2e-a8f2-ece7f5ae71f0"
    *               employeeRole:
    *                 type: string
    *                 enum: [supervisor, worker]
    *                 example: "worker"
    *             required:
    *               - employeeId
    *               - fieldId
    *               - employeeRole
    *     responses:
    *       200:
    *         description: Employee information updated successfully
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 message:
    *                   type: string
    *                   example: "Employee information updated successfully"
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
    *       404:
    *         description: Employee not found
    *         content:
    *           application/json:
    *             schema:
    *               type: object
    *               properties:
    *                 error:
    *                   type: string
    *                   example: "Employee not found"
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
   app.post('/farmer/update-employee', authenticateFarmerToken, farmers.updateEmployee);
}

