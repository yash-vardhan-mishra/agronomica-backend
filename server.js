// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const swaggerUiExpress = require('swagger-ui-express');
const swaggerSpec = require('./swaggerConfig');
require('./app/utils/cron.js')

// Load environment variables from .env file
dotenv.config();

const app = express();
// Enable CORS
const corsOptions = {
    origin: '*', // Allow requests from this origin
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Swagger setup
app.use('/api-docs', swaggerUiExpress.serve, swaggerUiExpress.setup(swaggerSpec));

// Use the routes defined in routes.js
require('./app/routes/employees.routes.js')(app);
require('./app/routes/farmers.routes.js')(app);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at port ${PORT} check the docs at http://localhost:${PORT}/api-docs`);
});
