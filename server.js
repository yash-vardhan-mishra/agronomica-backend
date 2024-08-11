// server.js
import express from 'express';
import { serve, setup } from 'swagger-ui-express';
import dotenv from 'dotenv';

import routes from './routes.js';
import swaggerSpec from './swaggerConfig.js';
import './cron.js';

// Load environment variables from .env file
dotenv.config();

const app = express();
app.use(express.json());

// Swagger setup
app.use('/api-docs', serve, setup(swaggerSpec));

// Use the routes defined in routes.js
app.use('/', routes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running at port ${PORT} check the docs at http://localhost:${PORT}/api-docs`);
});
