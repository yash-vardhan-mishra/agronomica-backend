// swaggerConfig.js
const swaggerJSDoc = require('swagger-jsdoc');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Agronomica API',
            version: '1.0.0',
            description: 'API documentation for Agronomica',
        },
        components: {
            securitySchemes: {
                ApiKeyAuth: {
                    type: "apiKey",
                    in: "header",
                    name: "Authorization",
                    description: "Enter your API key in the format `Bearer <token>`",
                },
            },
        },
        security: [
            {
                ApiKeyAuth: [],
            },
        ],
        servers: [
            {
                url: 'http://localhost:3000',
                description: 'Local server'
            }
        ],
    },
    apis: ['./app/routes/employees.routes.js', './app/routes/farmers.routes.js'], // Paths to the API docs
};

const swaggerSpec = swaggerJSDoc(options);

module.exports = swaggerSpec;