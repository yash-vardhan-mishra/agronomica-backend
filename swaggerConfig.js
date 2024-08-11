// swaggerConfig.js
import swaggerJSDoc from 'swagger-jsdoc';

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Agronomica API',
            version: '1.0.0',
            description: 'API documentation for Agronomica',
        },
        servers: [
            {
                url: 'http://localhost:3000',
                description: 'Local server'
            }
        ],
    },
    apis: ['./common-apis.js', './farmer-apis.js'], // Paths to the API docs
};

const swaggerSpec = swaggerJSDoc(options);

export default swaggerSpec;