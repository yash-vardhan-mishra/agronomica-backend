// routes.js
import router from './router.js';
import farmerApis from './farmer-apis.js';
import employeeApis from './employee-apis.js';

// Use Employee routes
router.use('/', employeeApis);

// Use farmer routes
router.use('/', farmerApis);

export default router;
