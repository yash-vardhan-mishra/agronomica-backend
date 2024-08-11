// routes.js
import router from './router.js';
import farmerApis from './farmer-apis.js';
import commonApis from './common-apis.js';

// common reset password apis
router.use('/', commonApis);

// Use farmer routes
router.use('/', farmerApis);

export default router;
