// routes.js
import router from './router.js';
import farmerApis from './farmer-apis.js';

// // common apis
// router.use('/', commonApis);

// Use farmer routes
router.use('/', farmerApis);

export default router;
