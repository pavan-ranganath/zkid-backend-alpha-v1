const express = require('express');
const authRoute = require('./auth.route');

const router = express.Router();

// API routes
const defaultRoutes = [
  // Login and registration
  {
    path: '/auth',
    route: authRoute,
  },
];

defaultRoutes.forEach((route) => {
  router.use(route.path, route.route);
});

module.exports = router;
