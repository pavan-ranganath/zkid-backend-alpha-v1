const express = require('express');
const validate = require('../../middlewares/validate');
const authValidation = require('../../validations/auth.validation');
const authController = require('../../controllers/auth.controller');

const router = express.Router();

// Registration request is validated, processed and provided with challenge

router.post(
  '/generate-entrada-registration-options',
  validate(authValidation.entradaAuthRegistration),
  authController.EntadaAuthRegistration
);

// Challenge verification is validated, processed
router.post(
  '/verify-entrada-registration',
  validate(authValidation.entradaAuthRegistrationVerify),
  authController.EntadaAuthRegistrationVerify
);

// Login request is  validated and processed
router.post('/entrada-login', validate(authValidation.entradaAuthLogin), authController.EntadaAuthLogin);

// Process the email verfication request
router.post('/verify-email', validate(authValidation.verifyEmail), authController.verifyEmail);

module.exports = router;
