const express = require('express');
const validate = require('../../middlewares/validate');
const authValidation = require('../../validations/auth.validation');
const authController = require('../../controllers/auth.controller');

const router = express.Router();

router.post('/generate-entrada-registration-options', validate(authValidation.entradaAuthRegistration), authController.EntadaAuthRegistration);
router.post('/verify-entrada-registration', validate(authValidation.entradaAuthRegistrationVerify), authController.EntadaAuthRegistrationVerify);
router.post('/entrada-login', validate(authValidation.entradaAuthLogin), authController.EntadaAuthLogin);


router.post('/verify-email', validate(authValidation.verifyEmail), authController.verifyEmail);

module.exports = router;
