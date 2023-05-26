const Joi = require('joi');

const verifyEmail = {
  query: Joi.object().keys({
    token: Joi.string().required(),
  }),
};

const entradaAuthRegistration = {
  body: Joi.object().keys({
    username: Joi.string().email().required(),
    name: Joi.string().required(),
    publicKey: Joi.string().required(),
    plainMsg: Joi.string().required(),
    signedMsg: Joi.string().required(),
  }),
};
const entradaAuthRegistrationVerify = {
  body: Joi.object().keys({
    signature: Joi.string().required(),
    encryptedData: Joi.string().required()
  }),
};
const entradaAuthLogin = {
  body: Joi.object().keys({
    username: Joi.string().email().required(),
    signature: Joi.string().required(),
    plainMsg: Joi.string().required(),
  }),
};

module.exports = {
  verifyEmail,
  entradaAuthRegistration,
  entradaAuthRegistrationVerify,
  entradaAuthLogin
};
