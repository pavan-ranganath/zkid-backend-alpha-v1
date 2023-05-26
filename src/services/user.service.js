const httpStatus = require('http-status');
const ApiError = require('../utils/ApiError');
const NewUser = require('../models/newUser.model');

/**
 * Create a user
 * @param {Object} userBody
 * @returns {Promise<User>}
 */
const entradaMethodCreateUser = async (userBody) => {
  if (await NewUser.isEmailAndPublic(userBody.username, userBody.publicKey)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Username / Public key already exists');
  }
  return NewUser.create(userBody);
};

const checkEmailExists = async (email) => {
  if (await NewUser.isEmailTaken(email)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
  }
};

const checkEmailAndPublicKeyExists = async (username, publicKey) => {
  if (await NewUser.isEmailAndPublic(username, publicKey)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Username / Public key exists');
  }
};

/**
 * Get user by email
 * @param {string} email
 * @returns {Promise<User>}
 */
const getEntradaAuthUserByEmail = async (username) => {
  return NewUser.findOne({ username });
};

/**
 * Get user by public key
 * @param {string} email
 * @returns {Promise<User>}
 */
const getEntradaAuthUserByPublicKey = async (publicKey) => {
  return NewUser.findOne({ publicKey });
};

module.exports = {
  checkEmailExists,
  entradaMethodCreateUser,
  checkEmailAndPublicKeyExists,
  getEntradaAuthUserByEmail,
  getEntradaAuthUserByPublicKey,
};
