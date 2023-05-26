const httpStatus = require('http-status');
const { User } = require('../models');
const ApiError = require('../utils/ApiError');
const NewUser = require('../models/newUser.model');


/**
 * Create a user
 * @param {Object} userBody
 * @returns {Promise<User>}
 */
const entradaMethodCreateUser = async (userBody) => {
  if (await NewUser.isEmailTaken(userBody.username)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Username already registered');
  }
  if (await NewUser.isPublicKeyTaken(userBody.publicKey)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Public key already exists');
  }
  return NewUser.create(userBody);
};



const checkEmailExists = async (email) => {
  if (await NewUser.isEmailTaken(email)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
  }
}

const checkEmailEntradaCustomUser = async (email, publicKey) => {
  if (await NewUser.isEmailTaken(email)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
  }
  if (await NewUser.isPublicKeyTaken(publicKey)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Public key already exists');
  }
}


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
  checkEmailEntradaCustomUser,
  getEntradaAuthUserByEmail,
  getEntradaAuthUserByPublicKey
};
