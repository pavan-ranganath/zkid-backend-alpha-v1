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

/**
 * Get user by id
 * @param {ObjectId} id
 * @returns {Promise<User>}
 */
const getUserById = async (id) => {
  return NewUser.findById(id);
};

/**
 * Update user by id
 * @param {ObjectId} userId
 * @param {Object} updateBody
 * @returns {Promise<User>}
 */
const updateUserById = async (userId, updateBody) => {
  const user = await getUserById(userId);
  if (!user) {
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  if (updateBody.email && (await NewUser.isEmailTaken(updateBody.email, userId))) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Email already taken');
  }
  Object.assign(user, updateBody);
  await user.save();
  return user;
};

module.exports = {
  checkEmailExists,
  entradaMethodCreateUser,
  checkEmailAndPublicKeyExists,
  getEntradaAuthUserByEmail,
  getEntradaAuthUserByPublicKey,
  getUserById,
  updateUserById
};
