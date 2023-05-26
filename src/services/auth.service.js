const httpStatus = require('http-status');

const { v4: uuidv4 } = require('uuid');
const emailService = require('./email.service');
const tokenService = require('./token.service');
const userService = require('./user.service');

const Token = require('../models/token.model');
const { tokenTypes } = require('../config/tokens');

const ApiError = require('../utils/ApiError');
const {
  generateRandomBytes,
  generateKeyPair,
  readOpenSslPublicKeys,
  verifySign,
  getSharedKey,
  encryptWithSharedKey,
  convertEd25519PublicKeyToCurve25519,
  convertEd25519PrivateKeyToCurve25519,
} = require('../middlewares/ed25519NewWrapper');
const logger = require('../config/logger');

// Generate 6 digit random
function generate6digitRandomNumber() {
  const minm = 100000;
  const maxm = 999999;
  return Math.floor(Math.random() * (maxm - minm + 1)) + minm;
}

/**
 * Verify email
 * * Verify the token
 * * Update user table
 * * Delete all the email verification token of that user
 * @param {string} verifyEmailToken
 * @returns {Promise <User>} user
 */
const verifyEmail = async (verifyEmailToken) => {
  try {
    const verifyEmailTokenDoc = await tokenService.verifyToken(verifyEmailToken, tokenTypes.VERIFY_EMAIL);
    const user = await userService.getUserById(verifyEmailTokenDoc.user);
    if (!user) {
      throw new Error('User not found');
    }
    await Token.deleteMany({ user: user.id, type: tokenTypes.VERIFY_EMAIL });
    await userService.updateUserById(user.id, { isEmailVerified: true });
  } catch (error) {
    logger.error(error);
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
  }
};

/**
 * Login user
 * * Check email and public exist
 * * Verify signature using user public key in table
 * * If email not verified send email
 * * Generate EPHEMERAL key
 * * Generate shared key
 * @param {string} email
 * @returns {Promise<User, String, Uint8Array>} User, ephemeral Key Pair, sharedKey
 */
const loginUsingPublicKey = async (username, plainMsg, signature) => {
  await userService.checkEmailExists(username);
  const user = await userService.getEntradaAuthUserByEmail(username);

  // VERIFY SIGNATURE USING USER PUBLIC KEY
  const clientPublicKey = readOpenSslPublicKeys(user.publicKey);
  if (!verifySign(signature, plainMsg, clientPublicKey)) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Signature verification failed');
  }

  // Check of email has been verified
  if (!user.isEmailVerified) {
    const verifyEmailToken = await tokenService.generateVerifyEmailToken(user);
    await emailService.sendVerificationEmail(user.username, verifyEmailToken);
    // throw new ApiError(httpStatus.UNAUTHORIZED, 'Please verify your email address');
  }

  // GENERTE EPHEMERAL KEY
  const ephemeralKeyPair = generateKeyPair('base64');

  // ED25519 -> curve25519
  const clientCurve25519PublicKey = convertEd25519PublicKeyToCurve25519(clientPublicKey);
  const ServerCurve25519PrivateKey = convertEd25519PrivateKeyToCurve25519(ephemeralKeyPair.secretKey);

  // GENERATE SHARED SECRET
  const sharedKey = getSharedKey(ServerCurve25519PrivateKey, clientCurve25519PublicKey);
  return { user, ephemeralKeyPair, sharedKey };
};

/**
 * User registration
 * @param {*} body REQUEST BODY
 * @param {*} req REQUEST
 * @returns encrypted challenge, ephemeral private/public Key, user ID
 * Check if user exists
 * Validate the signature
 * Generate the challenge
 * Generate Ephermal key pair
 * Generate shared key
 * Encrypt the challenge with shared key
 * Create session and storer user info with key pair
 */
async function entradaAuthRegistration(body, req) {
  const userPublicKey = body.publicKey;
  const { username } = body;

  const { signature, plainMsg } = body;

  // CHECK USER EXISTS
  await userService.checkEmailAndPublicKeyExists(username, userPublicKey);

  // VALIDATE SIGNATURE
  const clientPublicKey = readOpenSslPublicKeys(userPublicKey);
  if (!verifySign(signature, plainMsg, clientPublicKey)) {
    throw new Error('Signature verification failed');
  }

  const userId = uuidv4();

  // GENERATE CHALLENGE
  const challenge = Buffer.from(generateRandomBytes()).toString('base64');

  // GENERTE EPHEMERAL KEY
  const ephemeralKeyPair = generateKeyPair();
  logger.debug(`serverPrivateKey: ${Buffer.from(ephemeralKeyPair.secretKey).toString('base64')}`);
  logger.debug(`serverPublicKey: ${Buffer.from(ephemeralKeyPair.publicKey).toString('base64')}`);

  // ED25519 -> curve25519
  const clientCurve25519PublicKey = convertEd25519PublicKeyToCurve25519(clientPublicKey);
  const ServerCurve25519PrivateKey = convertEd25519PrivateKeyToCurve25519(ephemeralKeyPair.secretKey);

  // GENERATE SHARED SECRET
  const sharedKey = getSharedKey(ServerCurve25519PrivateKey, clientCurve25519PublicKey);
  logger.debug(`Server shared key (Base64):${Buffer.from(sharedKey).toString('base64')}`);

  // ENCRYPT CHALLENGE USING USER PUBLIC KEY
  const challengeEncrypt = encryptWithSharedKey(challenge, sharedKey);

  // CREATE SESSION
  req.session.user = { ...body, userId, challenge };
  req.session.keystore = {
    publicKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    privateKey: Buffer.from(ephemeralKeyPair.secretKey).toString('base64'),
    sharedKey: Buffer.from(sharedKey).toString('base64'),
  };
  return { ephemeralKeyPair, userId, challengeEncrypt };
}

/**
 * Add user to table
 * * Generate 6 digit random number
 * * Encrypt the andom number with shared key
 * * Add user to table
 * * Send verification email
 * @param {Buffer} sharedKey
 * @param {*} user
 * @returns Encrypted registration code
 */
async function addUserToTable(sharedKey, user) {
  const registrationCode = generate6digitRandomNumber();

  // ENCRYPT REGISTRATION CODE
  const encryptedRegistrationCode = encryptWithSharedKey(registrationCode.toString(), sharedKey);

  // CREATE USER IN DB
  const createUser = await userService.entradaMethodCreateUser({ ...user, registrationCode });

  // SEND VERIFICATION EMAIL
  const verifyEmailToken = await tokenService.generateVerifyEmailToken(createUser);
  await emailService.sendVerificationEmail(createUser.username, verifyEmailToken);
  return encryptedRegistrationCode;
}

module.exports = {
  verifyEmail,
  loginUsingPublicKey,
  entradaAuthRegistration,
  addUserToTable,
  generate6digitRandomNumber,
};
