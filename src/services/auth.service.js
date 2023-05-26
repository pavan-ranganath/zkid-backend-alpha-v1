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
  sign,
  generateKeyPair,
  readOpenSslPublicKeys,
  verifySign,
  getSharedKey,
  encryptWithSharedKey,
  convertEd25519PublicKeyToCurve25519,
  convertEd25519PrivateKeyToCurve25519,
} = require('../middlewares/ed25519NewWrapper');
const logger = require('../config/logger');

/**
 * Verify email
 * @param {string} verifyEmailToken
 * @returns {Promise}
 */
const verifyEmail = async (verifyEmailToken) => {
  try {
    const verifyEmailTokenDoc = await tokenService.verifyToken(verifyEmailToken, tokenTypes.VERIFY_EMAIL);
    const user = await userService.getUserById(verifyEmailTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await Token.deleteMany({ user: user.id, type: tokenTypes.VERIFY_EMAIL });
    await userService.updateUserById(user.id, { isEmailVerified: true });
  } catch (error) {
    logger.error(error);
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
  }
};

/**
 * Check email exists
 * @param {string} email
 * @returns {Promise<User>}
 */
const loginUsingPublicKey = async (username, plainMsg, signedMsg) => {
  await userService.checkEmailEntradaCustomUser(username);
  const user = await userService.getEntradaAuthUserByEmail(username);

  // VERIFY SIGNATURE USING USER PUBLIC KEY
  const clientPublicKey = readOpenSslPublicKeys(user.publicKey);
  if (!verifySign(signedMsg, plainMsg, clientPublicKey)) {
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

async function entradaAuthRegistration(body, username, req) {
  const userPublicKey = body.publicKey;
  const { signedMsg } = body;
  const { plainMsg } = body;

  // CHECK USER EXISTS
  await userService.checkEmailEntradaCustomUser(username, userPublicKey);

  // VALIDATE SIGNATURE
  const clientPublicKey = readOpenSslPublicKeys(userPublicKey);
  if (!verifySign(signedMsg, plainMsg, clientPublicKey)) {
    throw new Error('Signature verification failed');
  }

  const userId = uuidv4();

  // GENERATE CHALLENGE
  const challenge = Buffer.from(generateRandomBytes()).toString('base64');
  logger.log('challenge', challenge);

  // GENERTE EPHEMERAL KEY
  const ephemeralKeyPair = generateKeyPair();
  logger.log('serverPrivateKey', Buffer.from(ephemeralKeyPair.secretKey).toString('base64'));
  logger.log('serverPublicKey', Buffer.from(ephemeralKeyPair.publicKey).toString('base64'));

  // ED25519 -> curve25519
  const clientCurve25519PublicKey = convertEd25519PublicKeyToCurve25519(clientPublicKey);
  const ServerCurve25519PrivateKey = convertEd25519PrivateKeyToCurve25519(ephemeralKeyPair.secretKey);

  // GENERATE SHARED SECRET
  const sharedKey = getSharedKey(ServerCurve25519PrivateKey, clientCurve25519PublicKey);
  logger.log('Server shared key (Base64):', Buffer.from(sharedKey).toString('base64'));

  // ENCRYPT CHALLENGE USING USER PUBLIC KEY
  const challengeEncrypt = encryptWithSharedKey(challenge, sharedKey);

  const signedChallengeEncrypt = sign(challengeEncrypt, ephemeralKeyPair.secretKey);
  // let verifyMsg =  verifySign(challengeEncrypt,signedChallengeEncrypt,ephemeralKeyPair.publicKey)

  // CREATE SESSION
  req.session.user = { ...body, userId, challenge };
  req.session.keystore = {
    publicKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    privateKey: Buffer.from(ephemeralKeyPair.secretKey).toString('base64'),
    sharedKey: Buffer.from(sharedKey).toString('base64'),
  };
  return { ephemeralKeyPair, userId, challengeEncrypt, signedChallengeEncrypt };
}
module.exports = {
  verifyEmail,
  loginUsingPublicKey,
  entradaAuthRegistration,
};
