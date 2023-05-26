const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { authService } = require('../services');

const { readOpenSslPublicKeys, verifySign, decryptWithSharedKey } = require('../middlewares/ed25519NewWrapper');

/**
 * Register new user
 * read -
 * * username, publickey, signature, message
 * process -
 * * Check if user exists
 * * Validate the signature
 * * Generate the challenge
 * * Generate Ephermal key pair
 * * Generate shared key
 * * Encrypt the challenge with shared key
 * * Create session and storer user info with key pair
 * return -
 * * encrypted challenge, ephemeral Public Key, user ID
 */
const EntadaAuthRegistration = catchAsync(async (req, res) => {
  const { body } = req;
  const { ephemeralKeyPair, userId, challengeEncrypt } = await authService.entradaAuthRegistration(body, req);
  const respObj = {
    challengeEncrypt,
    ephemeralPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    userId,
  };
  res.send(respObj);
});

/**
 * 2nd step of registration process
 * read -
 * * signature, enncryppted data
 * process -
 * * Check if user session exists
 * * Retrieve user info and key pairs
 * * Verify signature
 * * Decrypt the challenge with shared key
 * * Verify the challenge
 * * Generate the registration code
 * * Encypt the registration code
 * * Add user to the table
 * * Send verification email
 * return -
 * * encrypted registration code, user id
 */
const EntadaAuthRegistrationVerify = catchAsync(async (req, res) => {
  const { body } = req;
  const { encryptedData } = body;
  const { signature } = body;

  if (req.session.user) {
    const { user } = req.session;
    const keyStore = req.session.keystore;
    const sharedKey = Buffer.from(keyStore.sharedKey, 'base64');
    // VERIFY SIGNATURE USING USER PUBLIC KEY
    const clientPublicKey = readOpenSslPublicKeys(user.publicKey);
    if (!verifySign(signature, encryptedData, clientPublicKey)) {
      return res.status(400).send({ error: 'Signature verification failed' });
    }

    // DECRYPT THE CHALLENGE USING SHARED KEY
    const decryptedChallenge = decryptWithSharedKey(encryptedData, sharedKey);
    const challengeObj = JSON.parse(decryptedChallenge);

    // COMPARE CHALLENGE
    if (challengeObj.challenge !== user.challenge) {
      return res.status(400).send({ error: 'Challenge verification failed' });
    }

    // ADD USER TO TABLE AND GENERATE REGISTRATION CODE
    const encryptedRegistrationCode = await authService.addUserToTable(sharedKey, user);

    // SEND ENCRYPTED REGISTRATION CODE AND USER INFO
    const respObj = {
      registrationCode: encryptedRegistrationCode,
      userId: user.userId,
    };
    res.send(respObj);
  }
});

/**
 * Login user
 * read -
 * * username, signature and message
 * Process -
 * * Check email and public exist
 * * Verify signature using user public key in table
 * * If email not verified send email
 * * Generate EPHEMERAL key
 * * Generate shared key
 * * Create session and storre user info
 * return -
 * Updated user info
 */
const EntadaAuthLogin = catchAsync(async (req, res) => {
  const { body } = req;
  const { username, plainMsg, signature } = body;
  const { user, ephemeralKeyPair, sharedKey } = await authService.loginUsingPublicKey(username, plainMsg, signature);

  // CREATE SESSION
  req.session.user = user;
  req.session.keystore = { ephemeralKeyPair, sharedKey };

  const respObj = {
    ephemeralPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    user,
  };
  return res.status(200).send({ status: 'success', ...respObj });
});

/**
 * Email verification reequest
 * Read -
 * * token
 * Process -
 * * Verify the token
 * * Update user table
 * * Delete all the email verification token of that user
 * Return -
 * * User info
 */
const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token);
  res.status(httpStatus.NO_CONTENT).send();
});

module.exports = {
  EntadaAuthRegistration,
  EntadaAuthRegistrationVerify,
  EntadaAuthLogin,
  verifyEmail,
};
