const httpStatus = require('http-status');
const catchAsync = require('../utils/catchAsync');
const { authService, userService, tokenService, emailService } = require('../services');
const logger = require('../config/logger');

const {
  readOpenSslPublicKeys,
  verifySign,
  encryptWithSharedKey,
  decryptWithSharedKey,
} = require('../middlewares/ed25519NewWrapper');

function generate6digitRandomNumber() {
  const minm = 100000;
  const maxm = 999999;
  return Math.floor(Math.random() * (maxm - minm + 1)) + minm;
}

const EntadaAuthRegistration = catchAsync(async (req, res) => {
  const { body } = req;
  const { username } = body;
  const { ephemeralKeyPair, userId, challengeEncrypt, signedChallengeEncrypt } = await authService.entradaAuthRegistration(
    body,
    username,
    req
  );
  logger.log('ephemeralKeyPair.publicKey', ephemeralKeyPair.publicKey);
  const respObj = {
    challengeEncrypt,
    signedChallengeEncrypt: signedChallengeEncrypt.toHex(),
    ephemeralPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    userId,
  };
  res.send(respObj);
});

const EntadaAuthRegistrationVerify = catchAsync(async (req, res) => {
  const { body } = req;
  const { encryptedData } = body;
  const { signature } = body;
  // logger.log(req.session);

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
    // GENERATE REGISTRATION CODE
    const registrationCode = generate6digitRandomNumber();

    // ENCRYPT REGISTRATION CODE
    const encryptedRegistrationCode = encryptWithSharedKey(registrationCode.toString(), sharedKey);

    // CREATE USER IN DB
    const createUser = await userService.entradaMethodCreateUser({ ...user, registrationCode });

    // SEND ENCRYPTED REGISTRATION CODE AND USER INFO
    const respObj = {
      registrationCode: encryptedRegistrationCode,
      userId: user.userId,
    };
    const verifyEmailToken = await tokenService.generateVerifyEmailToken(createUser);
    await emailService.sendVerificationEmail(createUser.username, verifyEmailToken);

    res.send(respObj);
  }
});

const EntadaAuthLogin = catchAsync(async (req, res) => {
  const { body } = req;
  const { username } = body;
  const { plainMsg } = body;
  const { signature } = body;
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
