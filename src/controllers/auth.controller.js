const catchAsync = require('../utils/catchAsync');
const { authService, userService, tokenService, emailService } = require('../services');


const { readOpenSslPublicKeys, verifySign, encryptWithSharedKey, decryptWithSharedKey } = require('../middlewares/ed25519NewWrapper')




const EntadaAuthRegistration = catchAsync(async (req, res) => {
  const body = req.body;
  const username = body.username;
  const { ephemeralKeyPair, userId, challengeEncrypt, signedChallengeEncrypt } = await authService.entradaAuthRegistration(body, username, req);
  console.log("ephemeralKeyPair.publicKey", ephemeralKeyPair.publicKey)
  const respObj = {
    challengeEncrypt: challengeEncrypt,
    signedChallengeEncrypt: signedChallengeEncrypt.toHex(),
    ephemeralPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    userId: userId
  }
  res.send(respObj)
});


const EntadaAuthRegistrationVerify = catchAsync(async (req, res) => {
  const body = req.body;
  const encryptedData = body.encryptedData;
  const signature = body.signature;
  // console.log(req.session);

  if (req.session.user) {
    let user = req.session.user
    let keyStore = req.session.keystore
    let sharedKey = Buffer.from(keyStore.sharedKey, "base64")
    // VERIFY SIGNATURE USING USER PUBLIC KEY
    const clientPublicKey = readOpenSslPublicKeys(user.publicKey)
    if (!verifySign(signature, encryptedData, clientPublicKey)) {
      return res.status(400).send({ error: "Signature verification failed" });
    }

    // DECRYPT THE CHALLENGE USING SHARED KEY

    let decryptedChallenge = decryptWithSharedKey(encryptedData, sharedKey)
    let challengeObj = JSON.parse(decryptedChallenge)
    // COMPARE CHALLENGE
    if (challengeObj.challenge != user.challenge) {
      return res.status(400).send({ error: "Challenge verification failed" });
    }
    // GENERATE REGISTRATION CODE
    let registrationCode = generate6digitRandomNumber()

    // ENCRYPT REGISTRATION CODE
    let encryptedRegistrationCode = encryptWithSharedKey(registrationCode.toString(), sharedKey)

    // CREATE USER IN DB
    const createUser = await userService.entradaMethodCreateUser({ ...user, registrationCode: registrationCode });

    // SEND ENCRYPTED REGISTRATION CODE AND USER INFO
    const respObj = {
      registrationCode: encryptedRegistrationCode,
      userId: user.userId
    }
    const verifyEmailToken = await tokenService.generateVerifyEmailToken(createUser);
    await emailService.sendVerificationEmail(createUser.username, verifyEmailToken);

    res.send(respObj)
  }
})

const EntadaAuthLogin = catchAsync(async (req, res) => {
  const body = req.body;
  const username = body.username;
  const plainMsg = body.plainMsg;
  const signature = body.signature;
  let {user, ephemeralKeyPair, sharedKey} = await authService.loginUsingPublicKey(username, plainMsg, signature);

  
  // CREATE SESSION
  req.session.user = user
  req.session.keystore = { ephemeralKeyPair: ephemeralKeyPair, sharedKey }

  const respObj = {
    ephemeralPubKey: Buffer.from(ephemeralKeyPair.publicKey).toString('base64'),
    user: user
  }
  return res.status(200).send({ status: "success", ...respObj })
})
const verifyEmail = catchAsync(async (req, res) => {
  await authService.verifyEmail(req.query.token);
  res.status(httpStatus.NO_CONTENT).send();
});

function generate6digitRandomNumber() {
  var minm = 100000;
  var maxm = 999999;
  return Math.floor(Math
  .random() * (maxm - minm + 1)) + minm;
}
module.exports = {
  EntadaAuthRegistration,
  EntadaAuthRegistrationVerify,
  EntadaAuthLogin,
  verifyEmail
};


