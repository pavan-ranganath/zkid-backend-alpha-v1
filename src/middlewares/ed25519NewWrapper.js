const asn1 = require('asn1.js');

const eddsa = require('elliptic');
const tweetNacl = require('tweetnacl');
const tweetNaclUtil = require('tweetnacl-util');

const _ed2curve = require('ed2curve');
const logger = require('../config/logger');

const ed25519EllipticLib = new eddsa.eddsa('ed25519');

/**
 * Removes the '-----BEGIN PUBLIC KEY-----' and '-----END PUBLIC KEY-----' from string
 * @param {String} publicKey
 * @returns key
 */
const readPublicKeyFromPem = (publicKey) => {
  const pemToBuffer = (pem) =>
    Buffer.from(
      pem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace(/\n/g, ''),
      'base64'
    );
  return pemToBuffer(publicKey);
};

/**
 * Removes the '-----BEGIN PRIVATE KEY-----' and '-----END PRIVATE KEY-----' from string
 * @param {String} privateKey
 * @returns
 */
const readPrivateKeyFromPem = (privateKey) => {
  const pemToBuffer = (pem) =>
    Buffer.from(
      pem.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').replace(/\n/g, ''),
      'base64'
    );

  return pemToBuffer(privateKey);
};

// Define the ASN.1 schema for Ed25519 private keys
const Ed25519PrivateKey = asn1.define('Ed25519PrivateKey', function () {
  return this.seq().obj(
    this.key('tbsCertificate').int(),
    this.key('signatureAlgorithm').seq().obj(this.key('algorithm').objid()),
    this.key('key').octstr().obj(this.key('privateKey').octstr())
  );
});

// Define the ASN.1 schema for Ed25519 public key
const Ed25519PublicKey = asn1.define('PublicKey', function () {
  this.seq().obj(
    this.key('tbsCertificate').seq().obj(this.key('signatureAlgorithm').objid()),
    this.key('signatureValue').bitstr()
  );
});

/**
 * Read openssl public key and parse it through ASN.1 decoder
 * @param {String} OpensslEd25519PublicKey
 * @returns public key
 */
const readOpenSslPublicKeys = (OpensslEd25519PublicKey) => {
  try {
    const extractedOnlyOpensslPublicKey = readPublicKeyFromPem(OpensslEd25519PublicKey);
    // Parse the ASN.1 public key
    const parsedServerPublicKey = Ed25519PublicKey.decode(extractedOnlyOpensslPublicKey, 'der');
    return parsedServerPublicKey.signatureValue.data;
  } catch (error) {
    logger.error('Failed to Read public keys', error);
    throw new Error('Failed to Read public the keys');
  }
};

/**
 * Read openssl pivate key and parse it through ASN.1 decoder
 * @param {String} OpensslEd25519PrivateKey
 * @returns private key
 */
const readOpenSslPrivateKeys = (OpensslEd25519PrivateKey) => {
  try {
    const extractedOnlyOpensslPrivateKey = readPrivateKeyFromPem(OpensslEd25519PrivateKey);
    // Parse the ASN.1 private key
    const parsedServerPrivateKey = Ed25519PrivateKey.decode(Buffer.from(extractedOnlyOpensslPrivateKey), 'der');
    return parsedServerPrivateKey.key.privateKey;
  } catch (error) {
    logger.error('Failed to Read private keys', error);
    throw new Error('Failed to Read private the keys');
  }
};

/**
 * Read openssl pivate key and public key and parse it through ASN.1 decoder
 * @param {String} privateKey
 * @param {String} publicKey
 * @returns
 */
const readKeysFromPem = (privateKey, publicKey) => {
  const publicKeyBuffer = readOpenSslPublicKeys(publicKey);
  const privateKeyBuffer = readOpenSslPrivateKeys(privateKey);

  return {
    publicKey: publicKeyBuffer,
    privateKey: privateKeyBuffer,
  };
};
const readOpenSslKeys = (OpensslEd25519PrivateKey, OpensslEd25519PublicKey) => {
  try {
    const parsedOnlyOpensslKeys = readKeysFromPem(OpensslEd25519PrivateKey, OpensslEd25519PublicKey);
    return { privateKey: parsedOnlyOpensslKeys.privateKey, publicKey: parsedOnlyOpensslKeys.publicKey };
  } catch (error) {
    logger.error('Failed to Read the keys', error);
    throw new Error('Failed to Read the keys');
  }
};

/**
 * Sign the message using ED25519 private key
 * @param {String} msg
 * @param {Uint8Array} privateKey
 * @returns
 */
const sign = (msg, privateKey) => {
  try {
    return ed25519EllipticLib.sign(msg, privateKey);
  } catch (error) {
    logger.error('Failed to sign the msg', error);
    throw new Error('Failed to sign the msg');
  }
};

/**
 * Generate key pair
 * @returns generate public and private key
 */
const generateKeyPair = () => {
  try {
    // let t = new eddsa.ec("ed25519")
    return tweetNacl.sign.keyPair();
  } catch (error) {
    logger.error('Error generating keypair', error);
    throw new Error('Error generating keypair');
  }
};

/**
 * Verify signature using public key
 * @param {Buffer} signedMsg
 * @param {Buffer} plainMsg
 * @param {Buffer} clientPublicKey
 * @returns
 */
const verifySign = (signature, plainMsg, clientPublicKey) => {
  return ed25519EllipticLib.verify(plainMsg, signature, clientPublicKey.toString('hex'));
};

/**
 * Generate shared key using
 * @param {Uint8Array} privateKey
 * @param {Uint8Array} publicKey
 * @returns
 */
const getSharedKey = (privateKey, publicKey) => {
  try {
    return tweetNacl.box.before(publicKey, privateKey);
  } catch (error) {
    logger.error('Error generating shared key', error);
    throw new Error('Error generating shared key');
  }
};

/**
 * Convert Private Ed25519 to curve25519
 * @param {Uint8Array} privateKey
 * @returns key
 */
const convertEd25519PrivateKeyToCurve25519 = (privateKey) => {
  return _ed2curve.convertSecretKey(privateKey);
};

/**
 * Convert Public Ed25519 to curve25519
 * @param {Uint8Array} publicKey
 * @returns key
 */
const convertEd25519PublicKeyToCurve25519 = (publicKey) => {
  return _ed2curve.convertPublicKey(publicKey);
};

// Encrypt the message using the shared key
const encryptWithSharedKey = (message, sharedKey) => {
  const nonce = tweetNacl.randomBytes(tweetNacl.box.nonceLength);
  const messageUint8 = tweetNaclUtil.decodeUTF8(message);
  const encrypted = tweetNacl.box.after(messageUint8, nonce, sharedKey);
  const encryptedMessage = new Uint8Array(nonce.length + encrypted.length);
  encryptedMessage.set(nonce);
  encryptedMessage.set(encrypted, nonce.length);
  return tweetNaclUtil.encodeBase64(encryptedMessage);
};

// Decrypt the encrypted message using the shared key
const decryptWithSharedKey = (encryptedMessage, sharedKey) => {
  const encryptedMessageUint8 = tweetNaclUtil.decodeBase64(encryptedMessage);
  const nonce = encryptedMessageUint8.slice(0, tweetNacl.box.nonceLength);
  const message = encryptedMessageUint8.slice(tweetNacl.box.nonceLength);
  const decrypted = tweetNacl.box.open.after(message, nonce, sharedKey);
  if (!decrypted) {
    throw new Error('Failed to decrypt message.');
  }
  return tweetNaclUtil.encodeUTF8(decrypted);
};

// Generate random bytes
const generateRandomBytes = () => {
  return tweetNacl.randomBytes(tweetNacl.box.nonceLength);
};
module.exports = {
  sign,
  generateKeyPair,
  readOpenSslPublicKeys,
  verifySign,
  getSharedKey,
  convertEd25519PrivateKeyToCurve25519,
  convertEd25519PublicKeyToCurve25519,
  encryptWithSharedKey,
  decryptWithSharedKey,
  generateRandomBytes,
};
