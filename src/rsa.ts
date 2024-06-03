import {
  validate as asn1Validate,
  create as asn1Create,
  Class as Asn1Class,
  Type as Asn1Type,
  
  integerToDer,
  fromDer,
  type Asn1
} from "./asn1";

import { createBuffer, hexToBytes } from "./util";

// for finding primes, which are 30k+i for i = 1, 7, 11, 13, 17, 19, 23, 29
const GCD_30_DELTA = [6, 4, 2, 4, 2, 4, 6, 2];

// validator for a PrivateKeyInfo structure
const privateKeyValidator = {
  // PrivateKeyInfo
  name: 'PrivateKeyInfo',
  tagClass: Asn1Class.UNIVERSAL,
  type: Asn1Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'PrivateKeyInfo.version',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion'
  }, {
    // privateKeyAlgorithm
    name: 'PrivateKeyInfo.privateKeyAlgorithm',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.SEQUENCE,
    constructed: true,
    value: [{
      name: 'AlgorithmIdentifier.algorithm',
      tagClass: Asn1Class.UNIVERSAL,
      type: Asn1Type.OID,
      constructed: false,
      capture: 'privateKeyOid'
    }]
  }, {
    // PrivateKey
    name: 'PrivateKeyInfo',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.OCTETSTRING,
    constructed: false,
    capture: 'privateKey'
  }]
};

// validator for an RSA private key
const rsaPrivateKeyValidator = {
  // RSAPrivateKey
  name: 'RSAPrivateKey',
  tagClass: Asn1Class.UNIVERSAL,
  type: Asn1Type.SEQUENCE,
  constructed: true,
  value: [{
    // Version (INTEGER)
    name: 'RSAPrivateKey.version',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyVersion'
  }, {
    // modulus (n)
    name: 'RSAPrivateKey.modulus',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyModulus'
  }, {
    // publicExponent (e)
    name: 'RSAPrivateKey.publicExponent',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPublicExponent'
  }, {
    // privateExponent (d)
    name: 'RSAPrivateKey.privateExponent',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrivateExponent'
  }, {
    // prime1 (p)
    name: 'RSAPrivateKey.prime1',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime1'
  }, {
    // prime2 (q)
    name: 'RSAPrivateKey.prime2',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyPrime2'
  }, {
    // exponent1 (d mod (p-1))
    name: 'RSAPrivateKey.exponent1',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent1'
  }, {
    // exponent2 (d mod (q-1))
    name: 'RSAPrivateKey.exponent2',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyExponent2'
  }, {
    // coefficient ((inverse of q) mod p)
    name: 'RSAPrivateKey.coefficient',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'privateKeyCoefficient'
  }]
};

// validator for an RSA public key
const rsaPublicKeyValidator = {
  // RSAPublicKey
  name: 'RSAPublicKey',
  tagClass: Asn1Class.UNIVERSAL,
  type: Asn1Type.SEQUENCE,
  constructed: true,
  value: [{
    // modulus (n)
    name: 'RSAPublicKey.modulus',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'publicKeyModulus'
  }, {
    // publicExponent (e)
    name: 'RSAPublicKey.exponent',
    tagClass: Asn1Class.UNIVERSAL,
    type: Asn1Type.INTEGER,
    constructed: false,
    capture: 'publicKeyExponent'
  }]
};

/**
 * Converts a private key from an ASN.1 object.
 *
 * @param obj the ASN.1 representation of a PrivateKeyInfo containing an
 *          RSAPrivateKey or an RSAPrivateKey.
 *
 * @return the private key.
 * TODO: type the return value
 */
export function privateKeyFromAsn1 (obj: Asn1): { privateKeyBytes: any } {
  // get PrivateKeyInfo
  var capture = {};
  var errors = [];
  if(asn1Validate(obj, privateKeyValidator, capture, errors)) {
    obj = fromDer(createBuffer(capture.privateKey));
  }

  // get RSAPrivateKey
  capture = {};
  errors = [];
  if(!asn1Validate(obj, rsaPrivateKeyValidator, capture, errors)) {
    var error = new Error('Cannot read private key. ' +
      'ASN.1 object does not contain an RSAPrivateKey.');
    // @ts-expect-error
    error.errors = errors;
    throw error;
  }

  // Note: Version is currently ignored.
  // capture.privateKeyVersion
  // FIXME: inefficient, get a BigInteger that uses byte strings
  var n, e, d, p, q, dP, dQ, qInv;
  n = createBuffer(capture.privateKeyModulus).toHex();
  e = createBuffer(capture.privateKeyPublicExponent).toHex();
  d = createBuffer(capture.privateKeyPrivateExponent).toHex();
  p = createBuffer(capture.privateKeyPrime1).toHex();
  q = createBuffer(capture.privateKeyPrime2).toHex();
  dP = createBuffer(capture.privateKeyExponent1).toHex();
  dQ = createBuffer(capture.privateKeyExponent2).toHex();
  qInv = createBuffer(capture.privateKeyCoefficient).toHex();

  // set private key
  return setRsaPrivateKey(
    new BigInteger(n, 16),
    new BigInteger(e, 16),
    new BigInteger(d, 16),
    new BigInteger(p, 16),
    new BigInteger(q, 16),
    new BigInteger(dP, 16),
    new BigInteger(dQ, 16),
    new BigInteger(qInv, 16));
};

/**
 * Converts a private key to an ASN.1 RSAPrivateKey.
 *
 * @param key the private key.
 *
 * @return the ASN.1 representation of an RSAPrivateKey.
 */
export function privateKeyToAsn1 (key): Asn1 {
  // RSAPrivateKey
  return asn1Create(Asn1Class.UNIVERSAL, Asn1Type.SEQUENCE, true, [
    // version (0 = only 2 primes, 1 multiple primes)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      integerToDer(0).getBytes()),
    // modulus (n)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.n)),
    // publicExponent (e)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.e)),
    // privateExponent (d)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.d)),
    // privateKeyPrime1 (p)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.p)),
    // privateKeyPrime2 (q)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.q)),
    // privateKeyExponent1 (dP)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.dP)),
    // privateKeyExponent2 (dQ)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.dQ)),
    // coefficient (qInv)
    asn1Create(Asn1Class.UNIVERSAL, Asn1Type.INTEGER, false,
      _bnToBytes(key.qInv))
  ]);
};

export { privateKeyToAsn1 as privateKeyToRSAPrivateKey }

/**
 * Converts a positive BigInteger into 2's-complement big-endian bytes.
 *
 * @param b the big integer to convert.
 *
 * @return the bytes.
 */
function _bnToBytes (b: number): string {
  // prepend 0x00 if first byte >= 0x80
  var hex = b.toString(16);
  if(hex[0] >= '8') {
    hex = '00' + hex;
  }
  var bytes = hexToBytes(hex);

  // ensure integer is minimally-encoded
  if(bytes.length > 1 &&
    // leading 0x00 for positive integer
    ((bytes.charCodeAt(0) === 0 &&
    (bytes.charCodeAt(1) & 0x80) === 0) ||
    // leading 0xFF for negative integer
    (bytes.charCodeAt(0) === 0xFF &&
    (bytes.charCodeAt(1) & 0x80) === 0x80))) {
    return bytes.substr(1);
  }

  return bytes;
}