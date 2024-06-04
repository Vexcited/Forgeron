import {
  fromDer as asn1FromDer,
  toDer as asn1ToDer,
  
  type Asn1
} from "./asn1";

import {
  decode as pemDecode,
  encode as pemEncode
} from "./pem";

import { privateKeyFromAsn1, privateKeyToAsn1 } from "./rsa";

import { type ByteStringBuffer, createBuffer } from "./util";

/**
 * Converts PEM-formatted data to DER.
 *
 * @param pem the PEM-formatted data.
 *
 * @return the DER-formatted data.
 * @deprecated Use pem.decode() instead.
 */
export function pemToDer (pem: string): ByteStringBuffer {
  const msg = pemDecode(pem)[0];
  
  if (msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert PEM to DER; PEM is encrypted.');
  }

  return createBuffer(msg.body);
};

/**
 * Converts an RSA private key from PEM format.
 *
 * @param pem the PEM-formatted private key.
 *
 * @return the private key.
 */
export function privateKeyFromPem (pem: string) {
  var msg = pemDecode(pem)[0];

  if(msg.type !== 'PRIVATE KEY' && msg.type !== 'RSA PRIVATE KEY') {
    var error = new Error('Could not convert private key from PEM; PEM ' +
      'header type is not "PRIVATE KEY" or "RSA PRIVATE KEY".');
    // TODO: write a custom Error for this
    // @ts-expect-error
    error.headerType = msg.type;
    throw error;
  }
  if(msg.procType && msg.procType.type === 'ENCRYPTED') {
    throw new Error('Could not convert private key from PEM; PEM is encrypted.');
  }

  // convert DER to ASN.1 object
  var obj = asn1FromDer(msg.body);

  return privateKeyFromAsn1(obj);
};

/**
 * Converts an RSA private key to PEM format.
 *
 * @param key the private key.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
export function privateKeyToPem (key, maxline?: number): string {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'RSA PRIVATE KEY',
    body: asn1ToDer(privateKeyToAsn1(key)).getBytes()
  };

  return pemEncode(msg, { maxline });
};

/**
 * Converts a PrivateKeyInfo to PEM format.
 *
 * @param pki the PrivateKeyInfo.
 * @param maxline the maximum characters per line, defaults to 64.
 *
 * @return the PEM-formatted private key.
 */
export function privateKeyInfoToPem (pki: Asn1, maxline?: number): string {
  // convert to DER, then PEM-encode
  var msg = {
    type: 'PRIVATE KEY',
    body: asn1ToDer(pki).getBytes()
  };

  return pemEncode(msg, { maxline });
};

/** @was forge.pki.setRsaPrivateKey */
export { setPrivateKey as setRsaPrivateKey } from "./rsa";
/** @was forge.pki.setRsaPublicKey */
export { setPublicKey as setRsaPublicKey } from "./rsa";