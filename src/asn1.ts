/*
 * JavaScript implementation of Abstract Syntax Notation Number One.
 *
 * An API for storing data using the Abstract Syntax Notation Number One
 * format using DER (Distinguished Encoding Rules) encoding. This encoding is
 * commonly used to store data for PKI, i.e. X.509 Certificates, and this
 * implementation exists for that purpose.
 *
 * Abstract Syntax Notation Number One (ASN.1) is used to define the abstract
 * syntax of information without restricting the way the information is encoded
 * for transmission. It provides a standard that allows for open systems
 * communication. ASN.1 defines the syntax of information data and a number of
 * simple data types as well as a notation for describing them and specifying
 * values for them.
 *
 * The RSA algorithm creates public and private keys that are often stored in
 * X.509 or PKCS#X formats -- which use ASN.1 (encoded in DER format). This
 * class provides the most basic functionality required to store and load DSA
 * keys that are encoded according to ASN.1.
 *
 * The most common binary encodings for ASN.1 are BER (Basic Encoding Rules)
 * and DER (Distinguished Encoding Rules). DER is just a subset of BER that
 * has stricter requirements for how data must be encoded.
 *
 * Each ASN.1 structure has a tag (a byte identifying the ASN.1 structure type)
 * and a byte array for the value of this ASN1 structure which may be data or a
 * list of ASN.1 structures.
 *
 * Each ASN.1 structure using BER is (Tag-Length-Value):
 *
 * | byte 0 | bytes X | bytes Y |
 * |--------|---------|----------
 * |  tag   | length  |  value  |
 *
 * ASN.1 allows for tags to be of "High-tag-number form" which allows a tag to
 * be two or more octets, but that is not supported by this class. A tag is
 * only 1 byte. Bits 1-5 give the tag number (ie the data type within a
 * particular 'class'), 6 indicates whether or not the ASN.1 value is
 * constructed from other ASN.1 values, and bits 7 and 8 give the 'class'. If
 * bits 7 and 8 are both zero, the class is UNIVERSAL. If only bit 7 is set,
 * then the class is APPLICATION. If only bit 8 is set, then the class is
 * CONTEXT_SPECIFIC. If both bits 7 and 8 are set, then the class is PRIVATE.
 * The tag numbers for the data types for the class UNIVERSAL are listed below:
 *
 * UNIVERSAL 0 Reserved for use by the encoding rules
 * UNIVERSAL 1 Boolean type
 * UNIVERSAL 2 Integer type
 * UNIVERSAL 3 Bitstring type
 * UNIVERSAL 4 Octetstring type
 * UNIVERSAL 5 Null type
 * UNIVERSAL 6 Object identifier type
 * UNIVERSAL 7 Object descriptor type
 * UNIVERSAL 8 External type and Instance-of type
 * UNIVERSAL 9 Real type
 * UNIVERSAL 10 Enumerated type
 * UNIVERSAL 11 Embedded-pdv type
 * UNIVERSAL 12 UTF8String type
 * UNIVERSAL 13 Relative object identifier type
 * UNIVERSAL 14-15 Reserved for future editions
 * UNIVERSAL 16 Sequence and Sequence-of types
 * UNIVERSAL 17 Set and Set-of types
 * UNIVERSAL 18-22, 25-30 Character string types
 * UNIVERSAL 23-24 Time types
 *
 * The length of an ASN.1 structure is specified after the tag identifier.
 * There is a definite form and an indefinite form. The indefinite form may
 * be used if the encoding is constructed and not all immediately available.
 * The indefinite form is encoded using a length byte with only the 8th bit
 * set. The end of the constructed object is marked using end-of-contents
 * octets (two zero bytes).
 *
 * The definite form looks like this:
 *
 * The length may take up 1 or more bytes, it depends on the length of the
 * value of the ASN.1 structure. DER encoding requires that if the ASN.1
 * structure has a value that has a length greater than 127, more than 1 byte
 * will be used to store its length, otherwise just one byte will be used.
 * This is strict.
 *
 * In the case that the length of the ASN.1 value is less than 127, 1 octet
 * (byte) is used to store the "short form" length. The 8th bit has a value of
 * 0 indicating the length is "short form" and not "long form" and bits 7-1
 * give the length of the data. (The 8th bit is the left-most, most significant
 * bit: also known as big endian or network format).
 *
 * In the case that the length of the ASN.1 value is greater than 127, 2 to
 * 127 octets (bytes) are used to store the "long form" length. The first
 * byte's 8th bit is set to 1 to indicate the length is "long form." Bits 7-1
 * give the number of additional octets. All following octets are in base 256
 * with the most significant digit first (typical big-endian binary unsigned
 * integer storage). So, for instance, if the length of a value was 257, the
 * first byte would be set to:
 *
 * 10000010 = 130 = 0x82.
 *
 * This indicates there are 2 octets (base 256) for the length. The second and
 * third bytes (the octets just mentioned) would store the length in base 256:
 *
 * octet 2: 00000001 = 1 * 256^1 = 256
 * octet 3: 00000001 = 1 * 256^0 = 1
 * total = 257
 *
 * The algorithm for converting a js integer value of 257 to base-256 is:
 *
 * var value = 257;
 * var bytes = [];
 * bytes[0] = (value >>> 8) & 0xFF; // most significant byte first
 * bytes[1] = value & 0xFF;        // least significant byte last
 *
 * On the ASN.1 UNIVERSAL Object Identifier (OID) type:
 *
 * An OID can be written like: "value1.value2.value3...valueN"
 *
 * The DER encoding rules:
 *
 * The first byte has the value 40 * value1 + value2.
 * The following bytes, if any, encode the remaining values. Each value is
 * encoded in base 128, most significant digit first (big endian), with as
 * few digits as possible, and the most significant bit of each byte set
 * to 1 except the last in each value's encoding. For example: Given the
 * OID "1.2.840.113549", its DER encoding is (remember each byte except the
 * last one in each encoding is OR'd with 0x80):
 *
 * byte 1: 40 * 1 + 2 = 42 = 0x2A.
 * bytes 2-3: 128 * 6 + 72 = 840 = 6 72 = 6 72 = 0x0648 = 0x8648
 * bytes 4-6: 16384 * 6 + 128 * 119 + 13 = 6 119 13 = 0x06770D = 0x86F70D
 *
 * The final value is: 0x2A864886F70D.
 * The full OID (including ASN.1 tag and length of 6 bytes) is:
 * 0x06062A864886F70D
 */

import { ByteStringBuffer, createBuffer, isArray } from "./util";

/**
 * ASN.1 classes.
 * @was forge.asn1.Class
 */
export enum Class {
  UNIVERSAL = 0x00,
  APPLICATION = 0x40,
  CONTEXT_SPECIFIC = 0x80,
  PRIVATE = 0xC0
}

/**
 * ASN.1 types. Not all types are supported by this implementation, only
 * those necessary to implement a simple PKI are implemented.
 * @was forge.asn1.Type
 */
export enum Type {
  NONE = 0,
  BOOLEAN = 1,
  INTEGER = 2,
  BITSTRING = 3,
  OCTETSTRING = 4,
  NULL = 5,
  OID = 6,
  ODESC = 7,
  EXTERNAL = 8,
  REAL = 9,
  ENUMERATED = 10,
  EMBEDDED = 11,
  UTF8 = 12,
  ROID = 13,
  SEQUENCE = 16,
  SET = 17,
  PRINTABLESTRING = 19,
  IA5STRING = 22,
  UTCTIME = 23,
  GENERALIZEDTIME = 24,
  BMPSTRING = 30
};

export interface Asn1 {
  tagClass: Class;
  type: Type;
  constructed: boolean;
  composed: boolean;
  value: string | Asn1[];

  bitStringContents?: string;
  original?: Asn1;
}

/**
 * Creates a new asn1 object.
 *
 * @param tagClass the tag class for the object.
 * @param type the data type (tag number) for the object.
 * @param constructed true if the asn1 object is in constructed form.
 * @param value the value for the object, if it is not constructed.
 * @param options the options to use
 *
 * @return the asn1 object.
 * @was forge.asn1.create
 */
export function create (tagClass: Class, type: Type, constructed: boolean, value: string | Asn1[], options?: {
  /** the plain BIT STRING content including padding byte. */
  bitStringContents?: string
}): Asn1 {
  /* An asn1 object has a tagClass, a type, a constructed flag, and a
    value. The value's type depends on the constructed flag. If
    constructed, it will contain a list of other asn1 objects. If not,
    it will contain the ASN.1 value as an array of bytes formatted
    according to the ASN.1 data type. */

  // remove undefined values
  if (isArray(value)) {
    const tmp: Asn1[] = [];
    for (var i = 0; i < value.length; ++i) {
      if (value[i] !== undefined) {
        tmp.push(value[i]);
      }
    }
    value = tmp;
  }

  const obj: Asn1 = {
    tagClass: tagClass,
    type: type,
    constructed: constructed,
    composed: constructed || isArray(value),
    value: value
  };

  if (options && 'bitStringContents' in options) {
    // TODO: copy byte buffer if it's a buffer not a string
    obj.bitStringContents = options.bitStringContents;
    // TODO: add readonly flag to avoid this overhead
    // save copy to detect changes
    obj.original = copy(obj) as Asn1;
  }

  return obj;
};

/**
 * Copies an asn1 object.
 *
 * @param obj the asn1 object.
 * @param options copy options
 * @return the a copy of the asn1 object.
 * @was forge.asn1.copy
 */
export function copy (obj: Array<Asn1> | string | Asn1, options?: {
  /** `true` to not copy bitStringContents */
  excludeBitStringContents: boolean
}) {
  if (isArray(obj)) {
    const copyObj: Asn1[] = [];
    
    for (var i = 0; i < obj.length; ++i) {
      copyObj.push(copy(obj[i], options) as Asn1);
    }

    return copyObj;
  }

  if (typeof obj === 'string') {
    // TODO: copy byte buffer if it's a buffer not a string
    return obj;
  }

  const copyObj: Asn1 = {
    tagClass: obj.tagClass,
    type: obj.type,
    constructed: obj.constructed,
    composed: obj.composed,
    value: copy(obj.value, options) as string | Asn1[]
  };

  if (options && !options.excludeBitStringContents) {
    // TODO: copy byte buffer if it's a buffer not a string
    copyObj.bitStringContents = obj.bitStringContents;
  }
  return copyObj;
};

/**
 * Compares asn1 objects for equality.
 *
 * Note this function does not run in constant time.
 *
 * @param obj1 the first asn1 object.
 * @param obj2 the second asn1 object.
 * @return true if the asn1 objects are equal.
 * @was forge.asn1.equals
 */
export function equals (obj1: string | Asn1 | Asn1[], obj2: string | Asn1 | Asn1[], options?: {
  /** `true` to compare bitStringContents */
  includeBitStringContents: boolean
}): boolean {
  // If one of them is an array...
  if (isArray(obj1) || isArray(obj2)) {
    // If the other is not an array...
    if (!isArray(obj2) || !isArray(obj1)) {
      return false;
    }

    if (obj1.length !== obj2.length) {
      return false;
    }

    for (var i = 0; i < obj1.length; ++i) {
      if(!equals(obj1[i], obj2[i])) {
        return false;
      }
    }

    return true;
  }

  if (typeof obj1 !== typeof obj2) {
    return false;
  }

  if (typeof obj1 === 'string' || typeof obj2 === 'string') {
    return obj1 === obj2;
  }

  var equal = obj1.tagClass === obj2.tagClass &&
    obj1.type === obj2.type &&
    obj1.constructed === obj2.constructed &&
    obj1.composed === obj2.composed &&
    equals(obj1.value, obj2.value);
  
  if (options && options.includeBitStringContents) {
    equal = equal && (obj1.bitStringContents === obj2.bitStringContents);
  }

  return equal;
};

/**
 * Gets the length of a BER-encoded ASN.1 value.
 *
 * In case the length is not specified, undefined is returned.
 *
 * @param b the BER-encoded ASN.1 byte buffer, starting with the first
 *          length byte.
 *
 * @return the length of the BER-encoded ASN.1 value or undefined.
 * @was forge.asn1.getBerValueLength
 */
export function getBerValueLength (b: ByteStringBuffer): number | undefined {
  // TODO: move this function and related DER/BER functions to a der.js
  // file; better abstract ASN.1 away from der/ber.
  var b2 = b.getByte();
  if (b2 === 0x80) {
    return undefined;
  }

  // see if the length is "short form" or "long form" (bit 8 set)
  var length: number;
  var longForm = b2 & 0x80;
  if(!longForm) {
    // length is just the first byte
    length = b2;
  } else {
    // the number of bytes the length is specified in bits 7 through 1
    // and each length byte is in big-endian base-256
    length = b.getInt((b2 & 0x7F) << 3);
  }
  
  return length;
};

export class TooFewBytesDerError extends Error {
  available: number;
  remaining: number;
  requested: number;

  constructor(message: string, available: number, remaining: number, requested: number) {
    super(message);
    this.available = available;
    this.remaining = remaining;
    this.requested = requested;
  }
}

/**
 * Check if the byte buffer has enough bytes. Throws an [TooFewBytesDerError] if not.
 *
 * @param bytes the byte buffer to parse from.
 * @param remaining the bytes remaining in the current parsing state.
 * @param n the number of bytes the buffer must have.
 */
function _checkBufferLength (bytes: ByteStringBuffer, remaining: number, n:  number): void {
  if (n > remaining) {
    throw new TooFewBytesDerError('Too few bytes to parse DER.', 
      bytes.length(),
      remaining,
      n
    );
  }
}

/**
 * Gets the length of a BER-encoded ASN.1 value.
 *
 * In case the length is not specified, undefined is returned.
 *
 * @param bytes the byte buffer to parse from.
 * @param remaining the bytes remaining in the current parsing state.
 *
 * @return the length of the BER-encoded ASN.1 value or undefined.
 */
const _getValueLength = (bytes: ByteStringBuffer, remaining: number): number | undefined => {
  // TODO: move this function and related DER/BER functions to a der.js
  // file; better abstract ASN.1 away from der/ber.
  // fromDer already checked that this byte exists
  var b2 = bytes.getByte();
  remaining--;
  if (b2 === 0x80) {
    return void 0;
  }

  // see if the length is "short form" or "long form" (bit 8 set)
  var length: number;
  var longForm = b2 & 0x80;
  if (!longForm) {
    // length is just the first byte
    length = b2;
  } else {
    // the number of bytes the length is specified in bits 7 through 1
    // and each length byte is in big-endian base-256
    var longFormBytes = b2 & 0x7F;
    _checkBufferLength(bytes, remaining, longFormBytes);
    length = bytes.getInt(longFormBytes << 3);
  }

  // FIXME: this will only happen for 32 bit getInt with high bit set
  if (length < 0) {
    throw new Error('Negative length: ' + length);
  }

  return length;
};

export class UnparsedDerBytesRemainError extends Error {
  byteCount: number;
  remaining: number;

  constructor(message: string, byteCount: number, remaining: number) {
    super(message);
    this.byteCount = byteCount;
    this.remaining = remaining;
  }
}

/**
 * Parses an asn1 object from a byte buffer in DER format.
 *
 * @param bytes the byte buffer to parse from.
 * @param options object with options or boolean `strict` flag
 * 
 * @throws Will throw [UnparsedDerBytesRemainError] for various malformed input conditions.
 * @return the parsed asn1 object.
 * 
 * @was forge.asn1.fromDer
 */
export function fromDer (bytes: string | ByteStringBuffer, options?: boolean | {
  /**
   * `true` to be strict when checking value lengths, `false` to
   * allow truncated values
   * 
   * @default true
   */
  strict?: boolean;
  
  /**
   * true to ensure all bytes are parsed
   * 
   * @default true
   */
  parseAllBytes?: boolean;

  /**
   * `true` to attempt to decode the content of
   * BIT STRINGs (not OCTET STRINGs) using strict mode. Note that
   * without schema support to understand the data context this can
   * erroneously decode values that happen to be valid ASN.1. This
   * flag will be deprecated or removed as soon as schema support is
   * available.
   * 
   * @default true
   */
  decodeBitStrings?: boolean;
}): Asn1 {
  if (options === undefined) {
    options = {
      strict: true,
      parseAllBytes: true,
      decodeBitStrings: true
    };
  }

  if (typeof options === 'boolean') {
    options = {
      strict: options,
      parseAllBytes: true,
      decodeBitStrings: true
    };
  }

  if (!('strict' in options)) {
    options.strict = true;
  }

  if (!('parseAllBytes' in options)) {
    options.parseAllBytes = true;
  }

  if (!('decodeBitStrings' in options)) {
    options.decodeBitStrings = true;
  }

  // wrap in buffer if needed
  if(typeof bytes === 'string') {
    bytes = createBuffer(bytes);
  }

  const byteCount = bytes.length();
  const value = _fromDer(bytes, bytes.length(), 0, options);

  if (options.parseAllBytes && bytes.length() !== 0) {
    throw new UnparsedDerBytesRemainError('Unparsed DER bytes remain after ASN.1 parsing.',
      byteCount,
      bytes.length()
    );
  }

  return value;
};

/**
 * Internal function to parse an asn1 object from a byte buffer in DER format.
 *
 * @param bytes the byte buffer to parse from.
 * @param remaining the number of bytes remaining for this chunk.
 * @param depth the current parsing depth.
 * @param options object with same options as fromDer().
 *
 * @return the parsed asn1 object.
 */
function _fromDer (bytes: ByteStringBuffer, remaining: number, depth: number, options: {
  strict?: boolean;
  parseAllBytes?: boolean;
  decodeBitStrings?: boolean;
}): Asn1 {
  // temporary storage for consumption calculations
  var start: number;

  // minimum length for ASN.1 DER structure is 2
  _checkBufferLength(bytes, remaining, 2);

  // get the first byte
  var b1 = bytes.getByte();
  // consumed one byte
  remaining--;

  // get the tag class
  var tagClass = (b1 & 0xC0);

  // get the type (bits 1-5)
  var type = b1 & 0x1F;

  // get the variable value length and adjust remaining bytes
  start = bytes.length();
  var length = _getValueLength(bytes, remaining);
  remaining -= start - bytes.length();

  // ensure there are enough bytes to get the value
  if (length !== undefined && length > remaining) {
    if (options.strict) {
      throw new TooFewBytesDerError('Too few bytes to read ASN.1 value.',
        bytes.length(),
        remaining,
        length
      );
    }

    // Note: be lenient with truncated values and use remaining state bytes
    length = remaining;
  }

  // value storage
  var value: any;
  // possible BIT STRING contents storage
  var bitStringContents: string | undefined;

  // constructed flag is bit 6 (32 = 0x20) of the first byte
  var constructed = ((b1 & 0x20) === 0x20);
  if(constructed) {
    // parse child asn1 objects from the value
    value = [];
    if(length === undefined) {
      // asn1 object of indefinite length, read until end tag
      for(;;) {
        _checkBufferLength(bytes, remaining, 2);
        if(bytes.bytes(2) === String.fromCharCode(0, 0)) {
          bytes.getBytes(2);
          remaining -= 2;
          break;
        }
        start = bytes.length();
        value.push(_fromDer(bytes, remaining, depth + 1, options));
        remaining -= start - bytes.length();
      }
    } else {
      // parsing asn1 object of definite length
      while(length > 0) {
        start = bytes.length();
        value.push(_fromDer(bytes, length, depth + 1, options));
        remaining -= start - bytes.length();
        length -= start - bytes.length();
      }
    }
  }

  // if a BIT STRING, save the contents including padding
  if(value === undefined && tagClass === Class.UNIVERSAL && type === Type.BITSTRING) {
    bitStringContents = bytes.bytes(length);
  }

  // determine if a non-constructed value should be decoded as a composed
  // value that contains other ASN.1 objects. BIT STRINGs (and OCTET STRINGs)
  // can be used this way.
  if(value === undefined && options.decodeBitStrings &&
    tagClass === Class.UNIVERSAL &&
    // FIXME: OCTET STRINGs not yet supported here
    // .. other parts of forge expect to decode OCTET STRINGs manually
    (type === Type.BITSTRING /*|| type === Type.OCTETSTRING*/) && length !== undefined && length > 1) {
    // save read position
    var savedRead = bytes.read;
    var savedRemaining = remaining;
    var unused = 0;
    if(type === Type.BITSTRING) {
      /* The first octet gives the number of bits by which the length of the
        bit string is less than the next multiple of eight (this is called
        the "number of unused bits").

        The second and following octets give the value of the bit string
        converted to an octet string. */
      _checkBufferLength(bytes, remaining, 1);
      unused = bytes.getByte();
      remaining--;
    }
    // if all bits are used, maybe the BIT/OCTET STRING holds ASN.1 objs
    if(unused === 0) {
      try {
        // attempt to parse child asn1 object from the value
        // (stored in array to signal composed value)
        start = bytes.length();
        var subOptions = {
          // enforce strict mode to avoid parsing ASN.1 from plain data
          strict: true,
          decodeBitStrings: true
        };
        var composed = _fromDer(bytes, remaining, depth + 1, subOptions);
        var used = start - bytes.length();
        remaining -= used;
        if(type == Type.BITSTRING) {
          used++;
        }

        // if the data all decoded and the class indicates UNIVERSAL or
        // CONTEXT_SPECIFIC then assume we've got an encapsulated ASN.1 object
        var tc = composed.tagClass;
        if(used === length &&
          (tc === Class.UNIVERSAL || tc === Class.CONTEXT_SPECIFIC)) {
          value = [composed];
        }
      } catch {
        // No-op.
      }
    }

    if (value === undefined) {
      // restore read position
      bytes.read = savedRead;
      remaining = savedRemaining;
    }
  }

  if (value === undefined) {
    // asn1 not constructed or composed, get raw value
    // TODO: do DER to OID conversion and vice-versa in .toDer?

    if (length === undefined) {
      if(options.strict) {
        throw new Error('Non-constructed ASN.1 object of indefinite length.');
      }
      // be lenient and use remaining state bytes
      length = remaining;
    }

    if (type === Type.BMPSTRING) {
      value = '';
      for(; length > 0; length -= 2) {
        _checkBufferLength(bytes, remaining, 2);
        value += String.fromCharCode(bytes.getInt16());
        remaining -= 2;
      }
    } else {
      value = bytes.getBytes(length);
      remaining -= length;
    }
  }

  // add BIT STRING contents if available
  const asn1Options = bitStringContents === undefined ? void 0 : {
    bitStringContents
  };

  // create and return asn1 object
  return create(tagClass, type, constructed, value, asn1Options);
}

/**
 * Converts the given asn1 object to a buffer of bytes in DER format.
 *
 * @param asn1 the asn1 object to convert to bytes.
 *
 * @return the buffer of bytes.
 * @was forge.asn1.toDer
 */
export function toDer (obj: Asn1): ByteStringBuffer {
  var bytes = createBuffer();

  // build the first byte
  var b1 = obj.tagClass | obj.type;

  // for storing the ASN.1 value
  var value = createBuffer();

  // use BIT STRING contents if available and data not changed
  var useBitStringContents = false;
  if('bitStringContents' in obj) {
    useBitStringContents = true;
    if(obj.original) {
      useBitStringContents = equals(obj, obj.original);
    }
  }

  if (useBitStringContents) {
    value.putBytes(obj.bitStringContents!);
  } else if(obj.composed) {
    // if composed, use each child asn1 object's DER bytes as value
    // turn on 6th bit (0x20 = 32) to indicate asn1 is constructed
    // from other asn1 objects
    if(obj.constructed) {
      b1 |= 0x20;
    } else {
      // type is a bit string, add unused bits of 0x00
      value.putByte(0x00);
    }

    // add all of the child DER bytes together
    for(var i = 0; i < obj.value.length; ++i) {
      if(obj.value[i] !== undefined) {
        value.putBuffer(toDer(obj.value[i] as Asn1));
      }
    }
  } else {
    // use asn1.value directly
    if(obj.type === Type.BMPSTRING) {
      for(var i = 0; i < obj.value.length; ++i) {
        value.putInt16((obj.value as string).charCodeAt(i));
      }
    } else {
      const v = obj.value as string;

      // ensure integer is minimally-encoded
      // TODO: should all leading bytes be stripped vs just one?
      // .. ex '00 00 01' => '01'?
      if(obj.type === Type.INTEGER &&
        v.length > 1 &&
        // leading 0x00 for positive integer
        ((v.charCodeAt(0) === 0 &&
        (v.charCodeAt(1) & 0x80) === 0) ||
        // leading 0xFF for negative integer
        (v.charCodeAt(0) === 0xFF &&
        (v.charCodeAt(1) & 0x80) === 0x80))) {
        value.putBytes(v.substr(1));
      } else {
        value.putBytes(v);
      }
    }
  }

  // add tag byte
  bytes.putByte(b1);

  // use "short form" encoding
  if(value.length() <= 127) {
    // one byte describes the length
    // bit 8 = 0 and bits 7-1 = length
    bytes.putByte(value.length() & 0x7F);
  } else {
    // use "long form" encoding
    // 2 to 127 bytes describe the length
    // first byte: bit 8 = 1 and bits 7-1 = # of additional bytes
    // other bytes: length in base 256, big-endian
    var len = value.length();
    var lenBytes = '';
    do {
      lenBytes += String.fromCharCode(len & 0xFF);
      len = len >>> 8;
    } while(len > 0);

    // set first byte to # bytes used to store the length and turn on
    // bit 8 to indicate long-form length is used
    bytes.putByte(lenBytes.length | 0x80);

    // concatenate length bytes in reverse since they were generated
    // little endian and we need big endian
    for(var i = lenBytes.length - 1; i >= 0; --i) {
      bytes.putByte(lenBytes.charCodeAt(i));
    }
  }

  // concatenate value bytes
  bytes.putBuffer(value);
  return bytes;
};

// TODO: asn1.oidToDer
// TODO: asn1.derToOid
// TODO: asn1.utcTimeToDate
// TODO: asn1.generalizedTimeToDate
// TODO: asn1.dateToUtcTime
// TODO: asn1.dateToGeneralizedTime

/**
 * Converts a javascript integer to a DER-encoded byte buffer to be used
 * as the value for an INTEGER type.
 *
 * @param x the integer.
 *
 * @return the byte buffer.
 */
export function integerToDer (x: number): ByteStringBuffer {
  const rval = createBuffer();

  if (x >= -0x80 && x < 0x80) {
    return rval.putSignedInt(x, 8);
  }
  if (x >= -0x8000 && x < 0x8000) {
    return rval.putSignedInt(x, 16);
  }
  if (x >= -0x800000 && x < 0x800000) {
    return rval.putSignedInt(x, 24);
  }
  if (x >= -0x80000000 && x < 0x80000000) {
    return rval.putSignedInt(x, 32);
  }
  
  var error = new Error('Integer too large; max is 32-bits.');
  // TODO: write a custom Error for this
  // @ts-expect-error
  error.integer = x;

  throw error;
};

// TODO: asn1.derToInteger

/**
 * Validates that the given ASN.1 object is at least a super set of the
 * given ASN.1 structure. Only tag classes and types are checked. An
 * optional map may also be provided to capture ASN.1 values while the
 * structure is checked.
 *
 * To capture an ASN.1 value, set an object in the validator's 'capture'
 * parameter to the key to use in the capture map. To capture the full
 * ASN.1 object, specify 'captureAsn1'. To capture BIT STRING bytes, including
 * the leading unused bits counter byte, specify 'captureBitStringContents'.
 * To capture BIT STRING bytes, without the leading unused bits counter byte,
 * specify 'captureBitStringValue'.
 *
 * Objects in the validator may set a field 'optional' to true to indicate
 * that it isn't necessary to pass validation.
 *
 * @param obj the ASN.1 object to validate.
 * @param v the ASN.1 structure validator.
 * @param capture an optional map to capture values in.
 * @param errors an optional array for storing validation errors.
 *
 * @return true on success, false on failure.
 */
export function validate (obj: Asn1, v: any, capture, errors) {
  var rval = false;

  // ensure tag class and type are the same if specified
  if((obj.tagClass === v.tagClass || typeof(v.tagClass) === 'undefined') &&
    (obj.type === v.type || typeof(v.type) === 'undefined')) {
    // ensure constructed flag is the same if specified
    if(obj.constructed === v.constructed ||
      typeof(v.constructed) === 'undefined') {
      rval = true;

      // handle sub values
      if(v.value && isArray(v.value)) {
        var j = 0;
        for(var i = 0; rval && i < v.value.length; ++i) {
          rval = v.value[i].optional || false;
          if(obj.value[j]) {
            rval = validate(obj.value[j] as Asn1, v.value[i], capture, errors);
            if(rval) {
              ++j;
            }
            else if(v.value[i].optional) {
              rval = true;
            }
          }
          if(!rval && errors) {
            errors.push(
              '[' + v.name + '] ' +
              'Tag class "' + v.tagClass + '", type "' +
              v.type + '" expected value length "' +
              v.value.length + '", got "' +
              obj.value.length + '"');
          }
        }
      }

      if(rval && capture) {
        if(v.capture) {
          capture[v.capture] = obj.value;
        }
        if(v.captureAsn1) {
          capture[v.captureAsn1] = obj;
        }
        if(v.captureBitStringContents && 'bitStringContents' in obj) {
          capture[v.captureBitStringContents] = obj.bitStringContents;
        }
        if(v.captureBitStringValue && 'bitStringContents' in obj) {
          var value;
          if(obj.bitStringContents!.length < 2) {
            capture[v.captureBitStringValue] = '';
          } else {
            // FIXME: support unused bits with data shifting
            var unused = obj.bitStringContents!.charCodeAt(0);
            if(unused !== 0) {
              throw new Error(
                'captureBitStringValue only supported for zero unused bits');
            }
            capture[v.captureBitStringValue] = obj.bitStringContents!.slice(1);
          }
        }
      }
    } else if(errors) {
      errors.push(
        '[' + v.name + '] ' +
        'Expected constructed "' + v.constructed + '", got "' +
        obj.constructed + '"');
    }
  } else if(errors) {
    if(obj.tagClass !== v.tagClass) {
      errors.push(
        '[' + v.name + '] ' +
        'Expected tag class "' + v.tagClass + '", got "' +
        obj.tagClass + '"');
    }
    if(obj.type !== v.type) {
      errors.push(
        '[' + v.name + '] ' +
        'Expected type "' + v.type + '", got "' + obj.type + '"');
    }
  }
  return rval;
};

// TODO: _nonLatinRegex
// TODO: asn1.prettyPrint
