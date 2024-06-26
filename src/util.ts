// forge.util.isArray
export const isArray = (x: any): x is Array<any> => Array.isArray(x);
// forge.util.isArrayBuffer
export const isArrayBuffer = (x: any): x is ArrayBuffer => typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer;
// forge.util.isArrayBufferView
export const isArrayBufferView = (x: any): x is ArrayBufferView => x && isArrayBuffer(x.buffer) && x.byteLength !== undefined;

/**
 * Ensure a bits param is 8, 16, 24, or 32. Used to validate input for
 * algorithms where bit manipulation, JavaScript limitations, and/or algorithm
 * design only allow for byte operations of a limited size.
 *
 * @param n number of bits.
 *
 * @throws `Error` if `n` invalid.
 */
function _checkBitsParam (n: number): void {
  if (!(n === 8 || n === 16 || n === 24 || n === 32)) {
    throw new Error(`Only 8, 16, 24, or 32 bits supported: ${n}`);
  }
}

/**
 * Constructor for a binary string backed byte buffer.
 *
 * @param [b] the bytes to wrap (either encoded as string, one byte per
 *          character, or as an ArrayBuffer or Typed Array).
 */
export class ByteStringBuffer {
  private data: string;
  public read: number;
  private _constructedStringLength: number;
  
  /**
   * Constructor for a binary string backed byte buffer.
   *
   * @param [b] the bytes to wrap (either encoded as string, one byte per
   *          character, or as an ArrayBuffer or Typed Array).
   */
  constructor (b?: string | ArrayBuffer | ArrayBufferView | ByteStringBuffer) {
    // TODO: update to match DataBuffer API

    // the data in this buffer
    this.data = '';
    // the pointer for reading from this buffer
    this.read = 0;

    if (typeof b === 'string') {
      this.data = b;
    }
    else if (isArrayBuffer(b) || isArrayBufferView(b)) {
      if (typeof Buffer !== 'undefined' && b instanceof Buffer) {
        this.data = b.toString('binary');
      }
      else {
        // convert native buffer to forge buffer
        // FIXME: support native buffers internally instead
        var arr = new Uint8Array(b as ArrayBufferLike);
        try {
          this.data = String.fromCharCode.apply(null, arr);
        } catch(e) {
          for(var i = 0; i < arr.length; ++i) {
            this.putByte(arr[i]);
          }
        }
      }
    }
    else if (b instanceof ByteStringBuffer ||
      // Otherwise if it's an object that gives ByteStringBuffer-like data...
      (typeof b === 'object' && typeof (b as ByteStringBuffer).data === 'string' && typeof (b as ByteStringBuffer).read === 'number')
    ) {
      // copy existing buffer
      this.data = b.data;
      this.read = b.read;
    }

    // used for v8 optimization
    this._constructedStringLength = 0;
  }

  /* NOTE: This is an optimization for V8-based browsers. When V8 concatenates
  a string, the strings are only joined logically using a "cons string" or
  "constructed/concatenated string". These containers keep references to one
  another and can result in very large memory usage. For example, if a 2MB
  string is constructed by concatenating 4 bytes together at a time, the
  memory usage will be ~44MB; so ~22x increase. The strings are only joined
  together when an operation requiring their joining takes place, such as
  substr(). This function is called when adding data to this buffer to ensure
  these types of strings are periodically joined to reduce the memory
  footprint. */
  private _MAX_CONSTRUCTED_STRING_LENGTH = 4096;
  private _optimizeConstructedString (x) {
    this._constructedStringLength += x;
    if(this._constructedStringLength > this._MAX_CONSTRUCTED_STRING_LENGTH) {
      // this substr() should cause the constructed string to join
      this.data.substr(0, 1);
      this._constructedStringLength = 0;
    }
  };

  /**
   * Gets the number of bytes in this buffer.
   * @return the number of bytes in this buffer.
   */
  public length(): number {
    return this.data.length - this.read;
  }

  /**
   * Gets whether or not this buffer is empty.
   * @return true if this buffer is empty, false if not.
   */
  public isEmpty (): boolean {
    return this.length() <= 0;
  };

  /**
   * Puts a byte in this buffer.
   *
   * @param b the byte to put.
   *
   * @return this buffer.
   */
  public putByte (b: number): ByteStringBuffer {
    return this.putBytes(String.fromCharCode(b));
  };

  /**
   * Puts a byte in this buffer N times.
   *
   * @param b the byte to put.
   * @param n the number of bytes of value b to put.
   *
   * @return this buffer.
   */
  public fillWithByte (byte: number, n: number): ByteStringBuffer {
    let b = String.fromCharCode(byte);
    var d = this.data;
    while (n > 0) {
      if (n & 1) {
        d += b;
      }
      n >>>= 1;
      if (n > 0) {
        b += b;
      }
    }
    this.data = d;
    this._optimizeConstructedString(n);
    return this;
  }

  /**
   * Puts bytes in this buffer.
   *
   * @param bytes the bytes (as a binary encoded string) to put.
   *
   * @return this buffer.
   */
  public putBytes (bytes: string): ByteStringBuffer {
    this.data += bytes;
    this._optimizeConstructedString(bytes.length);
    return this;
  }

  /**
   * Puts a UTF-16 encoded string into this buffer.
   *
   * @param str the string to put.
   *
   * @return this buffer.
   */
  public putString (str: string): ByteStringBuffer {
    return this.putBytes(encodeUtf8(str));
  }

  /**
   * Puts a 16-bit integer in this buffer in big-endian order.
   *
   * @param i the 16-bit integer.
   *
   * @return this buffer.
   */
  public putInt16 (i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i & 0xFF));
  };

  /**
   * Puts a 24-bit integer in this buffer in big-endian order.
   *
   * @param i the 24-bit integer.
   *
   * @return this buffer.
   */
  public putInt24(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i >> 16 & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i & 0xFF));
  }

  /**
   * Puts a 32-bit integer in this buffer in big-endian order.
   *
   * @param i the 32-bit integer.
   *
   * @return this buffer.
   */
  public putInt32(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i >> 24 & 0xFF) +
      String.fromCharCode(i >> 16 & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i & 0xFF));
  }

  /**
   * Puts a 16-bit integer in this buffer in little-endian order.
   *
   * @param i the 16-bit integer.
   *
   * @return this buffer.
   */
  public putInt16Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF));
  }

  /**
   * Puts a 24-bit integer in this buffer in little-endian order.
   *
   * @param i the 24-bit integer.
   *
   * @return this buffer.
   */
  public putInt24Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i >> 16 & 0xFF));
  }

  /**
   * Puts a 32-bit integer in this buffer in little-endian order.
   *
   * @param i the 32-bit integer.
   *
   * @return this buffer.
   */
  public putInt32Le(i: number): ByteStringBuffer {
    return this.putBytes(
      String.fromCharCode(i & 0xFF) +
      String.fromCharCode(i >> 8 & 0xFF) +
      String.fromCharCode(i >> 16 & 0xFF) +
      String.fromCharCode(i >> 24 & 0xFF));
  }

  /**
   * Puts an n-bit integer in this buffer in big-endian order.
   *
   * @param i the n-bit integer.
   * @param n the number of bits in the integer (8, 16, 24, or 32).
   *
   * @return this buffer.
   */
  public putInt(i: number, n: number): ByteStringBuffer {
    _checkBitsParam(n);
    var bytes = '';
    do {
      n -= 8;
      bytes += String.fromCharCode((i >> n) & 0xFF);
    } while(n > 0);
    return this.putBytes(bytes);
  }

  /**
   * Puts a signed n-bit integer in this buffer in big-endian order. Two's
   * complement representation is used.
   *
   * @param i the n-bit integer.
   * @param n the number of bits in the integer (8, 16, 24, or 32).
   *
   * @return this buffer.
   */
  public putSignedInt(i: number, n: number): ByteStringBuffer {
    // putInt checks n
    if(i < 0) {
      i += 2 << (n - 1);
    }
    return this.putInt(i, n);
  }

  /**
   * Puts the given buffer into this buffer.
   *
   * @param buffer the buffer to put into this one.
   *
   * @return this buffer.
   */
  public putBuffer(buffer: ByteStringBuffer): ByteStringBuffer {
    return this.putBytes(buffer.getBytes());
  }

  /**
   * Gets a byte from this buffer and advances the read pointer by 1.
   *
   * @return the byte.
   */
  public getByte(): number {
    return this.data.charCodeAt(this.read++);
  }

  /**
   * Gets a uint16 from this buffer in big-endian order and advances the read
   * pointer by 2.
   *
   * @return the uint16.
   */
  public getInt16(): number {
    var rval = (
      this.data.charCodeAt(this.read) << 8 ^
      this.data.charCodeAt(this.read + 1));
    this.read += 2;
    return rval;
  }

  /**
   * Gets a uint24 from this buffer in big-endian order and advances the read
   * pointer by 3.
   *
   * @return the uint24.
   */
  public getInt24(): number {
    var rval = (
      this.data.charCodeAt(this.read) << 16 ^
      this.data.charCodeAt(this.read + 1) << 8 ^
      this.data.charCodeAt(this.read + 2));
    this.read += 3;
    return rval;
  }

  /**
   * Gets a uint32 from this buffer in big-endian order and advances the read
   * pointer by 4.
   *
   * @return the word.
   */
  public getInt32(): number {
    var rval = (
      this.data.charCodeAt(this.read) << 24 ^
      this.data.charCodeAt(this.read + 1) << 16 ^
      this.data.charCodeAt(this.read + 2) << 8 ^
      this.data.charCodeAt(this.read + 3));
    this.read += 4;
    return rval;
  }

  /**
   * Gets a uint16 from this buffer in little-endian order and advances the read
   * pointer by 2.
   *
   * @return the uint16.
   */
  public getInt16Le(): number {
    var rval = (
      this.data.charCodeAt(this.read) ^
      this.data.charCodeAt(this.read + 1) << 8);
    this.read += 2;
    return rval;
  }

  /**
   * Gets a uint24 from this buffer in little-endian order and advances the read
   * pointer by 3.
   *
   * @return the uint24.
   */
  public getInt24Le(): number {
    var rval = (
      this.data.charCodeAt(this.read) ^
      this.data.charCodeAt(this.read + 1) << 8 ^
      this.data.charCodeAt(this.read + 2) << 16);
    this.read += 3;
    return rval;
  }

  /**
   * Gets a uint32 from this buffer in little-endian order and advances the read
   * pointer by 4.
   *
   * @return the word.
   */
  public getInt32Le(): number {
    var rval = (
      this.data.charCodeAt(this.read) ^
      this.data.charCodeAt(this.read + 1) << 8 ^
      this.data.charCodeAt(this.read + 2) << 16 ^
      this.data.charCodeAt(this.read + 3) << 24);
    this.read += 4;
    return rval;
  }

  /**
   * Gets an n-bit integer from this buffer in big-endian order and advances the
   * read pointer by ceil(n/8).
   *
   * @param n the number of bits in the integer (8, 16, 24, or 32).
   *
   * @return the integer.
   */
  public getInt(n: number): number {
    _checkBitsParam(n);
    var rval = 0;
    do {
      // TODO: Use (rval * 0x100) if adding support for 33 to 53 bits.
      rval = (rval << 8) + this.data.charCodeAt(this.read++);
      n -= 8;
    } while(n > 0);
    return rval;
  }

  /**
   * Gets a signed n-bit integer from this buffer in big-endian order, using
   * two's complement, and advances the read pointer by n/8.
   *
   * @param n the number of bits in the integer (8, 16, 24, or 32).
   *
   * @return the integer.
   */
  public getSignedInt(n: number): number {
    // getInt checks n
    var x = this.getInt(n);
    var max = 2 << (n - 2);
    if(x >= max) {
      x -= max << 1;
    }
    return x;
  }

  /**
   * Reads bytes out as a binary encoded string and clears them from the
   * buffer. Note that the resulting string is binary encoded (in node.js this
   * encoding is referred to as `binary`, it is *not* `utf8`).
   *
   * @param count the number of bytes to read, undefined or null for all.
   *
   * @return a binary encoded string of bytes.
   */
  public getBytes(count?: number): string {
    var rval: string;
    if(count) {
      // read count bytes
      count = Math.min(this.length(), count);
      rval = this.data.slice(this.read, this.read + count);
      this.read += count;
    } else if(count === 0) {
      rval = '';
    } else {
      // read all bytes, optimize to only copy when needed
      rval = (this.read === 0) ? this.data : this.data.slice(this.read);
      this.clear();
    }
    return rval;
  }

  /**
   * Gets a binary encoded string of the bytes from this buffer without
   * modifying the read pointer.
   *
   * @param count the number of bytes to get, omit to get all.
   *
   * @return a string full of binary encoded characters.
   */
  public bytes(count?: number): string {
    return (typeof(count) === 'undefined' ?
    this.data.slice(this.read) :
    this.data.slice(this.read, this.read + count));
  }

  /**
   * Gets a byte at the given index without modifying the read pointer.
   *
   * @param i the byte index.
   *
   * @return the byte.
   */
  public at(i: number): number {
    return this.data.charCodeAt(this.read + i);
  }

  /**
   * Puts a byte at the given index without modifying the read pointer.
   *
   * @param i the byte index.
   * @param b the byte to put.
   *
   * @return this buffer.
   */
  public setAt(i: number, b: number): ByteStringBuffer {
    this.data = this.data.substr(0, this.read + i) +
    String.fromCharCode(b) +
    this.data.substr(this.read + i + 1);
    return this;
  }

  /**
   * Gets the last byte without modifying the read pointer.
   *
   * @return the last byte.
   */
  public last(): number {
    return this.data.charCodeAt(this.data.length - 1);
  }

  /**
   * Creates a copy of this buffer.
   * @return the copy.
   */
  public copy(): ByteStringBuffer {
    var c = createBuffer(this.data);
    c.read = this.read;
    return c;
  }

  /**
   * Compacts this buffer.
   * @return this buffer.
   */
  public compact(): ByteStringBuffer {
    if (this.read > 0) {
      this.data = this.data.slice(this.read);
      this.read = 0;
    }

    return this;
  }

  /**
   * Clears this buffer.
   * @return this buffer.
   */
  public clear(): ByteStringBuffer {
    this.data = '';
    this.read = 0;
    return this;
  }

  /**
   * Shortens this buffer by trimming bytes off of the end of this buffer.
   *
   * @param count the number of bytes to trim off.
   *
   * @return this buffer.
   */
  public truncate(count: number): ByteStringBuffer {
    var len = Math.max(0, this.length() - count);
    this.data = this.data.substr(this.read, len);
    this.read = 0;
    return this;
  }

  /**
   * Converts this buffer to a hexadecimal string.
   *
   * @return a hexadecimal string.
   */
  public toHex(): string {
    var rval = '';
    for(var i = this.read; i < this.data.length; ++i) {
      var b = this.data.charCodeAt(i);
      if(b < 16) {
        rval += '0';
      }
      rval += b.toString(16);
    }
    return rval;
  }

  /**
   * Converts this buffer to a UTF-16 string (standard JavaScript string).
   * @return a UTF-16 string.
   */
  public toString(): string {
    return decodeUtf8(this.bytes());
  }
}

// Alias for `forge.util.ByteBuffer`.
export const ByteBuffer = ByteStringBuffer;

/**
 * Creates a buffer that stores bytes. A value may be given to populate the
 * buffer with data. This value can either be string of encoded bytes or a
 * regular string of characters. When passing a string of binary encoded
 * bytes, the encoding `raw` should be given. This is also the default. When
 * passing a string of characters, the encoding `utf8` should be given.
 *
 * @param [input] a string with encoded bytes to store in the buffer.
 * @param [encoding] (default: 'raw', other: 'utf8').
 */
export function createBuffer (
  input?: string | ArrayBuffer | ArrayBufferView | ByteStringBuffer,
  encoding?: "raw" | "utf8"
): ByteStringBuffer {
  // TODO: deprecate, use new ByteBuffer() instead
  encoding = encoding || 'raw';
  
  if (input !== undefined && encoding === 'utf8') {
    input = encodeUtf8(input as string); // is string because encoding is 'utf8'
  }

  return new ByteBuffer(input);
};

/**
 * Fills a string with a particular value. If you want the string to be a byte
 * string, pass in String.fromCharCode(theByte).
 *
 * @param c the character to fill the string with, use String.fromCharCode
 *          to fill the string with a byte value.
 * @param n the number of characters of value c to fill with.
 *
 * @return the filled string.
 */
export function fillString (c: string, n: number): string {
  var s = '';

  while (n > 0) {
    if (n & 1) {
      s += c;
    }

    n >>>= 1;
    
    if (n > 0) {
      c += c;
    }
  }

  return s;
}; // forge.util.fillString

/**
 * Performs a per byte XOR between two byte strings and returns the result as a
 * string of bytes.
 *
 * @param s1 first string of bytes.
 * @param s2 second string of bytes.
 * @param n the number of bytes to XOR.
 *
 * @return the XOR'd result.
 */
export function xorBytes (s1: string, s2: string, n: number): string {
  var s3 = '';
  var b = 0;
  var t = '';
  var i = 0;
  var c = 0;
  for(; n > 0; --n, ++i) {
    b = s1.charCodeAt(i) ^ s2.charCodeAt(i);
    if(c >= 10) {
      s3 += t;
      t = '';
      c = 0;
    }
    t += String.fromCharCode(b);
    ++c;
  }
  s3 += t;
  return s3;
}; // forge.util.xorBytes

/**
 * Converts a hex string into a 'binary' encoded string of bytes.
 *
 * @param hex the hexadecimal string to convert.
 * @return the binary-encoded string of bytes.
 */
export function hexToBytes (hex: string): string {
  // TODO: deprecate: "Deprecated. Use util.binary.hex.decode instead."
  let rval = '';
  let i = 0;

  // VEXCITED EDIT: was `hex.length & 1 == 1`
  if ((hex.length & 1) == 1) {
    // odd number of characters, convert first character alone
    i = 1;
    rval += String.fromCharCode(parseInt(hex[0], 16));
  }

  // convert 2 characters (1 byte) at a time
  for (; i < hex.length; i += 2) {
    rval += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }

  return rval;
}; // forge.util.hexToBytes

/**
 * Converts a 'binary' encoded string of bytes to hex.
 *
 * @param bytes the byte string to convert.
 *
 * @return the string of hexadecimal characters.
 */
export function bytesToHex (bytes: string): string {
  // TODO: deprecate: "Deprecated. Use util.binary.hex.encode instead."
  return createBuffer(bytes).toHex();
}; // forge.util.bytesToHex

/**
 * Converts an 32-bit integer to 4-big-endian byte string.
 *
 * @param i the integer.
 *
 * @return the byte string.
 */
export function int32ToBytes (i: number): string {
  return (
    String.fromCharCode(i >> 24 & 0xFF) +
    String.fromCharCode(i >> 16 & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i & 0xFF));
}; // forge.util.int32ToBytes

// base64 characters, reverse mapping
var _base64 =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
var _base64Idx = [
/*43 -43 = 0*/
/*'+',  1,  2,  3,'/' */
   62, -1, -1, -1, 63,

/*'0','1','2','3','4','5','6','7','8','9' */
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,

/*15, 16, 17,'=', 19, 20, 21 */
  -1, -1, -1, 64, -1, -1, -1,

/*65 - 43 = 22*/
/*'A','B','C','D','E','F','G','H','I','J','K','L','M', */
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12,

/*'N','O','P','Q','R','S','T','U','V','W','X','Y','Z' */
   13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,

/*91 - 43 = 48 */
/*48, 49, 50, 51, 52, 53 */
  -1, -1, -1, -1, -1, -1,

/*97 - 43 = 54*/
/*'a','b','c','d','e','f','g','h','i','j','k','l','m' */
   26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,

/*'n','o','p','q','r','s','t','u','v','w','x','y','z' */
   39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
];

// base58 characters (Bitcoin alphabet)
const _base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Base64 encodes a 'binary' encoded string of bytes.
 *
 * @param input the binary encoded string of bytes to base64-encode.
 * @param maxline the maximum number of encoded characters per line to use,
 *          defaults to none.
 *
 * @return the base64-encoded output.
 */
export function encode64 (input: string, maxline?: number): string {
  // TODO: deprecate: "Deprecated. Use util.binary.base64.encode instead."
  var line = '';
  var output = '';
  var chr1, chr2, chr3;
  var i = 0;
  while(i < input.length) {
    chr1 = input.charCodeAt(i++);
    chr2 = input.charCodeAt(i++);
    chr3 = input.charCodeAt(i++);

    // encode 4 character group
    line += _base64.charAt(chr1 >> 2);
    line += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
    if(isNaN(chr2)) {
      line += '==';
    } else {
      line += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
      line += isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63);
    }

    if(maxline && line.length > maxline) {
      output += line.substr(0, maxline) + '\r\n';
      line = line.substr(maxline);
    }
  }
  output += line;
  return output;
}; // forge.util.encode64

/**
 * Base64 decodes a string into a 'binary' encoded string of bytes.
 *
 * @param input the base64-encoded input.
 *
 * @return the binary encoded string.
 */
export function decode64 (input: string): string {
  // TODO: deprecate: "Deprecated. Use util.binary.base64.decode instead."

  // remove all non-base64 characters
  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');

  var output = '';
  var enc1, enc2, enc3, enc4;
  var i = 0;

  while(i < input.length) {
    enc1 = _base64Idx[input.charCodeAt(i++) - 43];
    enc2 = _base64Idx[input.charCodeAt(i++) - 43];
    enc3 = _base64Idx[input.charCodeAt(i++) - 43];
    enc4 = _base64Idx[input.charCodeAt(i++) - 43];

    output += String.fromCharCode((enc1 << 2) | (enc2 >> 4));
    if(enc3 !== 64) {
      // decoded at least 2 bytes
      output += String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2));
      if(enc4 !== 64) {
        // decoded 3 bytes
        output += String.fromCharCode(((enc3 & 3) << 6) | enc4);
      }
    }
  }

  return output;
}; // forge.util.decode64

/**
 * Encodes the given string of characters (a standard JavaScript
 * string) as a binary encoded string where the bytes represent
 * a UTF-8 encoded string of characters. Non-ASCII characters will be
 * encoded as multiple bytes according to UTF-8.
 *
 * @param str a standard string of characters to encode.
 *
 * @return the binary encoded string.
 */
export function encodeUtf8 (str: string): string {
  return unescape(encodeURIComponent(str));
}; // forge.util.encodeUtf8

/**
 * Decodes a binary encoded string that contains bytes that
 * represent a UTF-8 encoded string of characters -- into a
 * string of characters (a standard JavaScript string).
 *
 * @param str the binary encoded string to decode.
 *
 * @return the resulting standard string of characters.
 */
export function decodeUtf8 (str: string): string {
  return decodeURIComponent(escape(str));
}; // forge.util.decodeUtf8
