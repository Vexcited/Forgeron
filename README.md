# Forgeron

A rewrite of the `node-forge` library in TypeScript with a focus on ESM compatibility with tree-shaking support.

## Roadmap

## `asn1.js`

- [x] `forge.asn1.create`
- [x] `forge.asn1.copy`
- [x] `forge.asn1.equals` (some typing issues)
- [x] `forge.asn1.getBerValueLength`
- [x] `forge.asn1.fromDer`
- [x] `forge.asn1.toDer`
- [ ] `forge.asn1.oidToDer`
- [ ] `forge.asn1.derToOid`
- [ ] `forge.asn1.utcTimeToDate`
- [ ] `forge.asn1.generalizedTimeToDate`
- [ ] `forge.asn1.dateToUtcTime`
- [ ] `forge.asn1.dateToGeneralizedTime`
- [ ] `forge.asn1.integerToDer`
- [ ] `forge.asn1.derToInteger`
- [ ] `forge.asn1.validate`
- [ ] `forge.asn1.prettyPrint`

### `util.js`

- [x] `forge.util.isArray`
- [x] `forge.util.isArrayBuffer`
- [x] `forge.util.isArrayBufferView`

- [x] `forge.util.ByteStringBuffer` (`forge.util.ByteBuffer` is an alias for `forge.util.ByteStringBuffer`)
  - [x] `constructor`
  - [x] `length`
  - [x] `isEmpty`
  - [x] `putByte`
  - [x] `fillWithByte`
  - [x] `putBytes`
  - [x] `putString`
  - [x] `putInt16`
  - [x] `putInt24`
  - [x] `putInt32`
  - [x] `putInt16Le`
  - [x] `putInt24Le`
  - [x] `putInt32Le`
  - [x] `putInt`
  - [x] `putSignedInt`
  - [x] `putBuffer`
  - [x] `getByte`
  - [x] `getInt16`
  - [x] `getInt24`
  - [x] `getInt32`
  - [x] `getInt16Le`
  - [x] `getInt24Le`
  - [x] `getInt32Le`
  - [x] `getInt`
  - [x] `getSignedInt`
  - [x] `getBytes`
  - [x] `bytes`
  - [x] `at`
  - [x] `setAt`
  - [x] `last`
  - [x] `copy`
  - [x] `compact`
  - [x] `clear`
  - [x] `truncate`
  - [x] `toHex`
  - [x] `toString`

- [ ] `forge.util.DataBuffer` (experimental though)
  - [ ] `constructor`
  - [ ] `length`
  - [ ] `isEmpty`
  - [ ] `accommodate`
  - [ ] `putByte`
  - [ ] `fillWithByte`
  - [ ] `putBytes`
  - [ ] `putBuffer`
  - [ ] `putString`
  - [ ] `putInt16`
  - [ ] `putInt24`
  - [ ] `putInt32`
  - [ ] `putInt16Le`
  - [ ] `putInt24Le`
  - [ ] `putInt32Le`
  - [ ] `putInt`
  - [ ] `putSignedInt`
  - [ ] `getByte`
  - [ ] `getInt16`
  - [ ] `getInt24`
  - [ ] `getInt32`
  - [ ] `getInt16Le`
  - [ ] `getInt24Le`
  - [ ] `getInt32Le`
  - [ ] `getInt`
  - [ ] `getSignedInt`
  - [ ] `getBytes`
  - [ ] `bytes`
  - [ ] `at`
  - [ ] `setAt`
  - [ ] `last`
  - [ ] `copy`
  - [ ] `compact`
  - [ ] `clear`
  - [ ] `truncate`
  - [ ] `toHex`
  - [ ] `toString`

- [x] `forge.util.fillString`
- [x] `forge.util.xorBytes`
- [x] `forge.util.hexToBytes`
- [x] `forge.util.bytesToHex`
- [x] `forge.util.int32ToBytes`
- [x] `forge.util.encode64`
- [x] `forge.util.decode64`
- [x] `forge.util.encodeUtf8`
- [x] `forge.util.decodeUtf8`

- [x] `forge.util.createBuffer`

- [ ] `forge.util.binary`
  - [ ] `raw`
    - [ ] `encode`
    - [ ] `decode`
  - [ ] `hex`
    - [ ] `encode` (alias for `forge.util.bytesToHex`)
    - [ ] `decode`
  - [ ] `base64`
    - [ ] `encode`
    - [ ] `decode`
  - [ ] `base58`
    - [ ] `encode`
    - [ ] `decode`
  - [ ] `baseN` (re-export from `baseN.js` file)
    - [ ] `encode` (baseN.js -> `encode`)
    - [ ] `decode` (baseN.js -> `decode`)
- [ ] `forge.util.text`
  - [ ] `utf8`
    - [ ] `encode`
    - [ ] `decode`
  - [ ] `utf16`
    - [ ] `encode`
    - [ ] `decode`

- [ ] `forge.util.deflate`
- [ ] `forge.util.inflate`

- [ ] `forge.util.setItem`
- [ ] `forge.util.getItem`
- [ ] `forge.util.removeItem`
- [ ] `forge.util.clearItems`

- [ ] `forge.util.isEmpty`

- [ ] `forge.util.format`
- [ ] `forge.util.formatNumber`
- [ ] `forge.util.formatSize`

- [ ] `forge.util.bytesFromIP`
- [ ] `forge.util.bytesFromIPv4`
- [ ] `forge.util.bytesFromIPv6`

- [ ] `forge.util.bytesToIP`
- [ ] `forge.util.bytesToIPv4`
- [ ] `forge.util.bytesToIPv6`

- [ ] `forge.util.estimateCores`

## License

This project is a fork of the original [`node-forge`](https://github.com/digitalbazaar/forge) project, which was dual-licensed under the BSD 3-Clause License or the GPL 2.0 License.

This hard fork is based on the BSD 3-Clause License version of the original project. As a result, this fork is licensed under the MIT License. You can find the full text of the MIT License in the [LICENSE](./LICENSE) file.
