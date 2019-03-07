# pbkdf2-sha512-wasm
This is a WebAssembly implementation of PBKDF2. However, it has some limitations:
* Key length cannot be specified, it will always be 64 bytes.
* While the hash function _can_ be custom, the returned hashes from the function must be 64 bytes since it is only intended to be used with sha512.

This library was created to serve a the base for BIP32 and BIP39, and to work around [`bitcoin-ts`'s](https://github.com/bitjson/bitcoin-ts) implementation of `sha512`.

# Usage:

## Promise(pbkdf2Instance) instantiatePbkdf2(Object sha512[, Uint8Array binary])

Returns an object specified below.

* `sha512` must be a an object with a `hash` method. [Like this](https://bitjson.github.io/bitcoin-ts/interfaces/sha512.html).
* `binary` is optional. It must be a Uint8Array containing the WASM binary. If none is specified, it will load the binary provided by this package.

***

## Uint8Array pbkdf2Instance.xorStr(Uint8Array buffer, Number value)

Xor's every byte in the `buffer` by `value`.

***

## Uint8Array pbkdf2Instance.xorStrs(Uint8Array buffer1, Uint8Array buffer2)

Xor's every byte in `buffer1` by the corrosponding byte in `buffer2`. Both arguments must be the same length.

***

## Uint8Array pbkdf2Instance.hmacSha512(Uint8Array key, Uint8Array data[, Boolean paranoia])

Returns an HMAC hash

* `key` key to hash with.
* `data` data to hash with.
* `paranoia` zero out the arguments and return data from internal heap. Defaults is true.

***

## Uint8Array pbkdf2Instance.pbkdf2Sha512(Uint8Array key, Uint8Array data, Number iterations[, Boolean paranoia])

Returns a PBKDF2 hash

* `key` key to hash with.
* `data` data to hash with.
* `iterations` number of hashing iterations.
* `paranoia` zero out the arguments and return data from internal heap. Defaults is true.

***

## pbkdf2Instance.wipeInternalMemory()

Zero out the previous arguments and return data from internal heap. The main purpose of this function is to give the option zero everything out after using the hashing functions consecutively while not clearing the data every single time.

***

# Example:

```js
const bitcoinTS = require("bitcoin-ts");
const {instantiatePbkdf2} = require("pbkdf2-wasm");
const pbkdf2 = await instantiatePbkdf2(await bitcoinTS.instantiateSha512());

const data = Buffer.from("aaaaaaa");
const salt = Buffer.from("bbbbbbb");

const hash = pbkdf2.pbkdf2Sha512(salt, data, 2048); // Woohoo! you've got a PBKDF2 hash in WASM!
```
