# keccak-wasm
[![NPM](https://nodei.co/npm/keccak-wasm.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/keccak-wasm/)

This is a WebAssembly implementation of the Keccak hashing functions. This library supports keccak224, keccak256, keccak384, and keccak512.

# Usage and example:

```js
// No manual initialization is required as the WASM binary is instantiated through the use of esm top-level await. 
import {KeccakHash, keccak256, keccak256ToHex} from "keccak-wasm";

keccak256(Buffer.from("Hello, hello! Testing testing")); // "Uint8Array [0x3c, 0xf7, 0x01, 0x29, ...]"
keccak256ToHex(Buffer.from("Hello, hello! Testing testing")); // "3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8"

// Constructor can take the values 224, 256, 384, and 512
keccak = new KeccakHash(256);

// Hash some bytes
keccak.update(Buffer.from("Hello, hello! Testing testing"));

// keccak.digestHex(), or keccak.digest() for a Uint8Array output. This resets the hasher.
keccak.digestHex() // "3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8"

// hash a string, this will be converted to UTF8.
keccak.updateStr("Hello, hello! Testing testing");

// keccak.finalDigestToHex(), or keccak.finalDigest(). This will destroy the `KeccakHash` rendering it unusable.
keccak.finalDigestToHex() // "3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8"
// If you don't use any of the final* functions, you should call keccak.free() unless you want memory leaks.
```
