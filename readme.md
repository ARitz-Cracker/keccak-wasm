# keccak-wasm
[![NPM](https://nodei.co/npm/keccak-wasm.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/keccak-wasm/)

[![Build Status](https://travis-ci.org/ARitz-Cracker/keccak-wasm.svg?branch=master)](https://travis-ci.org/ARitz-Cracker/keccak-wasm)
[![Coverage Status](https://coveralls.io/repos/github/ARitz-Cracker/keccak-wasm/badge.svg?branch=master)](https://coveralls.io/github/ARitz-Cracker/keccak-wasm?branch=master)

This is a WebAssembly implementation of the Keccak hashing functions. This library supports keccak224, keccak256, keccak384, and keccak512

This module will return `Buffer`s as its results should a global `Buffer` object exists. If one doesn't, it will return `Uint8Array`s

# Usage and example:

```js
const {InitializeKeccak, Keccak, keccak224, keccak256, keccak384, keccak512} = require("keccak")
await InitializeKeccak(); // This must be called before using this library.

//keccak256(data, hexString = true);
keccak256("Hello, hello! Testing testing"); // "3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8"
keccak256("Hello, hello! Testing testing", true); // "3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8"
keccak256("Hello, hello! Testing testing", false); // "Buffer <3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8>"

// Constructor can take the values 224, 256, 384, and 512
keccak = new Keccak(256);

// keccak.update(data (Uint8Array or string), paranoia = true)
// When paranoia is true, data will be wiped from its internal memory after being processed
keccak.update("Hello, hello! Testing testing");

// keccak.final(hexString = true, destroy = true, paranoia = false)
// When destroy is true, the Keccak object cannot be reused.
// Paranoia defaults to false since the given data is wiped by default in keccak.update
keccak.final() // "3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8"
```
