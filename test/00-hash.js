const chai = require('chai');
chai.use(require("chai-as-promised"));
const expect = chai.expect;

const {randomBytes} = require("crypto");
const jsSha3 = require('js-sha3');
const js_keccak224 = jsSha3.keccak224;
const js_keccak256 = jsSha3.keccak256;
const js_keccak384 = jsSha3.keccak384;
const js_keccak512 = jsSha3.keccak512;
const {InitializeKeccak, Keccak, keccak224, keccak256, keccak384, keccak512} = require('../');

const jsFuncs = [js_keccak224, js_keccak256, js_keccak384, js_keccak512]
const simpleFuncs = [keccak224, keccak256, keccak384, keccak512];
const supportedBits = [224, 256, 384, 512];
const staticTestString = "Hello, hello! Testing testing";
const staticTestBuffer = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x20, 0x54, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67]);
const staticTestResults = [
	new Uint8Array([0x18, 0x59, 0xbf, 0xfc, 0x68, 0xf3, 0x07, 0x14, 0xd6, 0xc8, 0x0a, 0x3c, 0x0f, 0x1e, 0x17, 0x99, 0xb4, 0x1a, 0x04, 0x0c, 0xb9, 0x5f, 0x2c, 0x8e, 0x85, 0x2c, 0xb7, 0xdd]),
	new Uint8Array([0x3c, 0xf7, 0x01, 0x29, 0x53, 0xf4, 0xe0, 0x4a, 0x80, 0xda, 0x00, 0x06, 0x5c, 0x1f, 0x12, 0xce, 0x47, 0xbd, 0xd2, 0x46, 0x33, 0x87, 0x9c, 0x29, 0xe3, 0x5b, 0xb1, 0x2e, 0x5f, 0x6f, 0x54, 0xa8]),
	new Uint8Array([0x76, 0x11, 0x83, 0xa3, 0xab, 0x75, 0xaa, 0x84, 0x65, 0x96, 0x86, 0xb2, 0xf7, 0xfd, 0xba, 0x92, 0x8a, 0xca, 0xda, 0x48, 0x1e, 0xa4, 0x26, 0x0f, 0xe5, 0xce, 0xc9, 0x0a, 0x14, 0xb0, 0x88, 0xd6, 0x05, 0x63, 0x5f, 0x78, 0x0a, 0x29, 0x13, 0xc6, 0x0c, 0xac, 0xa0, 0x82, 0x8e, 0x82, 0x96, 0xe4]),
	new Uint8Array([0xfe, 0x9d, 0x7f, 0xf6, 0x60, 0x70, 0x1b, 0x06, 0xae, 0xf6, 0x02, 0xda, 0x9b, 0xcd, 0x47, 0x7b, 0xac, 0x41, 0xb4, 0x99, 0xd9, 0x32, 0x29, 0x44, 0xed, 0xc2, 0x25, 0x94, 0x9c, 0x04, 0x65, 0x39, 0xeb, 0x21, 0xe2, 0x18, 0x3d, 0x13, 0x46, 0xee, 0xff, 0x5c, 0x71, 0x4d, 0xfd, 0x22, 0x9c, 0x62, 0xf0, 0xc7, 0xc4, 0xa9, 0x0a, 0x11, 0x43, 0xa4, 0xdd, 0x0b, 0xc9, 0x34, 0x32, 0xb2, 0x2b, 0x9c])
]
const staticTestResultStrings = [
	"1859bffc68f30714d6c80a3c0f1e1799b41a040cb95f2c8e852cb7dd",
	"3cf7012953f4e04a80da00065c1f12ce47bdd24633879c29e35bb12e5f6f54a8",
	"761183a3ab75aa84659686b2f7fdba928acada481ea4260fe5cec90a14b088d605635f780a2913c60caca0828e8296e4",
	"fe9d7ff660701b06aef602da9bcd477bac41b499d9322944edc225949c046539eb21e2183d1346eeff5c714dfd229c62f0c7c4a90a1143a4dd0bc93432b22b9c",
]
const staticTestDoubleResultStrings = [
	"10d67c625732fbd17bdcb73882362a6c09f9dc673fb5278de743213a",
	"8fdbbf6352c21315fca2c10ab09da40d67d2abb559d55a3322c2d7597192b85c",
	"fb8619e185fe7a3dce67a1b6d2f9ee1d5573cf95faea757f72a6506ae6656f8c15a9856e1497d5f99d7547f45732cc47",
	"019ffe2b0b51af773f0219372d8cf1fb61f24cea33db98a5ce0534855b8a06d2d27274ad73258791f7ef0093fac63743ed295c3098774b21c849cd01819549fd",
]
describe("Keccak hasher", function() {
	before(function(done) {
		InitializeKeccak().then(done).catch(done);
	});
	describe("Keccak object", function(){
		it("can return Uint8Arrays, given a string or Uint8Array", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				let result = keccak.update(staticTestString, false).final(false, false);
				expect(result).to.deep.equal(staticTestResults[i]);
				result = keccak.update(staticTestBuffer).final(false, true);
				expect(result).to.deep.equal(staticTestResults[i]);
			}
		});
		it("can return hex strings, given a string or Uint8Array", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				let result = keccak.update(staticTestString).final(true, false);
				expect(result).to.deep.equal(staticTestResultStrings[i]);
				result = keccak.update(staticTestBuffer).final(true, true);
				expect(result).to.deep.equal(staticTestResultStrings[i]);
			}
		});
		it("defaults to hex strings", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				let result = keccak.update(staticTestString).final();
				expect(result).to.deep.equal(staticTestResultStrings[i]);
			}
		});
		it("is not reusable when specified", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				result = keccak.update(staticTestBuffer).final(true, true);
				expect(result).to.deep.equal(staticTestResultStrings[i]);
				expect(function(){keccak.destroy()}).to.throw("Keccak instance has been destroyed");
				expect(function(){keccak.reset()}).to.throw("Keccak instance has been destroyed");
				expect(function(){keccak.update(staticTestBuffer)}).to.throw("Keccak instance has been destroyed");
				expect(function(){keccak.final(staticTestBuffer)}).to.throw("Keccak instance has been destroyed");
			}
		});
		it("is not reusable by default", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				result = keccak.update(staticTestBuffer).final();
				expect(result).to.deep.equal(staticTestResultStrings[i]);
				expect(function(){keccak.destroy()}).to.throw("Keccak instance has been destroyed");
				expect(function(){keccak.reset()}).to.throw("Keccak instance has been destroyed");
				expect(function(){keccak.update(staticTestBuffer)}).to.throw("Keccak instance has been destroyed");
				expect(function(){keccak.final(staticTestBuffer)}).to.throw("Keccak instance has been destroyed");
			}
		});
		it("can be destroyed anytime", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				keccak.update(staticTestString);
				keccak.destroy(true);
				expect(function(){keccak.final(staticTestBuffer)}).to.throw("Keccak instance has been destroyed");
			}
		});
		it("can be reset anytime", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				keccak.update(staticTestString).reset();
				const result = keccak.update(staticTestBuffer).final(true);
				expect(result).to.deep.equal(staticTestResultStrings[i]);
			}
		});
		it("throws when given an invalid type", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				expect(function(){keccak.update(1)}).to.throw("Must be a string or Uint8Array");
				keccak.destroy();
			}
		});
		it("can handle multiple instances", function(){
			let keccaks = [[], [], [], []];
			for (let i = 0; i < 4; i += 1){
				for (let ii = 0; ii < 6; ii += 1){
					keccaks[i][ii] = new Keccak(supportedBits[i]);
				}
			}
			for (let i = 0; i < 4; i += 1){
				for (let ii = 0; ii < 6; ii += 1){
					keccaks[i][ii].update(staticTestString);
				}
			}
			for (let i = 0; i < 4; i += 1){
				for (let ii = 0; ii < 6; ii += 1){
					keccaks[i][ii].update(staticTestBuffer);
				}
			}
			for (let i = 0; i < 4; i += 1){
				for (let ii = 0; ii < 6; ii += 1){
					const result = keccaks[i][ii].final();
					expect(result).to.deep.equal(staticTestDoubleResultStrings[i]);
				}
			}
		});
		it("deletes its internal data when given data larger than 128kb", function(){
			const keccak = new Keccak(256);
			const result = keccak.update("a".repeat(133120)).final();
			expect(keccak._argLen).to.equal(0);
			expect(keccak._argPtr).to.equal(0);
			expect(result).to.deep.equal("85dadbc9721e444a8f16f015ac38bfe69b856e6e2d04c7a8fb1a9db692b6f592");
		});
		it("deletes its internal data when given data larger than 128kb", function(){
			const keccak = new Keccak(256);
			keccak.update("a".repeat(133120));
			expect(keccak._argLen).to.equal(0);
			expect(keccak._argPtr).to.equal(0);
			const result = keccak.final();
			expect(result).to.deep.equal("85dadbc9721e444a8f16f015ac38bfe69b856e6e2d04c7a8fb1a9db692b6f592");
		});
		it("can handle inputs larger than the WASM memory space", function(){
			const keccak = new Keccak(256);
			keccak.update("a".repeat(19398656), false);
			let result = keccak.final(true, false, true);
			expect(result).to.deep.equal("89b5430467d9a74ae8435bd9c758107151da6ba6ee67643cca4efb046e12f939");
			keccak.update("a".repeat(19398656), true);
			result = keccak.final(true, true, true);
			expect(result).to.deep.equal("89b5430467d9a74ae8435bd9c758107151da6ba6ee67643cca4efb046e12f939");
		});
	});
	describe("Simple functions", function(){
		it("works", function(){
			for (let i = 0; i < 4; i += 1){
				expect(simpleFuncs[i](staticTestBuffer)).to.deep.equal(staticTestResultStrings[i]);
				expect(simpleFuncs[i](staticTestBuffer, true)).to.deep.equal(staticTestResultStrings[i]);
				expect(simpleFuncs[i](staticTestBuffer, false)).to.deep.equal(staticTestResults[i]);
			}
		});
		it("runs faster than js-sha3 (64 bytes)", function(){
			let stuff = randomBytes(64);
			for (let i = 0; i < 4; i += 1){
				const jsStartTime = process.hrtime.bigint();
				const jsHexResult = jsFuncs[i](stuff);
				const jsBufferResult = new Uint8Array(jsFuncs[i].arrayBuffer(stuff));
				const jsTime = Number(process.hrtime.bigint() - jsStartTime);

				const wasmStartTime = process.hrtime.bigint();
				const wasmHexResult = simpleFuncs[i](stuff);
				const wasmBufferResult = simpleFuncs[i](stuff, false);
				const wasmTime = Number(process.hrtime.bigint() - wasmStartTime);
				expect(wasmHexResult).to.equal(jsHexResult);
				expect(wasmBufferResult).to.deep.equal(jsBufferResult);
				console.log("WASM time",  wasmTime * 0.000001, "ms");
				console.log("JS time", jsTime * 0.000001, "ms");
				expect(wasmTime).to.be.lessThan(jsTime);
			}
			
		});
		it("runs faster than js-sha3 (256KB)", function(){
			let stuff = randomBytes(262144);
			for (let i = 0; i < 4; i += 1){
				const jsStartTime = process.hrtime.bigint();
				const jsHexResult = jsFuncs[i](stuff);
				const jsBufferResult = new Uint8Array(jsFuncs[i].arrayBuffer(stuff));
				const jsTime = Number(process.hrtime.bigint() - jsStartTime);

				const wasmStartTime = process.hrtime.bigint();
				const wasmHexResult = simpleFuncs[i](stuff);
				const wasmBufferResult = simpleFuncs[i](stuff, false);
				const wasmTime = Number(process.hrtime.bigint() - wasmStartTime);
				expect(wasmHexResult).to.equal(jsHexResult);
				expect(wasmBufferResult).to.deep.equal(jsBufferResult);
				console.log("WASM time",  wasmTime * 0.000001, "ms");
				console.log("JS time", jsTime * 0.000001, "ms");
				expect(wasmTime).to.be.lessThan(jsTime);
			}
		});
		it("runs faster than js-sha3 (1MB)", function(){
			let stuff = randomBytes(1048576);
			for (let i = 0; i < 4; i += 1){
				const jsStartTime = process.hrtime.bigint();
				const jsHexResult = jsFuncs[i](stuff);
				const jsBufferResult = new Uint8Array(jsFuncs[i].arrayBuffer(stuff));
				const jsTime = Number(process.hrtime.bigint() - jsStartTime);

				const wasmStartTime = process.hrtime.bigint();
				const wasmHexResult = simpleFuncs[i](stuff);
				const wasmBufferResult = simpleFuncs[i](stuff, false);
				const wasmTime = Number(process.hrtime.bigint() - wasmStartTime);
				expect(wasmHexResult).to.equal(jsHexResult);
				expect(wasmBufferResult).to.deep.equal(jsBufferResult);
				console.log("WASM time",  wasmTime * 0.000001, "ms");
				console.log("JS time", jsTime * 0.000001, "ms");
				expect(wasmTime).to.be.lessThan(jsTime);
			}
		});
	});
});