const chai = require('chai');
chai.use(require("chai-as-promised"));
const expect = chai.expect;

const {randomBytes} = require("crypto");
require('js-sha3')
const {InitializeKeccak, Keccak, keccak224, keccak256, keccak384, keccak512} = require('../');

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
describe("Keccak hasher", function() {
	before(function(done) {
		InitializeKeccak().then(done).catch(done);
	});
	describe("Keccak object", function(){
		it("can return Uint8Arrays, given a string or Uint8Array", function(){
			for (let i = 0; i < 4; i += 1){
				const keccak = new Keccak(supportedBits[i]);
				let result = keccak.update(staticTestString).final(false, false);
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
		it("Is not reusable when specified", function(){
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
		it("Is not reusable by default", function(){
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
	});
});